"""The ``agent-census audit`` subcommand: keep the datacentre ASN list honest.

Cross-checks the ``(provider, ASN)`` associations in ``networks/datacenter_ranges.toml``
against Cloudflare Radar (authoritative AS org names + sibling ASNs + an
automated-vs-human traffic split as a hosting signal), the RIPEstat registry (the
RIR-registered holder, a second opinion on the name) and PeeringDB (a network-type
hint). It validates what's there, suggests *datacentre* sibling ASNs to add, and
-- with ``--asn`` -- assesses arbitrary candidate ASNs (e.g. the unrecognised ones
from ``agent-census calibrate``). Output is Markdown.

Standard library only. Responses are cached by URL for a week (atomic write);
HTTP uses one keep-alive connection per host, backs off on 429/5xx, and treats a
404 as a genuinely-unknown ASN. Needs a Cloudflare Radar API token, from
``--token`` or ``$CF_API_TOKEN``; RIPEstat and PeeringDB are queried anonymously.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import time
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from . import USER_AGENT, userconfig
from .dataload import load_egress_networks, load_range_sources
from .iprange import cache_dir

_RADAR = "https://api.cloudflare.com/client/v4/radar"
_PEERINGDB = "https://www.peeringdb.com/api"
# RIPEstat as-names: free, no token, and batchable (comma-separated resources).
# `sourceapp` is requested as a courtesy so RIPE can attribute the traffic. Each
# holder reads "<RIR handle> - <org name>".
_RIPESTAT = "https://stat.ripe.net/data/as-names/data.json?sourceapp=agent-census"
_TIMEOUT = 20
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024  # cap a JSON reply so a bad server can't OOM us
_MAX_ATTEMPTS = 3  # per request, on connection error or 429/5xx
_RETRY_CAP = 30.0  # seconds; ceiling on any single backoff
_PDB_CHUNK = 50  # ASNs per batched PeeringDB query
_RIPE_CHUNK = 100  # ASNs per batched RIPEstat as-names query
# ASN org data and 28-day traffic splits drift slowly, so cache responses by URL
# for a week -- re-running (or iterating on the report) doesn't re-hit the APIs.
_CACHE_TTL = 7 * 24 * 3600
_BOT_RANGE = "28d"
# A datacentre's egress is overwhelmingly automated; below this a listing (or a
# suggestion) is suspect (it may be an eyeball ISP, or an egress / VPN network).
_BOT_DATACENTRE = 85.0
_BOT_MIXED = 50.0
_MAX_SIBLINGS = 25  # cap related ASNs assessed per entry, to bound a cold run

# Generic words that don't identify an organisation, dropped before comparing our
# label to Radar's org name (so "Amazon AWS" still matches "Amazon Web Services").
_GENERIC = frozenset(
    {
        "inc",
        "llc",
        "ltd",
        "limited",
        "gmbh",
        "co",
        "corp",
        "corporation",
        "company",
        "sas",
        "bv",
        "sa",
        "ag",
        "plc",
        "group",
        "holdings",
        "srl",
        "pte",
        "oy",
        "as",
        "cloud",
        "hosting",
        "host",
        "server",
        "servers",
        "data",
        "systems",
        "solutions",
        "internet",
        "online",
        "networks",
        "network",
        "communications",
        "telecom",
        "the",
        "and",
        "global",
        "digital",
        "technologies",
        "tech",
        "services",
        "service",
    }
)


@dataclass
class AsnReport:
    """What the auditors know about one AS number."""

    asn: int
    radar_name: str | None = None
    radar_org: str | None = None
    radar_known: bool = False
    bot_pct: float | None = None
    bot_low_confidence: bool = False
    related: tuple[tuple[int, str], ...] = ()
    ripe_holder: str | None = None
    pdb_checked: bool = False
    pdb_name: str | None = None
    pdb_type: str | None = None


def _backoff(attempt: int, header: str | None = None) -> float:
    if header and header.strip().isdigit():
        return min(float(header.strip()), _RETRY_CAP)
    return min(2.0**attempt, _RETRY_CAP)


class _Client:
    """A small JSON HTTP client: keep-alive per host, retries, and a URL cache."""

    def __init__(self, token: str, *, refresh: bool = False) -> None:
        self._token = token
        self._conns: dict[str, http.client.HTTPSConnection] = {}
        self._cache: dict[str, list[object]] = {} if refresh else _load_cache()
        self._warned: set[str] = set()

    def _warn(self, message: str) -> None:
        if message not in self._warned:
            self._warned.add(message)
            print(f"warning: {message}", file=sys.stderr)

    def _conn(self, host: str) -> http.client.HTTPSConnection:
        conn = self._conns.get(host)
        if conn is None:
            conn = http.client.HTTPSConnection(host, timeout=_TIMEOUT)
            self._conns[host] = conn
        return conn

    def _drop(self, host: str) -> None:
        conn = self._conns.pop(host, None)
        if conn is not None:
            conn.close()

    def _request(self, url: str, auth: bool) -> object | None:
        parts = urllib.parse.urlsplit(url)
        host = parts.netloc
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        for attempt in range(_MAX_ATTEMPTS):
            try:
                conn = self._conn(host)
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                payload, status = response.read(_MAX_RESPONSE_BYTES), response.status
            except (http.client.HTTPException, OSError):
                self._drop(host)  # poisoned keep-alive socket; reopen next time
                if attempt + 1 < _MAX_ATTEMPTS:
                    time.sleep(_backoff(attempt))
                    continue
                self._warn(f"{host}: connection failed")
                return None
            if status == 200:
                try:
                    body: object = json.loads(payload)
                    return body
                except ValueError:
                    return None
            if status == 404:
                return None  # a genuinely-unknown ASN, not an error
            if status == 429 or 500 <= status < 600:
                delay = _backoff(attempt, response.getheader("Retry-After"))
                self._warn(f"{host}: HTTP {status}, backing off {delay:.0f}s")
                time.sleep(delay)
                continue
            self._warn(f"{host}: HTTP {status} (check the token?)")  # 401/403/…
            return None
        return None

    def fetch(self, url: str, *, auth: bool = False) -> object | None:
        """Return the JSON body for ``url``, from cache when fresh, else over HTTP."""
        hit = self._cache.get(url)
        if hit and isinstance(hit[0], (int, float)) and time.time() - hit[0] < _CACHE_TTL:
            return hit[1]
        body = self._request(url, auth)
        if body is not None:  # never cache an error / rate-limit / miss
            self._cache[url] = [time.time(), body]
        return body

    def close(self) -> None:
        """Close the keep-alive sockets and persist the cache (atomically)."""
        for conn in self._conns.values():
            try:
                conn.close()
            except OSError:
                pass
        self._conns.clear()
        _save_cache(self._cache)


def _load_cache() -> dict[str, list[object]]:
    try:
        data = json.loads((cache_dir() / "audit.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}


def _save_cache(cache: dict[str, list[object]]) -> None:
    path = cache_dir() / "audit.json"
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(cache), encoding="utf-8")
        tmp.replace(path)  # atomic: a crash leaves the old file intact, never a torn one
    except OSError:
        pass


def _radar_entity(client: _Client, asn: int) -> AsnReport:
    report = AsnReport(asn=asn)
    entity = _dig(client.fetch(f"{_RADAR}/entities/asns/{asn}", auth=True), "result", "asn")
    if not isinstance(entity, dict):
        return report
    report.radar_known = True
    report.radar_name = _str(entity.get("name"))
    # `aka` is the friendly name ("Hetzner Online GmbH"); `name` is the AS handle
    # ("HETZNER-AS"); `orgName` is only the RIR org handle ("ORG-HOA1-RIPE").
    report.radar_org = _str(entity.get("aka")) or report.radar_name or _str(entity.get("orgName"))
    related = entity.get("related")
    if isinstance(related, list):
        report.related = tuple(
            (int(item["asn"]), _str(item.get("name")) or "")
            for item in related
            if isinstance(item, dict) and "asn" in item
        )
    return report


def _radar_bot_pct(client: _Client, asn: int) -> tuple[float | None, bool]:
    body = client.fetch(
        f"{_RADAR}/http/summary/bot_class?asn={asn}&dateRange={_BOT_RANGE}", auth=True
    )
    summary = _dig(body, "result", "summary_0")
    if not isinstance(summary, dict) or "bot" not in summary:
        return None, False
    try:
        bot = float(summary["bot"])
    except (TypeError, ValueError):
        return None, False
    return bot, bool(_dig(body, "result", "meta", "confidenceInfo", "annotations"))


def _ripe_batch(client: _Client, asns: Iterable[int]) -> dict[int, str]:
    """RIR-registered holder per ASN ({asn: 'AKAMAI-LINODE-AP - Akamai Connected Cloud'}).

    A name check independent of Radar: the registry handle often preserves the brand
    we listed even when Radar's friendly name has moved to a parent company. Fetched
    in chunks (RIPEstat as-names takes a comma-separated resource list).
    """
    out: dict[int, str] = {}
    uniq = sorted(set(asns))
    for start in range(0, len(uniq), _RIPE_CHUNK):
        ids = ",".join(f"AS{a}" for a in uniq[start : start + _RIPE_CHUNK])
        names = _dig(client.fetch(f"{_RIPESTAT}&resource={ids}"), "data", "names")
        if isinstance(names, dict):
            for key, holder in names.items():
                if str(key).isdigit() and isinstance(holder, str) and holder:
                    out[int(key)] = holder
    return out


def _peeringdb_batch(
    client: _Client, asns: Iterable[int]
) -> dict[int, tuple[str | None, str | None]]:
    """One PeeringDB row per ASN ({asn: (name, info_type)}), fetched in chunks."""
    out: dict[int, tuple[str | None, str | None]] = {}
    uniq = sorted(set(asns))
    for start in range(0, len(uniq), _PDB_CHUNK):
        ids = ",".join(str(a) for a in uniq[start : start + _PDB_CHUNK])
        rows = _dig(
            client.fetch(f"{_PEERINGDB}/net?asn__in={ids}&fields=asn,name,info_type"), "data"
        )
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and "asn" in row:
                    out[int(row["asn"])] = (_str(row.get("name")), _str(row.get("info_type")))
    return out


def gather(client: _Client, asn: int) -> AsnReport:
    """Radar org + bot-class for one ASN (RIPE and PeeringDB are batched separately)."""
    report = _radar_entity(client, asn)
    report.bot_pct, report.bot_low_confidence = _radar_bot_pct(client, asn)
    return report


def _datacentre_siblings(
    client: _Client, report: AsnReport, known: set[int]
) -> list[tuple[int, str, float]]:
    """Related ASNs not already listed *and* themselves datacentre-like (high bot %)."""
    out: list[tuple[int, str, float]] = []
    for asn, name in report.related:
        if asn in known or len(out) >= _MAX_SIBLINGS:
            continue
        bot, _conf = _radar_bot_pct(client, asn)
        if bot is not None and bot >= _BOT_DATACENTRE:
            out.append((asn, name, bot))
    return out


def _sib_label(asn: int, name: str, bot: float) -> str:
    """Render a sibling ASN with its automated-traffic share, e.g. 'AS215859 X (93% automated)'."""
    return f"{f'AS{asn} {name}'.strip()} ({bot:.0f}% automated)"


def _render_suggestion(provider: str, siblings: list[tuple[int, str, float]]) -> str:
    """A suggestion block: inline for one sibling, a sub-list (one per line) for several."""
    labels = [_sib_label(a, n, b) for a, n, b in siblings]
    if len(labels) == 1:
        return f"- {provider}: {labels[0]}"
    return "\n".join([f"- {provider}:", *(f"  - {label}" for label in labels)])


def _dig(obj: object | None, *keys: str) -> object | None:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _org_tokens(name: str | None) -> set[str]:
    words = re.split(r"[^a-z0-9]+", (name or "").lower())
    tokens = {w for w in words if len(w) >= 3 and w not in _GENERIC}
    # Fold a run of single letters back into an acronym ("F.N.S." -> "fns"); the
    # per-letter split would otherwise drop them all and leave nothing to match on.
    letters: list[str] = []
    for word in [*words, ""]:  # the trailing "" flushes the final run
        if len(word) == 1:
            letters.append(word)
            continue
        if len(letters) >= 2:
            tokens.add("".join(letters))
        letters = []
    return tokens


def _names_match(ours: str, theirs: str | None) -> bool:
    """True if our provider label and Radar's org plausibly name the same entity.

    Three ways: a shared distinctive token; one token a prefix of another ("OVH" /
    "OVHcloud", "Cherry Servers" / "cherryservers"); or one name, stripped of all
    punctuation and spaces, contained in the other ("Digital Ocean" / "DigitalOcean",
    "Cloud.ru" / "… trading as Cloud.ru").
    """
    mine, yours = _org_tokens(ours), _org_tokens(theirs)
    if mine and yours:
        if mine & yours:
            return True
        if any(a.startswith(b) or b.startswith(a) for a in mine for b in yours):
            return True
    flat_ours, flat_theirs = _flatten(ours), _flatten(theirs or "")
    return (
        len(flat_ours) >= 5
        and len(flat_theirs) >= 5
        and (flat_ours in flat_theirs or flat_theirs in flat_ours)
    )


def _flatten(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _bot_note(report: AsnReport) -> str:
    if report.bot_pct is None:
        return "bot %: unknown"
    verdict = (
        "datacentre-like"
        if report.bot_pct >= _BOT_DATACENTRE
        else "mixed" if report.bot_pct >= _BOT_MIXED else "mostly human"
    )
    flag = " (low confidence)" if report.bot_low_confidence else ""
    return f"{report.bot_pct:.0f}% automated -- {verdict}{flag}"


def _pdb_note(report: AsnReport) -> str:
    if report.pdb_type:
        return f"PeeringDB: {report.pdb_name or '?'} [{report.pdb_type}]"
    return "PeeringDB: not listed"


def _pdb_hint(report: AsnReport) -> str:
    """An inline network-type hint from PeeringDB to ride alongside Radar's split."""
    return f"; PeeringDB calls it {report.pdb_type}" if report.pdb_type else ""


def _other_sources(report: AsnReport) -> str:
    """What RIPE and PeeringDB say about an ASN, for when Radar draws a blank."""
    hints = []
    if report.ripe_holder:
        hints.append(f"the RIPE registry has {report.ripe_holder!r}")
    if report.pdb_type:
        hints.append(f"PeeringDB has {report.pdb_name or '?'!r} [{report.pdb_type}]")
    return "; ".join(hints)


def _join_and(items: list[str]) -> str:
    """'a' / 'a and b' / 'a, b and c'."""
    if len(items) <= 1:
        return items[0] if items else ""
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _sources_drawn_blank(report: AsnReport) -> str:
    """The sources that were consulted and knew nothing -- always Radar and RIPE,
    plus PeeringDB when it was queried (i.e. not --no-peeringdb)."""
    checked = ["Radar", "RIPE"] + (["PeeringDB"] if report.pdb_checked else [])
    return _join_and(checked)


def _assessment(report: AsnReport) -> str:
    """A plain-language verdict on what kind of network the ASN is.

    The verdict leads on Radar's automated-vs-human split; PeeringDB's self-declared
    network type (when present) is appended as an independent hint. RIPE offers no
    type, only a holder name, so it doesn't feature here.
    """
    if not report.radar_known:
        hints = _other_sources(report)
        if hints:
            return f"unknown to Radar, but {hints} -- allocated but unrouted?"
        return f"unknown to {_sources_drawn_blank(report)} -- can't assess (dead / unrouted?)"
    pdb = _pdb_hint(report)
    if report.bot_pct is None:
        return f"no Radar traffic data{pdb}" if pdb else "no traffic data -- can't assess"
    if report.bot_pct >= _BOT_DATACENTRE:
        return f"datacentre / hosting (traffic is almost all automated){pdb}"
    if report.bot_pct >= _BOT_MIXED:
        return f"mixed -- hosting with human/VPN traffic, or a mixed network{pdb}"
    return f"eyeball ISP, not a datacentre (mostly human; or an egress / VPN network){pdb}"


def _asn_bullet(
    report: AsnReport,
    siblings: list[tuple[int, str, float]],
    *,
    suffix: str = "",
    assessment: str | None = None,
) -> str:
    """A Markdown bullet for an ASN, one fact per sub-bullet."""
    lines = [f"- **AS{report.asn}**{suffix}"]
    if report.radar_known:
        lines.append(f"  - Radar: {report.radar_org}")
        lines.append(f"  - {_bot_note(report)}")
    else:
        lines.append("  - Radar: unknown ASN (dead / unrouted?)")
    if report.ripe_holder:
        lines.append(f"  - RIPE: {report.ripe_holder}")
    if report.pdb_checked:
        lines.append(f"  - {_pdb_note(report)}")
    if assessment:
        lines.append(f"  - assessment: {assessment}")
    if siblings:
        shown = ", ".join(_sib_label(a, n, b) for a, n, b in siblings[:8])
        more = f" (+{len(siblings) - 8} more)" if len(siblings) > 8 else ""
        lines.append(f"  - datacentre siblings, not listed: {shown}{more}")
    return "\n".join(lines)


# Concern headings, in the order they're rendered.
_WRONG_NAME = "Wrong name"
_TRAFFIC_MIX = "Traffic mix"
_DEAD = "Unknown / dead ASNs"
_CONCERN_ORDER = (_WRONG_NAME, _TRAFFIC_MIX, _DEAD)


def _concerns(
    report: AsnReport, label: str, *, flag_traffic_mix: bool = True
) -> list[tuple[str, float, str]]:
    """Zero or more ``(heading, sort_key, message)`` problems this listing raises.

    ``flag_traffic_mix`` is for datacentres, whose egress should be near-all
    automated; for an egress network (a VPN/proxy fronting real users) low
    automation is normal, so the caller turns that concern off.
    """
    if not report.radar_known:  # Radar doesn't know it; the registry / PeeringDB might
        hints = _other_sources(report)
        note = (
            f"unknown to Radar, but {hints}"
            if hints
            else f"unknown to {_sources_drawn_blank(report)} -- dead or unrouted?"
        )
        return [(_DEAD, 0.0, f"AS{report.asn} ({label}): {note}")]
    out: list[tuple[str, float, str]] = []
    # Only a "wrong name" if neither Radar nor the RIR registry corroborates our
    # label -- the registry handle often keeps the brand after a parent rebrand.
    if not _names_match(label, report.radar_org) and not _names_match(label, report.ripe_holder):
        msg = f"AS{report.asn}: listed as {label!r}, but Radar says {report.radar_org!r}"
        if report.ripe_holder:
            msg += f" and RIPE has {report.ripe_holder!r}"
        out.append((_WRONG_NAME, 0.0, msg))
    if flag_traffic_mix and report.bot_pct is not None and report.bot_pct < _BOT_MIXED:
        # sort the section least-automated (most suspect) first
        msg = (
            f"AS{report.asn} ({label}): only {report.bot_pct:.0f}% automated "
            f"according to Radar{_pdb_hint(report)}"
        )
        out.append((_TRAFFIC_MIX, report.bot_pct, msg))
    return out


def _render_concerns(
    by_heading: dict[str, list[tuple[float, str]]],
    suggestions: list[str],
    duplicates: list[str],
    *,
    extras: tuple[tuple[str, list[str]], ...] = (),
    level: str = "##",
) -> list[str]:
    """Render a dataset's findings. ``extras`` are extra ``(heading, lines)``
    sections (e.g. egress automation); ``level`` sets the heading depth."""
    lines: list[str] = []
    for heading in _CONCERN_ORDER:
        items = by_heading.get(heading)
        if items:
            messages = [m for _key, m in sorted(items, key=lambda im: im[0])]
            lines += [f"{level} {heading}", "", *(f"- {m}" for m in messages), ""]
    for title, body in extras:
        if body:
            lines += [f"{level} {title}", "", *(f"- {m}" for m in body), ""]
    if suggestions:
        # Each entry is a self-contained block (a single bullet, or a parent with a
        # sub-list) already including its leading "- ", so emit them verbatim.
        lines += [f"{level} Suggested additions (datacentre siblings)", "", *suggestions, ""]
    if duplicates:
        lines += [f"{level} Duplicate ASNs", "", *(f"- {d}" for d in duplicates), ""]
    extras_empty = not any(body for _t, body in extras)
    if not any(by_heading.values()) and not suggestions and not duplicates and extras_empty:
        lines += ["_Nothing flagged._"]
    return lines


def audit_file(client: _Client, use_pdb: bool, verbose: bool) -> int:
    """Audit both packaged datasets -- datacentre ranges and egress networks."""
    datacentre = [(s.name, s.asns) for s in load_range_sources("datacenter_ranges")]
    egress = [(n.name, n.asns) for n in load_egress_networks()]
    # Listed across *both* files: siblings already covered anywhere aren't suggested,
    # and the same ASN appearing in both datasets is itself worth flagging.
    known = {asn for _n, asns in (*datacentre, *egress) for asn in asns}
    pdb = _peeringdb_batch(client, known) if use_pdb else {}
    ripe = _ripe_batch(client, known)
    origin: dict[int, set[tuple[str, str]]] = {}  # asn -> {(dataset, provider)}
    lines = ["# ASN data audit", ""]
    lines += _audit_section(
        client, "Datacentre ranges", datacentre, known, ripe, pdb, use_pdb, verbose, origin
    )
    lines += _audit_section(
        client, "Egress networks", egress, known, ripe, pdb, use_pdb, verbose, origin
    )
    lines += _cross_dataset(origin)
    sys.stdout.write("\n".join(lines).rstrip() + "\n")
    return 0


def _audit_section(  # pylint: disable=too-many-locals
    client: _Client,
    title: str,
    entries: list[tuple[str, tuple[int, ...]]],
    known: set[int],
    ripe: dict[int, str],
    pdb: dict[int, tuple[str | None, str | None]],
    use_pdb: bool,
    verbose: bool,
    origin: dict[int, set[tuple[str, str]]],
) -> list[str]:
    """One dataset's findings under an ``## title`` heading (concerns at ``###``).

    Datacentre entries suggest datacentre-like siblings and flag a low traffic mix;
    egress entries do neither -- their automation share is reported, not judged.
    """
    datacentre = title.startswith("Datacentre")
    seen: dict[int, str] = {}
    duplicates: list[str] = []
    by_heading: dict[str, list[tuple[float, str]]] = {}
    sibs_by_provider: dict[str, dict[int, tuple[str, float]]] = {}
    suggested_seen: set[int] = set()
    automation: list[tuple[float, str]] = []  # egress: reported for context, not flagged
    detail: list[str] = []  # the full per-provider listing (only printed with --verbose)
    for name, asns in entries:
        if not asns:
            continue
        if verbose:
            detail += [f"### {name}", ""]
        for asn in asns:
            if asn in seen and seen[asn] != name:
                duplicates.append(f"AS{asn}: listed under both {seen[asn]!r} and {name!r}")
            seen[asn] = name
            origin.setdefault(asn, set()).add((title, name))
            report = gather(client, asn)
            report.ripe_holder = ripe.get(asn)
            _attach_pdb(report, pdb, use_pdb)
            siblings = _datacentre_siblings(client, report, known) if datacentre else []
            if verbose:
                detail.append(_asn_bullet(report, siblings))
            for heading, sort_key, message in _concerns(report, name, flag_traffic_mix=datacentre):
                by_heading.setdefault(heading, []).append((sort_key, message))
            if not datacentre and report.bot_pct is not None:
                line = (
                    f"AS{asn} ({name}): {report.bot_pct:.0f}% automated "
                    f"per Radar{_pdb_hint(report)}"
                )
                automation.append((report.bot_pct, line))
            for sib_asn, sib_name, sib_bot in siblings:
                if sib_asn in suggested_seen:  # don't suggest the same sibling twice
                    continue
                suggested_seen.add(sib_asn)
                sibs_by_provider.setdefault(name, {})[sib_asn] = (sib_name, sib_bot)
        if verbose:
            detail.append("")
    suggestions = [
        _render_suggestion(provider, [(a, n, b) for a, (n, b) in sorted(bag.items())])
        for provider, bag in sibs_by_provider.items()
    ]
    extras = (
        ()
        if datacentre
        else (("Automation per network (informational)", [m for _k, m in sorted(automation)]),)
    )
    out = [f"## {title}", ""]
    if verbose:
        out += [*detail]
    out += _render_concerns(by_heading, suggestions, duplicates, extras=extras, level="###")
    out += [""]
    return out


def _cross_dataset(origin: dict[int, set[tuple[str, str]]]) -> list[str]:
    """ASNs that appear in more than one dataset -- a datacentre listed as egress too."""
    lines: list[str] = []
    for asn in sorted(origin):
        if len({dataset for dataset, _name in origin[asn]}) > 1:
            where = ", ".join(f"{name!r} ({dataset})" for dataset, name in sorted(origin[asn]))
            lines.append(f"- AS{asn}: {where}")
    if lines:
        return ["## Listed in more than one dataset", "", *lines, ""]
    return []


def assess_candidates(client: _Client, asns: list[int], use_pdb: bool) -> int:
    """Assess arbitrary ASNs as datacentre candidates (e.g. from calibrate)."""
    listed: dict[int, str] = {}
    for src in load_range_sources("datacenter_ranges"):
        for asn in src.asns:
            listed[asn] = f"{src.name} (datacentre)"
    for net in load_egress_networks():
        for asn in net.asns:
            listed[asn] = f"{net.name} (egress)"
    known = set(listed)
    pdb = _peeringdb_batch(client, asns) if use_pdb else {}
    ripe = _ripe_batch(client, asns)
    lines = ["# Datacentre ASN candidates", ""]
    for asn in asns:
        suffix = f" _(listed as “{listed[asn]}”)_" if asn in listed else " _(not listed)_"
        report = gather(client, asn)
        report.ripe_holder = ripe.get(asn)
        _attach_pdb(report, pdb, use_pdb)
        lines.append(
            _asn_bullet(
                report,
                _datacentre_siblings(client, report, known),
                suffix=suffix,
                assessment=_assessment(report),
            )
        )
    sys.stdout.write("\n".join(lines).rstrip() + "\n")
    return 0


def _attach_pdb(
    report: AsnReport, pdb: dict[int, tuple[str | None, str | None]], use_pdb: bool
) -> None:
    if use_pdb:
        report.pdb_checked = True
        report.pdb_name, report.pdb_type = pdb.get(report.asn, (None, None))


def _parse_asns(text: str) -> list[int]:
    out: list[int] = []
    for token in re.split(r"[,\s]+", text.strip()):
        token = token[2:] if token[:2].lower() == "as" else token
        # A 32-bit ASN is at most 10 digits; the length bound both rejects
        # nonsense and keeps int() away from the 4300-digit conversion limit
        # (which would raise ValueError on an absurdly long --asn token).
        if token.isdigit() and len(token) <= 10:
            asn = int(token)
            if 0 <= asn <= 0xFFFFFFFF:
                out.append(asn)
    return out


def _resolve_token(explicit: str | None, config: Path | None = None) -> str | None:
    """Token from --token (persisted), else env, else the saved config."""
    if explicit:
        store = userconfig.load(config)
        store.defaults["cf_api_token"] = explicit
        store.save()
        print(f"saved API token to {store.path}", file=sys.stderr)
        return explicit
    saved = userconfig.load(config).defaults.get("cf_api_token")
    return (
        os.environ.get("CF_API_TOKEN")
        or os.environ.get("CLOUDFLARE_API_TOKEN")
        or (saved if isinstance(saved, str) else None)
    )


def run(
    *,
    asn: str | None,
    token: str | None,
    no_peeringdb: bool,
    refresh: bool = False,
    verbose: bool = False,
    config: Path | None = None,
) -> int:
    """Entry point for the ``agent-census audit`` subcommand."""
    resolved = _resolve_token(token, config)
    if not resolved:
        print(
            "error: a Cloudflare Radar API token is required (--token or $CF_API_TOKEN).\n"
            "Create a free one at https://dash.cloudflare.com with the 'Radar' read permission.",
            file=sys.stderr,
        )
        return 2
    use_pdb = not no_peeringdb
    client = _Client(resolved, refresh=refresh)
    try:
        if asn:
            return assess_candidates(client, _parse_asns(asn), use_pdb)
        return audit_file(client, use_pdb, verbose)
    finally:
        client.close()
