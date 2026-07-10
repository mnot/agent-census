"""Render a deep trace of one client or all clients of a kind.

This is where a human checks a verdict against the raw evidence: every signal
that fired (including the runners-up that lost), the measured features, the
robots-compliance finding, and the actual requests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..model import Classification, ClientProfile, Kind
from ..pipeline import AnalysisResult
from .aggregate import group_actors
from .format import (
    client_label,
    count,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    kind_label,
    md_escape,
    ordered_tags,
    rationale_rows,
    truncate,
)

# Inspecting a single IP that carries at least this many distinct clients (a
# user-agent-rotating host) prints a per-client summary instead of one full
# block each, which would otherwise be near-identical and unreadably long.
ROLLUP_MIN_CLIENTS = 5


def select_profiles(
    result: AnalysisResult,
    *,
    client: str | None,
    kind: str | None,
    network: str | None = None,
    actor: str | None = None,
    tag: str | None = None,
) -> list[ClientProfile]:
    """Pick the profiles to inspect by client substring, kind, network, tag, and/or actor.

    The filters compose (AND), so ``kind`` + ``network`` drills into one cell of
    the kind x network cross-tab. ``network`` is a case-insensitive substring of
    each client's real origin-network label (e.g. ``aws``, ``relay``,
    ``residential``) -- matched before the report's display-time folding, so it can
    select a low-volume datacentre that the cross-tab collapses into its
    ``Other datacenters`` column rather than breaking out on its own.

    ``tag`` is a case-insensitive substring of the client's classification tags, so
    a family prefix selects the whole family: ``wba`` catches ``wba-verified`` /
    ``wba-expired`` / ``wba-mixed``, ``robots`` catches ``checked-robots`` /
    ``ignores-robots``. A client matches if any one of its tags contains the needle.

    ``actor`` is the exact id that leads a display-time actor group -- an IP,
    subnet, or operator label, the id the HTML report copies from a grouped row's
    summary. It expands to every member of that group, so the whole rotation an
    operator ran across many addresses can be inspected as one, not one member at
    a time.
    """
    profiles = list(result.profiles)
    if kind is not None:
        want = kind.strip().lower().replace(" ", "_").replace("-", "_")
        profiles = [p for p in profiles if p.classification.primary.value == want]
    if network is not None:
        needle = network.lower()
        profiles = [p for p in profiles if p.network and needle in p.network.lower()]
    if tag is not None:
        needle = tag.lower()
        profiles = [p for p in profiles if any(needle in t.lower() for t in p.classification.tags)]
    if actor is not None:
        profiles = _actor_members(profiles, actor)
    if client is not None:
        needle = client.lower()
        profiles = [
            p for p in profiles if needle in p.client_id.display.lower() or p.client_id.ip == client
        ]
    return profiles


def _actor_members(profiles: list[ClientProfile], lead_id: str) -> list[ClientProfile]:
    """Every member of the actor group(s) led by ``lead_id`` (an IP, subnet, or
    operator label -- whatever the lead's ``client_id.ip`` holds).

    Reconstructs the same folding the HTML report shows under a disclosure triangle,
    so an ``--actor`` id copied from a summary row expands back to exactly its
    members. Grouping runs per primary kind, mirroring the report's per-kind
    sections, so it holds even when ``--kind`` isn't also given."""
    by_kind: dict[Kind, list[ClientProfile]] = {}
    for profile in profiles:
        by_kind.setdefault(profile.classification.primary, []).append(profile)
    selected: list[ClientProfile] = []
    for kind_profiles in by_kind.values():
        for group in group_actors(kind_profiles):
            if group.lead.client_id.ip == lead_id:
                selected.extend(group.members)
    return selected


def _identity_block(profile: ClientProfile) -> list[str]:
    feats = profile.features
    cls = profile.classification
    return [
        f"## {md_escape(client_label(profile))}",
        "",
        f"- **Classified:** `{kind_label(cls.primary)}` (confidence {cls.confidence:.0%})",
        f"- **IP:** {profile.client_id.ip}"
        + (f" ({len(profile.member_ips)} IPs merged)" if profile.member_ips else ""),
        f"- **Network:** {profile.network}" if profile.network else "- **Network:** –",
        f"- **User-Agent:** "
        f"{md_escape(elide_ua(feats.user_agent, is_browser=cls.primary is Kind.BROWSER) or '–')}",
        f"- **Requests:** {feats.request_count:,} · "
        f"**Bandwidth:** {human_bytes(feats.total_bytes)} · "
        f"**Span:** {human_duration(feats.duration_seconds)}",
        f"- **Seen:** {fmt_ts(feats.first_seen)} → {fmt_ts(feats.last_seen)}",
        "",
    ]


def _rationale_block(profile: ClientProfile) -> list[str]:
    cls = profile.classification
    lines = ["### Why this classification", ""]
    for row in rationale_rows(cls):
        marker = "→" if row.primary else " "
        lines.append(
            f"- {marker} **{kind_label(row.kind)}** ({row.confidence:.0%}) — {row.classifier}"
        )
        for item in row.evidence:
            lines.append(f"    - {md_escape(item)}")
    lines.append("")
    lines += _tags_evidence_block(cls)
    return lines


def _tags_evidence_block(cls: Classification) -> list[str]:
    """Every tag with the concrete measurement that earned it (the second axis of
    the verdict, alongside the kind signals above)."""
    if not cls.tags:
        return ["**Tags:** –", ""]
    evidence = dict(cls.tag_evidence)
    lines = ["**Tags**", ""]
    for tag in ordered_tags(cls.tags):
        why = evidence.get(tag)
        lines.append(f"- `{tag}` — {md_escape(why)}" if why else f"- `{tag}`")
    lines.append("")
    return lines


def _compliance_block(profile: ClientProfile) -> list[str]:
    report = profile.compliance
    if report is None:
        return []
    lines = ["### robots.txt", "", f"- **Verdict:** {report.verdict.value}"]
    if report.matched_group is not None:
        lines.append(f"- **Matched group:** `{report.matched_group}`")
    lines.append(f"- **Disallowed paths requested:** {report.disallowed_hits}")
    if report.sample_disallowed:
        lines.append(f"  - e.g. {', '.join(md_escape(p) for p in report.sample_disallowed)}")
    lines.append(f"- **Fetched robots.txt first:** {report.fetched_robots_first}")
    if report.crawl_delay is not None:
        lines.append(
            f"- **Crawl-delay:** {report.crawl_delay}s "
            f"(respected: {report.crawl_delay_respected})"
        )
    lines.append("")
    return lines


def _features_block(profile: ClientProfile) -> list[str]:
    lines = ["### Features", "", "| Metric | Value |", "| --- | --- |"]
    lines += [
        f"| {md_escape(name)} | {md_escape(value)} |"
        for name, value in feature_rows(profile.features)
    ]
    lines.append("")
    return lines


def _trace_block(profile: ClientProfile, limit: int, full: bool) -> list[str]:
    entries = sorted(profile.entries, key=lambda e: (e.timestamp is None, e.timestamp or e.line_no))
    shown = entries if full else entries[:limit]
    lines = [
        f"### Request trace ({len(shown)} of {len(entries)})",
        "",
        "| Time | Method | Path | Status | Bytes | Referer |",
        "| --- | --- | --- | --: | --: | --- |",
    ]
    for entry in shown:
        request = (entry.path + ("?" + entry.query if entry.query else "")) or entry.raw_request
        target = md_escape(request[:80])
        lines.append(
            f"| {fmt_ts(entry.timestamp)} | {entry.method or '–'} | {target or '–'} | "
            f"{entry.status if entry.status is not None else '–'} | "
            f"{entry.bytes_sent if entry.bytes_sent is not None else '–'} | "
            f"{md_escape((entry.referer or '–')[:60])} |"
        )
    if not full and len(entries) > limit:
        lines.append(f"| …{len(entries) - limit:,} more (use --full) | | | | | |")
    lines.append("")
    return lines


def _is_rotation(profiles: list[ClientProfile]) -> bool:
    """True when every selected profile is the same IP and there are enough to roll up."""
    return len(profiles) >= ROLLUP_MIN_CLIENTS and len({p.client_id.ip for p in profiles}) == 1


def _rollup_block(profiles: list[ClientProfile]) -> list[str]:
    ip = profiles[0].client_id.ip
    total_requests = sum(p.features.request_count for p in profiles)
    total_bytes = sum(p.features.total_bytes for p in profiles)
    lines = [
        f"## {ip} — {count(len(profiles), 'client')} on one IP",
        "",
        f"This IP presents {count(len(profiles), 'distinct user-agent')} (user-agent rotation). "
        "Per-client summary below; inspect one by passing a distinctive part of its "
        "user-agent to `--client`.",
        "",
        "| User-Agent | Kind | Conf. | Requests | Bandwidth | Tags |",
        "| --- | --- | --: | --: | --: | --- |",
    ]
    for profile in profiles:
        cls = profile.classification
        ua = elide_ua(profile.features.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–"
        tags = ", ".join(sorted(cls.tags)) or "–"
        lines.append(
            f"| {md_escape(truncate(ua, 70))} | {kind_label(cls.primary)} | "
            f"{cls.confidence:.0%} | "
            f"{profile.features.request_count:,} | {human_bytes(profile.features.total_bytes)} | "
            f"{tags} |"
        )
    lines.append(f"| **Total** | | | {total_requests:,} | {human_bytes(total_bytes)} | |")
    lines.append("")
    return lines


# --- Brief mode -------------------------------------------------------------
#
# `--brief` trades the full per-client blocks for one compact row each, and the
# columns are chosen from the selector that drove the selection: inspecting by
# `--kind vuln_scanner` shows the attack shape (probe / traversal / evasion),
# by a `wba` tag shows the signature verdict and operator, by `--network` shows
# who is on that network. A column is a header, an alignment, and a getter that
# turns one profile into its cell.


@dataclass(frozen=True, slots=True)
class _Col:
    header: str
    right: bool  # right-align (numeric) rather than left
    get: Callable[[ClientProfile], str]


def _ua(profile: ClientProfile) -> str:
    cls = profile.classification
    ua = elide_ua(profile.features.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–"
    return md_escape(truncate(ua, 60))


def _tags_cell(profile: ClientProfile) -> str:
    return ", ".join(ordered_tags(profile.classification.tags)) or "–"


def _probe_cell(profile: ClientProfile) -> str:
    feats = profile.features
    return f"{feats.vuln_path_hits} ({feats.vuln_path_ratio:.0%})" if feats.vuln_path_hits else "–"


def _robots_cell(profile: ClientProfile) -> str:
    return profile.compliance.verdict.value if profile.compliance else "–"


def _disallowed_cell(profile: ClientProfile) -> str:
    return str(profile.compliance.disallowed_hits) if profile.compliance else "–"


def _verification_cell(profile: ClientProfile) -> str:
    return profile.verification.status.value if profile.verification else "–"


def _wba_operator_cell(profile: ClientProfile) -> str:
    if profile.wba is None:
        return "–"
    return md_escape(profile.wba.operator or profile.wba.signer_domain or "–")


def _wba_keyid_cell(profile: ClientProfile) -> str:
    if profile.wba is None or not profile.wba.keyid:
        return "–"
    return f"`{truncate(profile.wba.keyid, 16)}`"


def _tag_why_cell(needle: str) -> Callable[[ClientProfile], str]:
    """The concrete evidence for whichever of this client's tags matched the
    `--tag` needle -- the point of selecting by that tag, shown per client."""

    def get(profile: ClientProfile) -> str:
        evidence = dict(profile.classification.tag_evidence)
        for tag in ordered_tags(profile.classification.tags):
            if needle in tag.lower():
                why = evidence.get(tag)
                return md_escape(truncate(why, 60)) if why else f"`{tag}`"
        return "–"

    return get


_C_UA = _Col("User-Agent", False, _ua)
_C_IP = _Col("IP", False, lambda p: p.client_id.ip)
_C_KIND = _Col("Kind", False, lambda p: kind_label(p.classification.primary))
_C_CONF = _Col("Conf.", True, lambda p: f"{p.classification.confidence:.0%}")
_C_REQUESTS = _Col("Requests", True, lambda p: f"{p.features.request_count:,}")
_C_BYTES = _Col("Bandwidth", True, lambda p: human_bytes(p.features.total_bytes))
_C_TAGS = _Col("Tags", False, _tags_cell)
_C_NETWORK = _Col("Network", False, lambda p: md_escape(p.network) if p.network else "–")
_C_PROBE = _Col("Probe paths", True, _probe_cell)
_C_TRAVERSAL = _Col("Traversal", True, lambda p: str(p.features.traversal_hits or "–"))
_C_EVASION = _Col("Evasion", True, lambda p: str(p.features.evasion_hits or "–"))
_C_404 = _Col("404 %", True, lambda p: f"{p.features.ratio_404:.0%}")
_C_ROBOTS = _Col("robots", False, _robots_cell)
_C_DISALLOWED = _Col("Disallowed", True, _disallowed_cell)
_C_COVERAGE = _Col("Coverage", True, lambda p: f"{p.features.coverage:.0%}")
_C_DISTINCT = _Col("Distinct paths", True, lambda p: f"{p.features.distinct_paths:,}")
_C_FEED = _Col("Feed %", True, lambda p: f"{p.features.feed_ratio:.0%}")
_C_VERIFICATION = _Col("Verification", False, _verification_cell)
_C_WBA_STATUS = _Col("WBA", False, lambda p: p.wba.status.value if p.wba else "–")
_C_WBA_OPERATOR = _Col("Operator", False, _wba_operator_cell)
_C_WBA_KEYID = _Col("Key id", False, _wba_keyid_cell)

_GENERIC_COLS = [_C_UA, _C_KIND, _C_CONF, _C_REQUESTS, _C_TAGS]
_NETWORK_COLS = [_C_IP, _C_NETWORK, _C_KIND, _C_REQUESTS, _C_BYTES]
_IDENTITY_COLS = [_C_IP, _C_UA, _C_KIND, _C_REQUESTS, _C_BYTES]
_VULN_COLS = [_C_UA, _C_PROBE, _C_TRAVERSAL, _C_EVASION, _C_404, _C_REQUESTS]

# Kinds whose story is crawl shape + robots politeness rather than raw identity.
# (feed_reader is handled ahead of this set -- it gets its own feed-ratio columns.)
_CRAWL_KINDS = {
    "crawler",
    "ai_crawler",
    "search_engine",
    "archiver",
    "seo_marketing",
    "data_harvester",
    "scraper",
}
# Kinds where the question is whether the client is who its UA claims.
_IDENTITY_KINDS = {"browser", "spoofed_browser", "impersonator", "app"}


def _kind_columns(kind: str) -> list[_Col]:
    want = kind.strip().lower().replace(" ", "_").replace("-", "_")
    if want == "vuln_scanner":
        return _VULN_COLS
    if want == "feed_reader":
        return [_C_UA, _C_FEED, _C_REQUESTS]
    if want in _CRAWL_KINDS:
        return [_C_UA, _C_ROBOTS, _C_COVERAGE, _C_DISTINCT, _C_REQUESTS]
    if want in _IDENTITY_KINDS:
        return [_C_UA, _C_NETWORK, _C_VERIFICATION, _C_REQUESTS, _C_TAGS]
    return _GENERIC_COLS


def _tag_columns(tag: str) -> list[_Col]:
    needle = tag.lower()
    if "wba" in needle:
        return [_C_UA, _C_WBA_STATUS, _C_WBA_OPERATOR, _C_WBA_KEYID, _C_REQUESTS]
    if "robots" in needle:
        return [_C_UA, _C_ROBOTS, _C_DISALLOWED, _C_REQUESTS]
    if any(k in needle for k in ("dns", "ip-", "asn", "verif", "impersonat", "associated")):
        return [_C_UA, _C_VERIFICATION, _C_NETWORK, _C_REQUESTS]
    if any(k in needle for k in ("probe", "traversal", "evasion", "404")):
        return _VULN_COLS
    # Any other tag: show the concrete evidence that earned it, per client.
    return [
        _C_UA,
        _C_KIND,
        _Col(f"Why `{md_escape(tag)}`", False, _tag_why_cell(needle)),
        _C_REQUESTS,
    ]


def _brief_columns(
    *, kind: str | None, tag: str | None, network: str | None, actor: str | None
) -> tuple[list[_Col], str]:
    """The column set and a short focus label, chosen from the active selector.
    Most specific selector wins: an explicit tag over a kind over a network."""
    if tag is not None:
        return _tag_columns(tag), f"--tag {tag}"
    if kind is not None:
        return _kind_columns(kind), f"--kind {kind}"
    if network is not None:
        return _NETWORK_COLS, f"--network {network}"
    if actor is not None:
        return _IDENTITY_COLS, f"--actor {actor}"
    return _GENERIC_COLS, "selection"


def _brief_block(profiles: list[ClientProfile], cols: list[_Col], focus: str) -> list[str]:
    lines = [
        f"_{count(len(profiles), 'client')} · brief view tuned to `{focus}`._",
        "",
        "| " + " | ".join(c.header for c in cols) + " |",
        "| " + " | ".join("--:" if c.right else "---" for c in cols) + " |",
    ]
    for profile in profiles:
        lines.append("| " + " | ".join(c.get(profile) for c in cols) + " |")
    lines.append("")
    return lines


def render_inspect(
    selected: list[ClientProfile],
    *,
    limit: int = 20,
    full: bool = False,
    brief: bool = False,
    kind: str | None = None,
    tag: str | None = None,
    network: str | None = None,
    actor: str | None = None,
) -> str:
    """Render inspection output for already-selected client profiles.

    ``brief`` collapses each client to one compact row whose columns are tuned to
    the active selector (``kind`` / ``tag`` / ``network`` / ``actor``), for scanning
    a whole selection at once rather than reading each verdict in full."""
    if not selected:
        return "_No matching clients._\n"
    selected = sorted(selected, key=lambda p: p.features.request_count, reverse=True)
    out: list[str] = ["# Client Inspection", ""]
    if brief:
        cols, focus = _brief_columns(kind=kind, tag=tag, network=network, actor=actor)
        out += _brief_block(selected, cols, focus)
        return "\n".join(out).rstrip() + "\n"
    if _is_rotation(selected):
        out += _rollup_block(selected)
        return "\n".join(out).rstrip() + "\n"
    for profile in selected:
        out += _identity_block(profile)
        out += _rationale_block(profile)
        out += _compliance_block(profile)
        out += _features_block(profile)
        out += _trace_block(profile, limit, full)
        out.append("---")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
