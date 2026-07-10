"""Load the bundled reference data (one TOML file per category under ``data/``).

The files are grouped into subdirectories by role: ``signatures/`` for the string
match-lists (UA tokens and request paths), ``networks/`` for IP-range stanzas,
``agents/`` for declared crawlers, and ``tuning/`` for the numeric knobs.

Flat lists (``signatures/scanner_ua`` / ``signatures/feed_readers``) hold an array
under a key matching the file name; ``signatures/vuln_paths`` splits into two keyed
arrays (see :func:`load_vuln_paths`). Declared-crawler files (``search_engine`` …)
hold an ``[[agent]]`` array of tables, each with a ``ua_substring`` and optional
``domains`` / ``ranges`` / ``ranges_url``. Everything is cached per run.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType
from typing import Any

from .errors import ConfigError
from .iprange import KNOWN_FORMATS

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no stdlib tomllib.
    import tomli as tomllib


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


# Scalar / string type tokens and their predicates. `str|str[]` accepts either a
# single value or a list of them (e.g. an agent's ranges_url, which may name more
# than one published feed). `bool` is an int subclass, so `int` excludes it -- so
# `true` isn't read as a valid integer.
_SCALAR_PREDICATES: dict[str, Callable[[object], bool]] = {
    "str": lambda v: isinstance(v, str),
    "str|str[]": lambda v: isinstance(v, str) or _is_str_list(v),
    "str[]": _is_str_list,
    "bool": lambda v: isinstance(v, bool),
    "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "date": lambda v: isinstance(v, date),
}


def _type_ok(value: object, kind: str) -> bool:
    """True if ``value`` matches a schema type token (str / bool / date / str[] /
    int[] / asn[] / str|str[])."""
    predicate = _SCALAR_PREDICATES.get(kind)
    if predicate is not None:
        return predicate(value)
    if kind in ("int[]", "asn[]"):
        # bool is an int subclass in Python; exclude it so `true` isn't a valid int.
        # "asn[]" additionally bounds each value to the 32-bit ASN range, rejecting
        # a negative or absurdly large number that would reach a Radar/URL lookup.
        ranged = kind == "asn[]"
        return isinstance(value, list) and all(
            isinstance(x, int) and not isinstance(x, bool) and (not ranged or 0 <= x <= 0xFFFFFFFF)
            for x in value
        )
    raise AssertionError(f"unknown schema type {kind!r}")  # pragma: no cover


def _check_top_level(filename: str, data: dict[str, Any], allowed: set[str]) -> None:
    extra = set(data) - allowed
    if extra:
        raise ConfigError(
            f"{filename}: unexpected top-level key(s) {', '.join(sorted(extra))} "
            f"(expected {', '.join(sorted(allowed))})"
        )


def _check_table(filename: str, table: str, section: object, allowed: set[str]) -> dict[str, Any]:
    """Confirm ``[table]`` is a table with no keys outside ``allowed``; return it."""
    if not isinstance(section, dict):
        raise ConfigError(f"{filename}: [{table}] must be a table")
    extra = set(section) - allowed
    if extra:
        raise ConfigError(
            f"{filename}: [{table}] unexpected key(s) {', '.join(sorted(extra))} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )
    return section


def _grouped_lists(
    filename: str, data: dict[str, Any], schema: dict[str, set[str]]
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Validate a file of ``[table]`` sections, each holding named ``str[]`` arrays.

    ``schema`` maps each expected table to the keys it must contain. Returns a
    ``{(table, key): tuple}`` mapping. Unexpected tables or keys, non-table sections,
    non-``str[]`` values, and empty/missing arrays are all ``ConfigError`` -- an
    empty list would silently compile to a match-everything regex downstream, so a
    file is required to actually carry every list it declares.
    """
    _check_top_level(filename, data, set(schema))
    out: dict[tuple[str, str], tuple[str, ...]] = {}
    for table, keys in schema.items():
        section = _check_table(filename, table, data.get(table, {}), keys)
        for key in keys:
            value = section.get(key, [])
            if not _type_ok(value, "str[]"):
                raise ConfigError(f"{filename}: [{table}] '{key}' must be a list of strings")
            if not value:
                raise ConfigError(f"{filename}: [{table}] '{key}' must not be empty")
            out[(table, key)] = tuple(value)
    return out


def _is_number(value: object) -> bool:
    # bool is an int subclass in Python; exclude it so `true` isn't a valid number.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _as_urls(value: object) -> tuple[str, ...]:
    """Normalise a ``ranges_url`` field -- absent, a single URL, or a list of URLs
    (an agent may publish its ranges across more than one feed, e.g. one per IP
    family) -- to a tuple of URLs."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(url for url in value if isinstance(url, str))
    return ()


def load_tuning(name: str, schema: Mapping[str, str]) -> Mapping[str, float]:
    """Load a numeric tuning file (``data/tuning/<name>.toml``) into a flat mapping.

    ``schema`` maps each output knob name to its location in the file: either a
    top-level scalar (``"clean_browser_floor"``) or a ``table.key`` path
    (``"asset_coload.weight"``). The grouping exists for the file's readability; the
    returned mapping is flat, keyed by the schema's names. Every listed knob must be
    present and numeric, and any unexpected table or key in the file is rejected --
    so the file is always the complete, accurate list of a classifier's knobs. An
    integer in the file is accepted and widened to float.
    """
    filename = f"tuning/{name}.toml"
    data = _load(name, "tuning")
    scalars: set[str] = set()
    tables: dict[str, set[str]] = {}
    for path in schema.values():
        if "." in path:
            table, key = path.split(".", 1)
            tables.setdefault(table, set()).add(key)
        else:
            scalars.add(path)
    _check_top_level(filename, data, scalars | set(tables))
    for table, keys in tables.items():
        _check_table(filename, table, data.get(table, {}), keys)
    values: dict[str, float] = {}
    for field, path in schema.items():
        table, _, key = path.partition(".")
        section = data.get(table) if key else data
        raw = section.get(key or table) if isinstance(section, dict) else None
        if raw is None:
            raise ConfigError(f"{filename}: missing '{path}'")
        if not _is_number(raw):
            raise ConfigError(f"{filename}: '{path}' must be a number")
        values[field] = float(raw)
    return MappingProxyType(values)


def _validate_records(
    filename: str,
    array: str,
    entries: object,
    schema: dict[str, str],
    require: Callable[[dict[str, Any]], str] | None = None,
) -> list[dict[str, Any]]:
    """Check every ``[[array]]`` table for unknown keys, bad types, and `require`."""
    if not isinstance(entries, list):
        raise ConfigError(f"{filename}: [[{array}]] must be an array of tables")
    for index, entry in enumerate(entries, start=1):
        ctx = f"{filename}: [[{array}]] #{index}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{ctx}: expected a table")
        for key, value in entry.items():
            if key not in schema:
                raise ConfigError(
                    f"{ctx}: unknown key '{key}' (allowed: {', '.join(sorted(schema))})"
                )
            if not _type_ok(value, schema[key]):
                raise ConfigError(f"{ctx}: '{key}' must be {schema[key]}")
        problem = require(entry) if require else ""
        if problem:
            raise ConfigError(f"{ctx}: {problem}")
    return entries


def _bad_format(entry: dict[str, Any]) -> str:
    fmt = entry.get("format")
    if fmt is not None and fmt not in KNOWN_FORMATS:
        return f"unknown format '{fmt}' (allowed: {', '.join(sorted(KNOWN_FORMATS))})"
    return ""


_AGENT_SCHEMA = {
    "ua_substring": "str",
    "name": "str",
    "domains": "str[]",
    "ranges": "str[]",
    "ranges_url": "str|str[]",
    "format": "str",
    "asns": "asn[]",
    "asn_primary": "bool",
    "rdns_fallback": "bool",
    "user_triggered": "bool",
    "wba_operator": "str",
}
_SOURCE_SCHEMA = {
    "name": "str",
    "ranges": "str[]",
    "ranges_url": "str",
    "format": "str",
    "asns": "asn[]",
}
_NETWORK_SCHEMA = {
    "name": "str",
    "tag": "str",
    "group": "str",
    "ranges": "str[]",
    "ranges_url": "str",
    "format": "str",
    "asns": "asn[]",
}
_FAMILY_SCHEMA = {
    "name": "str",
    "anchor_major": "int",
    "anchor_date": "date",
    "days_per_major": "int",
}


def _require_family(entry: dict[str, Any]) -> str:
    missing = [k for k in _FAMILY_SCHEMA if k not in entry]
    return f"missing {', '.join(missing)}" if missing else ""


@dataclass(frozen=True, slots=True)
class CrawlerSpec:
    """How to verify a declared crawler: reverse-DNS domains, IP ranges, and/or
    the origin AS numbers the operator crawls from."""

    domains: tuple[str, ...] = ()
    ranges: tuple[str, ...] = ()
    # Zero or more published range feeds. More than one lets an operator that splits
    # its list across feeds (e.g. Pingdom's separate IPv4 and IPv6 lists) be covered
    # in full; all are fetched and merged, and all share the single ``fmt`` below.
    ranges_urls: tuple[str, ...] = ()
    fmt: str = "prefixes"  # how to parse each ranges_url feed (see iprange.extract_cidrs)
    # AS numbers the operator is expected to crawl from -- a second identity channel
    # that combines with the network channel (IP ranges and/or rDNS domains) as an
    # OR (see pipeline ``_resolve_asn_verification``). A network ``VERIFIED`` is the
    # strongest proof and stands; otherwise a UA match from one of these AS numbers
    # confirms the identity even when the network channel said otherwise -- an IP
    # outside the ranges *or* a failing rDNS check (``ASN_ASSOCIATED``, coarser than
    # a range/DNS hit); a UA match from a different logged AS while the network
    # channel also failed is impersonation. A missing AS number is never read as
    # impersonation. Declare alongside ranges/domains for an operator whose traffic
    # also comes from an AS it owns (e.g. Censys's ASNs beyond its published
    # subnets, or facebookexternalhit from AS32934 when its rDNS can't be confirmed).
    asns: tuple[int, ...] = ()
    # When an agent declares both ranges and domains, both must verify by default
    # (either failing is impersonation). Set this for operators whose reverse DNS
    # isn't reliable: ranges become primary and the domains are only a fallback
    # used when the ranges can't be obtained.
    rdns_fallback: bool = False
    # The agent fetches on behalf of a present user (a "-User" / on-behalf-of proxy
    # like ChatGPT-User or Amzn-User), rather than crawling autonomously. Orthogonal
    # to the kind -- it surfaces as the ``user-triggered`` tag, not a kind of its own.
    user_triggered: bool = False
    # Names the :class:`WbaOperator` (by ``name``) this UA is expected to sign as,
    # if it uses Web Bot Auth. Lets the impersonation check catch a UA claiming
    # this agent while validly signed by a different registered operator.
    wba_operator: str | None = None
    # The agent's declared human-readable name (e.g. "Googlebot"), for display --
    # orthogonal to every verification field above.
    name: str | None = None


@dataclass(frozen=True, slots=True)
class WbaOperator:
    """A Web Bot Auth operator: a signing identity mapped to a human name.

    Matched offline against a request's parsed ``Signature-Agent`` URL and/or the
    ``keyid`` (JWK thumbprint) its signature names -- the "who", orthogonal to
    whether the signature verifies. The crawler UA(s) it should present are linked
    the other way round -- a declared ``[[agent]]`` entry's own ``wba_operator``
    names this operator -- so a *valid* signature whose operator differs from the
    declared crawler can be flagged (phase 2's stricter check).
    """

    name: str
    agent_urls: tuple[str, ...] = ()
    keyids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RangeSource:
    """One provider's IP ranges: inline CIDRs and/or a fetchable published list."""

    name: str = ""
    ranges: tuple[str, ...] = ()
    ranges_url: str | None = None
    fmt: str = "prefixes"  # how to parse ranges_url (see iprange.extract_cidrs)
    asns: tuple[int, ...] = ()  # AS numbers this provider owns, for log-ASN matching


@dataclass(frozen=True, slots=True)
class EgressNetwork:
    """A named shared-egress network whose clients are merged and tagged."""

    name: str = ""  # the network's own identity -> client id (e.g. "Tor", "NordVPN")
    tag: str = ""
    group: str = ""  # cross-tab column header; several networks may share one (e.g. "VPNs")
    ranges: tuple[str, ...] = ()
    ranges_url: str | None = None
    fmt: str = "prefixes"
    asns: tuple[int, ...] = ()  # match by AS number too (for VPNs/proxies with no range list)


@dataclass(frozen=True, slots=True)
class BrowserRelease:
    """A browser family's release cadence: a known major + date, and days/major."""

    name: str
    anchor_major: int
    anchor_date: date
    days_per_major: int


@dataclass(frozen=True, slots=True)
class UaSignatures:
    """Syntactic User-Agent markers, grouped by what they recognise.

    Each tuple is a list of case-insensitive tokens from ``signatures/ua_signatures.toml``. The
    matchers in :mod:`agent_census.uas` compile these into the regexes that decide
    whether a UA looks like a browser, declares itself a bot, names a headless
    engine, is a bare HTTP library, or names a feed reader.
    """

    browser_engines: tuple[str, ...] = ()
    # Automation tokens, split by how they must sit in the string (see the data file).
    automation_substrings: tuple[str, ...] = ()  # matched anywhere
    automation_standalone_words: tuple[str, ...] = ()  # word boundary both sides
    automation_suffix_words: tuple[str, ...] = ()  # word boundary on the right only
    headless_engines: tuple[str, ...] = ()
    library_names: tuple[str, ...] = ()
    feed_terms: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RequestSignatures:
    """Request-line markers (path / query / method) from ``signatures/request_signatures.toml``.

    Consumed by feature extraction to count static assets, page fetches, probing
    attempts, uncommon methods, and feed polls. Plain token lists; the regex/set
    machinery that uses them lives in :mod:`agent_census.features`.
    """

    static_extensions: tuple[str, ...] = ()
    static_media_types: tuple[str, ...] = ()
    page_extensions: tuple[str, ...] = ()
    page_media_types: tuple[str, ...] = ()
    chrome_asset_markers: tuple[str, ...] = ()
    traversal_markers: tuple[str, ...] = ()
    evasion_markers: tuple[str, ...] = ()
    uncommon_methods: tuple[str, ...] = ()
    feed_filename_tokens: tuple[str, ...] = ()
    feed_filenames: tuple[str, ...] = ()


@lru_cache(maxsize=None)
def _load(name: str, subdir: str = "") -> dict[str, Any]:
    root = files("agent_census.data")
    resource = (root / subdir / f"{name}.toml") if subdir else (root / f"{name}.toml")
    return tomllib.loads(resource.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def load_list(name: str) -> tuple[str, ...]:
    """Return the flat array from ``signatures/<name>.toml`` (keyed by ``name``).

    These are the corroborating substring lists (scanner / monitor / app-client /
    feed-reader UA tokens, spam-submission paths); they all live under
    ``data/signatures/``. The array must be present and non-empty: an empty list
    would compile to a match-everything regex at the call sites, so a missing/empty
    list is a ``ConfigError`` rather than a silently over-broad matcher.
    """
    data = _load(name, "signatures")
    _check_top_level(f"signatures/{name}.toml", data, {name})
    value = data.get(name, [])
    if not _type_ok(value, "str[]"):
        raise ConfigError(f"signatures/{name}.toml: '{name}' must be a list of strings")
    if not value:
        raise ConfigError(f"signatures/{name}.toml: '{name}' must not be empty")
    return tuple(value)


@lru_cache(maxsize=None)
def load_vuln_paths() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(always_probe, probe_if_absent)`` from ``signatures/vuln_paths.toml``.

    ``always_probe`` substrings are hostile regardless of the response status
    (secret files, RCE, traversal). ``probe_if_absent`` substrings are real paths
    on sites running that stack, so a hit counts as probing only when the response
    says the path is absent (404/410); a resolved response means it belongs to this
    site. See the file header for the rationale.

    Both keys must be present and non-empty: like :func:`load_list`, an empty array
    compiles to a match-everything regex, so a missing/emptied bucket is a
    ``ConfigError`` rather than silently disabling (or over-broadening) that class
    of probe detection.
    """
    data = _load("vuln_paths", "signatures")
    _check_top_level("signatures/vuln_paths.toml", data, {"always_probe", "probe_if_absent"})
    out: list[tuple[str, ...]] = []
    for key in ("always_probe", "probe_if_absent"):
        value = data.get(key, [])
        if not _type_ok(value, "str[]"):
            raise ConfigError(f"signatures/vuln_paths.toml: '{key}' must be a list of strings")
        if not value:
            raise ConfigError(f"signatures/vuln_paths.toml: '{key}' must not be empty")
        out.append(tuple(value))
    return out[0], out[1]


# Crawler/bot categories: one TOML file each, an [[agent]] table per agent.
#
# This is the *identity-verification* list (netverify, ASN feeds), NOT the
# "recognised good crawler" list (uas.KNOWN_CRAWLER_CATEGORIES, which routes a UA
# to a crawler classifier and makes the generic crawler/scraper classifiers
# defer). vuln_scanner / monitor belong here so a self-declaring scanner or
# monitor can be authenticated against its published ranges, but must stay out of
# that other list -- their behavioural classification is unchanged; we only
# confirm (or refute) the network origin of the identity they claim.
KNOWN_AGENT_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
    "data_harvester",
    "vuln_scanner",
    "monitor",
)


def _require_agent(entry: dict[str, Any]) -> str:
    primary = bool(entry.get("asn_primary"))
    if primary and not entry.get("asns"):
        return "'asn_primary' needs an 'asns' list (the AS is the identity)"
    # Plain `asns` is verification for a UA-named agent, so it needs a ua_substring;
    # only an asn_primary agent may stand on its AS alone.
    if not entry.get("ua_substring") and not primary:
        return "an agent needs a 'ua_substring' (or 'asn_primary' with 'asns')"
    wba_operator = entry.get("wba_operator")
    # A stale/typo'd name wouldn't fail to load -- it would silently mismatch every
    # legitimately-signed request from this agent and misfire as impersonation, so
    # this is checked eagerly rather than left to surface at classification time.
    if wba_operator and wba_operator not in {op.name for op in load_wba_operators()}:
        return f"'wba_operator' {wba_operator!r} names no operator in agents/web_bot_auth.toml"
    return ""


@lru_cache(maxsize=None)
def _agents(category: str) -> tuple[dict[str, Any], ...]:
    """The validated ``[[agent]]`` tables of ``agents/<category>.toml`` (raw dicts)."""
    data = _load(category, "agents")
    label = f"agents/{category}.toml"
    _check_top_level(label, data, {"agent"})
    entries = _validate_records(
        label, "agent", data.get("agent", []), _AGENT_SCHEMA, _require_agent
    )
    return tuple(entries)


_WBA_OPERATOR_SCHEMA = {
    "name": "str",
    "agent_urls": "str[]",
    "keyids": "str[]",
}


def _require_wba_operator(entry: dict[str, Any]) -> str:
    if not entry.get("name"):
        return "a Web Bot Auth operator needs a 'name'"
    # It must be matchable by *something* offline -- a directory URL or a keyid.
    if not entry.get("agent_urls") and not entry.get("keyids"):
        return "an operator needs at least one 'agent_urls' or 'keyids' entry to match on"
    return ""


@lru_cache(maxsize=None)
def load_wba_operators() -> tuple[WbaOperator, ...]:
    """Return the Web Bot Auth operator list from ``agents/web_bot_auth.toml``.

    Maps a signing identity (directory URL and/or published JWK thumbprints) to a
    human operator name. Offline data, like the declared-crawler files; the
    cryptographic check is layered on separately. The crawler UA(s) an operator
    should present live on the matching ``[[agent]]`` entry's ``wba_operator``
    field, not here -- see :func:`load_tokens`.
    """
    data = _load("web_bot_auth", "agents")
    label = "agents/web_bot_auth.toml"
    _check_top_level(label, data, {"operator"})
    entries = _validate_records(
        label, "operator", data.get("operator", []), _WBA_OPERATOR_SCHEMA, _require_wba_operator
    )
    return tuple(
        WbaOperator(
            name=entry["name"],
            agent_urls=tuple(entry.get("agent_urls", ())),
            keyids=tuple(entry.get("keyids", ())),
        )
        for entry in entries
    )


@lru_cache(maxsize=None)
def load_tokens(category: str) -> tuple[tuple[str, CrawlerSpec], ...]:
    """Return ``(ua_substring, spec)`` pairs from ``<category>.toml``.

    Agents recognised by AS number rather than a UA token (no ``ua_substring``)
    are skipped here; see :func:`load_asn_agents`.
    """
    pairs: list[tuple[str, CrawlerSpec]] = []
    for entry in _agents(category):
        ua = entry.get("ua_substring")
        if not ua:
            continue
        spec = CrawlerSpec(
            domains=tuple(entry.get("domains", [])),
            ranges=tuple(entry.get("ranges", [])),
            ranges_urls=_as_urls(entry.get("ranges_url")),
            fmt=entry.get("format", "prefixes"),
            asns=tuple(entry.get("asns", [])),
            rdns_fallback=bool(entry.get("rdns_fallback", False)),
            user_triggered=bool(entry.get("user_triggered", False)),
            wba_operator=entry.get("wba_operator"),
            name=entry.get("name"),
        )
        pairs.append((ua, spec))
    return tuple(pairs)


@lru_cache(maxsize=None)
def load_asn_agents(category: str) -> tuple[tuple[int, str], ...]:
    """Return ``(asn, label)`` for ``asn_primary`` agents in ``<category>.toml``.

    Only ``asn_primary`` agents are recognised *by* their AS number (the AS is the
    identity): all their traffic folds into one entry, classified from the AS
    regardless of User-Agent. A plain ``asns`` list is verification for a
    ua_substring-named agent (see :class:`CrawlerSpec`) and is not returned here.
    """
    out: list[tuple[int, str]] = []
    for entry in _agents(category):
        if not entry.get("asn_primary"):
            continue
        label = entry.get("name") or entry.get("ua_substring") or category
        for asn in entry.get("asns", []):
            out.append((int(asn), label))
    return tuple(out)


@lru_cache(maxsize=None)
def load_asn_range_feeds() -> tuple[tuple[int, str, str], ...]:
    """``(asn, ranges_url, format)`` for ``asn_primary`` agents that publish a feed.

    Lets an AS-identified crawler be matched by IP when the log doesn't carry the
    client's AS number: its AS's announced prefixes are fetched and the IP checked
    against them. Keyed by the agent's first ``asns`` entry (all map to one label).
    Only ``asn_primary`` agents qualify -- recovering a verification agent's AS from
    its own range feed would defeat the ranges-take-precedence-over-ASN rule.
    """
    feeds: list[tuple[int, str, str]] = []
    for category in KNOWN_AGENT_CATEGORIES:
        for entry in _agents(category):
            urls, asns = _as_urls(entry.get("ranges_url")), entry.get("asns")
            if urls and asns and entry.get("asn_primary"):
                fmt = entry.get("format", "prefixes")
                feeds.extend((int(asns[0]), url, fmt) for url in urls)
    return tuple(feeds)


@lru_cache(maxsize=None)
def load_range_sources(name: str) -> tuple[RangeSource, ...]:
    """Return the ``[[source]]`` range stanzas from ``networks/<name>.toml``."""
    data = _load(name, "networks")
    _check_top_level(f"networks/{name}.toml", data, {"source"})
    entries = _validate_records(
        f"networks/{name}.toml", "source", data.get("source", []), _SOURCE_SCHEMA, _bad_format
    )
    sources: list[RangeSource] = []
    for entry in entries:
        sources.append(
            RangeSource(
                name=entry.get("name", ""),
                ranges=tuple(entry.get("ranges", [])),
                ranges_url=entry.get("ranges_url"),
                fmt=entry.get("format", "prefixes"),
                asns=tuple(int(asn) for asn in entry.get("asns", [])),
            )
        )
    return tuple(sources)


@lru_cache(maxsize=None)
def load_egress_networks() -> tuple[EgressNetwork, ...]:
    """Return the ``[[network]]`` stanzas from ``networks/egress_networks.toml``."""
    data = _load("egress_networks", "networks")
    _check_top_level("networks/egress_networks.toml", data, {"network"})
    entries = _validate_records(
        "networks/egress_networks.toml",
        "network",
        data.get("network", []),
        _NETWORK_SCHEMA,
        _bad_format,
    )
    networks: list[EgressNetwork] = []
    for entry in entries:
        networks.append(
            EgressNetwork(
                name=entry.get("name", ""),
                tag=entry.get("tag", ""),
                group=entry.get("group", ""),
                ranges=tuple(entry.get("ranges", [])),
                ranges_url=entry.get("ranges_url"),
                fmt=entry.get("format", "prefixes"),
                asns=tuple(entry.get("asns", [])),
            )
        )
    return tuple(networks)


@lru_cache(maxsize=None)
def load_browser_releases() -> tuple[BrowserRelease, ...]:
    """Return the ``[[family]]`` release-cadence anchors from ``browser_releases.toml``."""
    data = _load("browser_releases")
    _check_top_level("browser_releases.toml", data, {"family"})
    entries = _validate_records(
        "browser_releases.toml", "family", data.get("family", []), _FAMILY_SCHEMA, _require_family
    )
    return tuple(
        BrowserRelease(
            name=entry["name"],
            anchor_major=entry["anchor_major"],
            anchor_date=entry["anchor_date"],
            days_per_major=entry["days_per_major"],
        )
        for entry in entries
    )


_UA_SIGNATURE_SCHEMA: dict[str, set[str]] = {
    "browser": {"layout_engines"},
    "automation": {"substrings", "standalone_words", "suffix_words"},
    "headless": {"engines"},
    "http_library": {"names"},
    "feed_reader": {"generic_terms"},
}


@lru_cache(maxsize=None)
def load_ua_signatures() -> UaSignatures:
    """Return the grouped UA-string token lists from ``signatures/ua_signatures.toml``."""
    groups = _grouped_lists(
        "signatures/ua_signatures.toml", _load("ua_signatures", "signatures"), _UA_SIGNATURE_SCHEMA
    )
    return UaSignatures(
        browser_engines=groups[("browser", "layout_engines")],
        automation_substrings=groups[("automation", "substrings")],
        automation_standalone_words=groups[("automation", "standalone_words")],
        automation_suffix_words=groups[("automation", "suffix_words")],
        headless_engines=groups[("headless", "engines")],
        library_names=groups[("http_library", "names")],
        feed_terms=groups[("feed_reader", "generic_terms")],
    )


_REQUEST_SIGNATURE_SCHEMA: dict[str, set[str]] = {
    "static_assets": {"extensions", "media_types"},
    "pages": {"extensions", "media_types"},
    "chrome_assets": {"path_markers"},
    "path_traversal": {"markers"},
    "encoding_evasion": {"markers"},
    "methods": {"uncommon"},
    "feed_urls": {"filename_tokens", "filenames"},
}


@lru_cache(maxsize=None)
def load_request_signatures() -> RequestSignatures:
    """Return the grouped request-line token lists from ``signatures/request_signatures.toml``."""
    groups = _grouped_lists(
        "signatures/request_signatures.toml",
        _load("request_signatures", "signatures"),
        _REQUEST_SIGNATURE_SCHEMA,
    )
    return RequestSignatures(
        static_extensions=groups[("static_assets", "extensions")],
        static_media_types=groups[("static_assets", "media_types")],
        page_extensions=groups[("pages", "extensions")],
        page_media_types=groups[("pages", "media_types")],
        chrome_asset_markers=groups[("chrome_assets", "path_markers")],
        traversal_markers=groups[("path_traversal", "markers")],
        evasion_markers=groups[("encoding_evasion", "markers")],
        uncommon_methods=groups[("methods", "uncommon")],
        feed_filename_tokens=groups[("feed_urls", "filename_tokens")],
        feed_filenames=groups[("feed_urls", "filenames")],
    )


# Numeric thresholds shared by more than one classifier or tag (data/tuning/shared.toml),
# keyed by the names the consumers look them up under.
_SHARED_TUNING: dict[str, str] = {
    "unknown_threshold": "verdict.unknown_threshold",
    "browser_coload_min": "browser_shape.coload_ratio_min",
    "browser_coload_min_pages": "browser_shape.coload_min_pages",
    "browser_no_coload_max": "browser_shape.no_coload_max",
    "browser_follow_min": "browser_shape.follow_ratio_min",
    "browser_no_follow_max": "browser_shape.no_follow_max",
    "cadence_metronomic_max": "cadence.metronomic_max",
    "cadence_bursty_min": "cadence.bursty_min",
    "head_notable_ratio": "head_traffic.notable_ratio",
    "fabricated_self_referer_min": "fabricated_referer.self_referer_min",
    "fabricated_min_requests": "fabricated_referer.min_requests",
    "feed_dominant_ratio_min": "feed_traffic.dominant_ratio_min",
    "storm_404_ratio_min": "storm_404.ratio_min",
    "storm_404_distinct_paths_min": "storm_404.distinct_paths_min",
    "forbidden_ratio_min": "forbidden.ratio_min",
    "forbidden_min_requests": "forbidden.min_requests",
    "impossible_referer_ratio_min": "impossible_referer.ratio_min",
    "impossible_referer_min_hits": "impossible_referer.min_hits",
    "redirect_gate_min_requests": "redirect_gate.min_requests",
    "redirect_gate_3xx_ratio": "redirect_gate.gate_3xx_ratio",
    "no_cache_dominant_refetch_min": "no_cache_dominance.cold_refetch_min",
    "no_cache_dominant_fraction": "no_cache_dominance.dominant_fraction",
    "no_cache_high_volume": "no_cache_dominance.high_volume",
}


@lru_cache(maxsize=None)
def load_shared_tuning() -> Mapping[str, float]:
    """Return the cross-classifier numeric thresholds from ``tuning/shared.toml``."""
    return load_tuning("shared", _SHARED_TUNING)
