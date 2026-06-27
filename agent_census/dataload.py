"""Load the bundled reference data (one TOML file per category in ``data/``).

Flat lists (``vuln_paths`` / ``scanner_ua`` / ``feed_readers``) hold an array
under a key matching the file name. Declared-crawler files (``search_engine`` …)
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


def _type_ok(value: object, kind: str) -> bool:
    """True if ``value`` matches a schema type token (str / bool / str[] / int[])."""
    if kind == "str":
        return isinstance(value, str)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        # bool is an int subclass in Python; exclude it so `true` isn't a valid int.
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "date":
        return isinstance(value, date)
    if kind == "str[]":
        return isinstance(value, list) and all(isinstance(x, str) for x in value)
    if kind == "int[]":
        # bool is an int subclass in Python; exclude it so `true` isn't a valid ASN.
        return isinstance(value, list) and all(
            isinstance(x, int) and not isinstance(x, bool) for x in value
        )
    raise AssertionError(f"unknown schema type {kind!r}")  # pragma: no cover


def _check_top_level(filename: str, data: dict[str, Any], allowed: set[str]) -> None:
    extra = set(data) - allowed
    if extra:
        raise ConfigError(
            f"{filename}: unexpected top-level key(s) {', '.join(sorted(extra))} "
            f"(expected {', '.join(sorted(allowed))})"
        )


def _grouped_lists(
    filename: str, data: dict[str, Any], schema: dict[str, set[str]]
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Validate a file of ``[table]`` sections, each holding named ``str[]`` arrays.

    ``schema`` maps each expected table to the keys it may contain. Returns a
    ``{(table, key): tuple}`` mapping; a missing array reads as empty. Unexpected
    tables or keys, non-table sections, and non-``str[]`` values are ``ConfigError``.
    """
    _check_top_level(filename, data, set(schema))
    out: dict[tuple[str, str], tuple[str, ...]] = {}
    for table, keys in schema.items():
        section = data.get(table, {})
        if not isinstance(section, dict):
            raise ConfigError(f"{filename}: [{table}] must be a table")
        extra = set(section) - keys
        if extra:
            raise ConfigError(
                f"{filename}: [{table}] unexpected key(s) {', '.join(sorted(extra))} "
                f"(allowed: {', '.join(sorted(keys))})"
            )
        for key in keys:
            value = section.get(key, [])
            if not _type_ok(value, "str[]"):
                raise ConfigError(f"{filename}: [{table}] '{key}' must be a list of strings")
            out[(table, key)] = tuple(value)
    return out


def _is_number(value: object) -> bool:
    # bool is an int subclass in Python; exclude it so `true` isn't a valid number.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


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
        section = data.get(table, {})
        if not isinstance(section, dict):
            raise ConfigError(f"{filename}: [{table}] must be a table")
        extra = set(section) - keys
        if extra:
            raise ConfigError(
                f"{filename}: [{table}] unexpected key(s) {', '.join(sorted(extra))} "
                f"(allowed: {', '.join(sorted(keys))})"
            )
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
    "ranges_url": "str",
    "format": "str",
    "asns": "int[]",
    "asn_primary": "bool",
    "rdns_fallback": "bool",
}
_SOURCE_SCHEMA = {
    "name": "str",
    "ranges": "str[]",
    "ranges_url": "str",
    "format": "str",
    "asns": "int[]",
}
_NETWORK_SCHEMA = {
    "name": "str",
    "tag": "str",
    "group": "str",
    "ranges": "str[]",
    "ranges_url": "str",
    "format": "str",
    "asns": "int[]",
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
    """How to verify a declared crawler: reverse-DNS domains and/or IP ranges."""

    domains: tuple[str, ...] = ()
    ranges: tuple[str, ...] = ()
    ranges_url: str | None = None
    fmt: str = "prefixes"  # how to parse ranges_url (see iprange.extract_cidrs)
    # AS numbers the operator is expected to crawl from. The lowest-precedence
    # verification tier: used only when ranges/rDNS are absent or inconclusive. A
    # UA match from one of these AS numbers corroborates the identity; a UA match
    # from a different (logged) AS is impersonation.
    asns: tuple[int, ...] = ()
    # When an agent declares both ranges and domains, both must verify by default
    # (either failing is impersonation). Set this for operators whose reverse DNS
    # isn't reliable: ranges become primary and the domains are only a fallback
    # used when the ranges can't be obtained.
    rdns_fallback: bool = False


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

    Each tuple is a list of case-insensitive tokens from ``ua_signatures.toml``. The
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
    """Request-line markers (path / query / method) from ``request_signatures.toml``.

    Consumed by feature extraction to count static assets, page fetches, probing
    attempts, uncommon methods, and feed polls. Plain token lists; the regex/set
    machinery that uses them lives in :mod:`agent_census.features`.
    """

    static_extensions: tuple[str, ...] = ()
    page_extensions: tuple[str, ...] = ()
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
    """Return the flat array from ``<name>.toml`` (keyed by ``name``)."""
    data = _load(name)
    _check_top_level(f"{name}.toml", data, {name})
    value = data.get(name, [])
    if not _type_ok(value, "str[]"):
        raise ConfigError(f"{name}.toml: '{name}' must be a list of strings")
    return tuple(value)


# Crawler/bot categories: one TOML file each, an [[agent]] table per agent.
KNOWN_AGENT_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
    "data_harvester",
)


def _require_agent(entry: dict[str, Any]) -> str:
    primary = bool(entry.get("asn_primary"))
    if primary and not entry.get("asns"):
        return "'asn_primary' needs an 'asns' list (the AS is the identity)"
    # Plain `asns` is verification for a UA-named agent, so it needs a ua_substring;
    # only an asn_primary agent may stand on its AS alone.
    if not entry.get("ua_substring") and not primary:
        return "an agent needs a 'ua_substring' (or 'asn_primary' with 'asns')"
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
            ranges_url=entry.get("ranges_url"),
            fmt=entry.get("format", "prefixes"),
            asns=tuple(entry.get("asns", [])),
            rdns_fallback=bool(entry.get("rdns_fallback", False)),
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
            url, asns = entry.get("ranges_url"), entry.get("asns")
            if url and asns and entry.get("asn_primary"):
                feeds.append((int(asns[0]), url, entry.get("format", "prefixes")))
    return tuple(feeds)


@lru_cache(maxsize=None)
def load_range_sources(name: str) -> tuple[RangeSource, ...]:
    """Return the ``[[source]]`` range stanzas from ``<name>.toml``."""
    data = _load(name)
    _check_top_level(f"{name}.toml", data, {"source"})
    entries = _validate_records(
        f"{name}.toml", "source", data.get("source", []), _SOURCE_SCHEMA, _bad_format
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
    """Return the ``[[network]]`` stanzas from ``egress_networks.toml``."""
    data = _load("egress_networks")
    _check_top_level("egress_networks.toml", data, {"network"})
    entries = _validate_records(
        "egress_networks.toml", "network", data.get("network", []), _NETWORK_SCHEMA, _bad_format
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
    """Return the grouped UA-string token lists from ``ua_signatures.toml``."""
    groups = _grouped_lists("ua_signatures.toml", _load("ua_signatures"), _UA_SIGNATURE_SCHEMA)
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
    "static_assets": {"extensions"},
    "pages": {"extensions"},
    "path_traversal": {"markers"},
    "encoding_evasion": {"markers"},
    "methods": {"uncommon"},
    "feed_urls": {"filename_tokens", "filenames"},
}


@lru_cache(maxsize=None)
def load_request_signatures() -> RequestSignatures:
    """Return the grouped request-line token lists from ``request_signatures.toml``."""
    groups = _grouped_lists(
        "request_signatures.toml", _load("request_signatures"), _REQUEST_SIGNATURE_SCHEMA
    )
    return RequestSignatures(
        static_extensions=groups[("static_assets", "extensions")],
        page_extensions=groups[("pages", "extensions")],
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
    "browser_no_coload_max": "browser_shape.no_coload_max",
    "browser_follow_min": "browser_shape.follow_ratio_min",
    "browser_no_follow_max": "browser_shape.no_follow_max",
    "cadence_metronomic_max": "cadence.metronomic_max",
    "cadence_bursty_min": "cadence.bursty_min",
    "head_notable_ratio": "head_traffic.notable_ratio",
    "fabricated_self_referer_min": "fabricated_referer.self_referer_min",
    "fabricated_min_requests": "fabricated_referer.min_requests",
    "storm_404_ratio_min": "storm_404.ratio_min",
    "storm_404_distinct_paths_min": "storm_404.distinct_paths_min",
}


@lru_cache(maxsize=None)
def load_shared_tuning() -> Mapping[str, float]:
    """Return the cross-classifier numeric thresholds from ``tuning/shared.toml``."""
    return load_tuning("shared", _SHARED_TUNING)
