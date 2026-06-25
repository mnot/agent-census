"""Load the bundled reference data (one TOML file per category in ``data/``).

Flat lists (``vuln_paths`` / ``scanner_ua`` / ``feed_readers``) hold an array
under a key matching the file name. Declared-crawler files (``search_engine`` …)
hold an ``[[agent]]`` array of tables, each with a ``ua_substring`` and optional
``domains`` / ``ranges`` / ``ranges_url``. Everything is cached per run.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from importlib.resources import files
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

    name: str = ""
    tag: str = ""
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


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, Any]:
    text = (files("agent_census.data") / f"{name}.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


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
    if not (entry.get("ua_substring") or entry.get("asns")):
        return "an agent needs a 'ua_substring' or 'asns'"
    return ""


@lru_cache(maxsize=None)
def _agents(category: str) -> tuple[dict[str, Any], ...]:
    """The validated ``[[agent]]`` tables of ``<category>.toml`` (raw dicts)."""
    data = _load(category)
    _check_top_level(f"{category}.toml", data, {"agent"})
    entries = _validate_records(
        f"{category}.toml", "agent", data.get("agent", []), _AGENT_SCHEMA, _require_agent
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
            rdns_fallback=bool(entry.get("rdns_fallback", False)),
        )
        pairs.append((ua, spec))
    return tuple(pairs)


@lru_cache(maxsize=None)
def load_asn_agents(category: str) -> tuple[tuple[int, str], ...]:
    """Return ``(asn, label)`` for agents in ``<category>.toml`` recognised by ASN.

    An agent recognised by origin AS number carries an ``asns`` list and a
    ``name`` (its display label) instead of a ``ua_substring``.
    """
    out: list[tuple[int, str]] = []
    for entry in _agents(category):
        label = entry.get("name") or entry.get("ua_substring") or category
        for asn in entry.get("asns", []):
            out.append((int(asn), label))
    return tuple(out)


@lru_cache(maxsize=None)
def load_asn_range_feeds() -> tuple[tuple[int, str, str], ...]:
    """``(asn, ranges_url, format)`` for ASN agents that publish a prefix feed.

    Lets an ASN-recognised crawler be matched by IP when the log doesn't carry the
    client's AS number: its AS's announced prefixes are fetched and the IP checked
    against them. Keyed by the agent's first ``asns`` entry (all map to one label).
    """
    feeds: list[tuple[int, str, str]] = []
    for category in KNOWN_AGENT_CATEGORIES:
        for entry in _agents(category):
            url, asns = entry.get("ranges_url"), entry.get("asns")
            if url and asns:
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
