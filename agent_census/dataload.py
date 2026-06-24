"""Load the bundled reference data (one TOML file per category in ``data/``).

Flat lists (``vuln_paths`` / ``scanner_ua`` / ``feed_readers``) hold an array
under a key matching the file name. Declared-crawler files (``search_engine`` …)
hold an ``[[agent]]`` array of tables, each with a ``ua_substring`` and optional
``domains`` / ``ranges`` / ``ranges_url``. Everything is cached per run.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no stdlib tomllib.
    import tomli as tomllib


@dataclass(frozen=True, slots=True)
class CrawlerSpec:
    """How to verify a declared crawler: reverse-DNS domains and/or IP ranges."""

    domains: tuple[str, ...] = ()
    ranges: tuple[str, ...] = ()
    ranges_url: str | None = None
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


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, Any]:
    text = (files("agent_census.data") / f"{name}.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


@lru_cache(maxsize=None)
def load_list(name: str) -> tuple[str, ...]:
    """Return the flat array from ``<name>.toml`` (keyed by ``name``)."""
    return tuple(_load(name).get(name, []))


# Crawler/bot categories: one TOML file each, an [[agent]] table per agent.
KNOWN_AGENT_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
)


@lru_cache(maxsize=None)
def load_tokens(category: str) -> tuple[tuple[str, CrawlerSpec], ...]:
    """Return ``(ua_substring, spec)`` pairs from ``<category>.toml``.

    Agents recognised by AS number rather than a UA token (no ``ua_substring``)
    are skipped here; see :func:`load_asn_agents`.
    """
    pairs: list[tuple[str, CrawlerSpec]] = []
    for entry in _load(category).get("agent", []):
        ua = entry.get("ua_substring")
        if not ua:
            continue
        spec = CrawlerSpec(
            domains=tuple(entry.get("domains", [])),
            ranges=tuple(entry.get("ranges", [])),
            ranges_url=entry.get("ranges_url"),
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
    for entry in _load(category).get("agent", []):
        label = entry.get("name") or entry.get("ua_substring") or category
        for asn in entry.get("asns", []):
            out.append((int(asn), label))
    return tuple(out)


@lru_cache(maxsize=None)
def load_range_sources(name: str) -> tuple[RangeSource, ...]:
    """Return the ``[[source]]`` range stanzas from ``<name>.toml``."""
    sources: list[RangeSource] = []
    for entry in _load(name).get("source", []):
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
    networks: list[EgressNetwork] = []
    for entry in _load("egress_networks").get("network", []):
        networks.append(
            EgressNetwork(
                name=entry.get("name", ""),
                tag=entry.get("tag", ""),
                ranges=tuple(entry.get("ranges", [])),
                ranges_url=entry.get("ranges_url"),
                fmt=entry.get("format", "prefixes"),
            )
        )
    return tuple(networks)
