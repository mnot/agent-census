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


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, Any]:
    text = (files("agent_census.data") / f"{name}.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


@lru_cache(maxsize=None)
def load_list(name: str) -> tuple[str, ...]:
    """Return the flat array from ``<name>.toml`` (keyed by ``name``)."""
    return tuple(_load(name).get(name, []))


@lru_cache(maxsize=None)
def load_tokens(category: str) -> tuple[tuple[str, CrawlerSpec], ...]:
    """Return ``(ua_substring, spec)`` pairs from ``<category>.toml``."""
    pairs: list[tuple[str, CrawlerSpec]] = []
    for entry in _load(category).get("agent", []):
        spec = CrawlerSpec(
            domains=tuple(entry.get("domains", [])),
            ranges=tuple(entry.get("ranges", [])),
            ranges_url=entry.get("ranges_url"),
        )
        pairs.append((entry["ua_substring"], spec))
    return tuple(pairs)
