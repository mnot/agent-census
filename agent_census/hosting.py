"""Heuristic: does an IP belong to a datacenter / cloud hosting range?

A browser User-Agent arriving from hosting infrastructure (rather than an ISP or
mobile network) is the signature of spoofed-browser automation. Ranges come from
``data/datacenter_ranges.toml``: inline CIDRs are always used (offline); each
source's ``ranges_url`` is fetched and merged only when range fetching is enabled
(:func:`agent_census.iprange.enable_remote`, wired to ``--fetch-ranges``), so a
default run stays offline. A miss means "not known to be hosted", not
"residential" -- the inline list is a small starter set.
"""

from __future__ import annotations

from functools import lru_cache

from .dataload import load_range_sources
from .iprange import (
    Network,
    extract_cidrs,
    fetch_ranges_text,
    ip_in,
    parse_networks,
    remote_enabled,
)

_DATA = "datacenter_ranges"


@lru_cache(maxsize=None)
def _networks() -> tuple[Network, ...]:
    nets: list[Network] = []
    for source in load_range_sources(_DATA):
        nets.extend(parse_networks(source.ranges))
        if remote_enabled() and source.ranges_url:
            text = fetch_ranges_text(source.ranges_url)
            if text:
                nets.extend(parse_networks(extract_cidrs(text, source.fmt)))
    return tuple(nets)


@lru_cache(maxsize=None)
def is_datacenter_ip(ip: str) -> bool:
    """True if ``ip`` falls in a known hosting range. Unparseable IPs are False."""
    return ip_in(ip, _networks()) is not None
