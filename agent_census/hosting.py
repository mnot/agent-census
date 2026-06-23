"""Heuristic: does an IP belong to a datacenter / cloud hosting range?

A browser User-Agent arriving from hosting infrastructure (rather than an ISP or
mobile network) is the signature of spoofed-browser automation. Ranges come from
``data/datacenter_ranges.toml``: inline CIDRs are always used; each source's
``ranges_url`` is fetched and merged when range fetching is enabled (on by
default, cached weekly; ``--no-fetch-ranges`` stays offline on the inline list).
A miss means "not known to be hosted", not "residential" -- the inline list is a
small starter set.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from .dataload import load_range_sources
from .iprange import Interval, RangeIndex, fetch_range_intervals, network_intervals, remote_enabled

_DATA = "datacenter_ranges"


@lru_cache(maxsize=None)
def _index() -> RangeIndex:
    v4: list[Interval] = []
    v6: list[Interval] = []
    for source in load_range_sources(_DATA):
        inline4, inline6 = network_intervals(source.ranges)
        v4 += inline4
        v6 += inline6
        if remote_enabled() and source.ranges_url:
            fetched4, fetched6 = fetch_range_intervals(source.ranges_url, source.fmt)
            v4 += fetched4
            v6 += fetched6
    return RangeIndex(v4, v6)


@lru_cache(maxsize=None)
def is_datacenter_ip(ip: str) -> bool:
    """True if ``ip`` falls in a known hosting range. Unparseable IPs are False."""
    return _index().contains(ip)


@lru_cache(maxsize=None)
def datacenter_subnet(ip: str) -> str | None:
    """The /24 (v4) or /48 (v6) of a datacenter IP, or None if it isn't one.

    Used to lump an adjacent VM fleet -- same subnet, same client -- into one
    entry rather than scattering it across near-identical addresses.
    """
    if not is_datacenter_ip(ip):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return format(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
