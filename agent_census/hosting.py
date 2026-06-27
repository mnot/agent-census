"""Heuristic: does an IP belong to a datacenter / cloud hosting range?

A browser User-Agent arriving from hosting infrastructure (rather than an ISP or
mobile network) is the signature of spoofed-browser automation. Ranges come from
``data/networks/datacenter_ranges.toml``: inline CIDRs are always used; each source's
``ranges_url`` is fetched and merged when range fetching is enabled (on by
default, cached weekly; ``--no-fetch-ranges`` stays offline on the inline list).
A miss means "not known to be hosted", not "residential" -- the inline list is a
small starter set.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from .dataload import load_asn_range_feeds, load_range_sources
from .iprange import Interval, RangeIndex, fetch_range_intervals, network_intervals, remote_enabled

_DATA = "datacenter_ranges"


@lru_cache(maxsize=None)
def _provider_indexes() -> tuple[tuple[str, RangeIndex], ...]:
    """One ``(provider_name, RangeIndex)`` per source, so a hit can be attributed.

    Keeping the providers separate (rather than one merged index) is what lets
    :func:`datacenter_provider` name the owner; it costs no extra intervals, just
    a handful of small indexes instead of one big one.
    """
    built: list[tuple[str, RangeIndex]] = []
    for source in load_range_sources(_DATA):
        inline4, inline6 = network_intervals(source.ranges)
        v4: list[Interval] = list(inline4)
        v6: list[Interval] = list(inline6)
        if remote_enabled() and source.ranges_url:
            fetched4, fetched6 = fetch_range_intervals(
                source.ranges_url, source.fmt, source.name or "hosting"
            )
            v4 += fetched4
            v6 += fetched6
        if v4 or v6:
            built.append((source.name or "hosting", RangeIndex(v4, v6)))
    return tuple(built)


@lru_cache(maxsize=None)
def datacenter_provider(ip: str) -> str | None:
    """Name of the hosting provider whose ranges contain ``ip``, or None.

    First match wins if two feeds overlap. Unparseable IPs are None.
    """
    for name, index in _provider_indexes():
        if index.contains(ip):
            return name
    return None


@lru_cache(maxsize=None)
def _asn_providers() -> dict[int, str]:
    """Map each provider AS number (from the ``asns`` annotations) to its name.

    Static config, independent of ``--fetch-ranges``: it needs no network and
    matches against the AS number a log may already carry (``%{MM_ASN}e``).
    """
    mapping: dict[int, str] = {}
    for source in load_range_sources(_DATA):
        for asn in source.asns:
            mapping.setdefault(asn, source.name or "hosting")
    return mapping


def datacenter_provider_for_asn(asn: int | None) -> str | None:
    """Provider name for a logged AS number declared a datacenter, or None."""
    if asn is None:
        return None
    return _asn_providers().get(asn)


@lru_cache(maxsize=None)
def _asn_feed_indexes() -> tuple[tuple[int, RangeIndex], ...]:
    """One ``(asn, RangeIndex)`` per ASN agent that publishes a prefix feed.

    Only built when range fetching is on (``--fetch-ranges``); empty otherwise.
    """
    if not remote_enabled():
        return ()
    built: list[tuple[int, RangeIndex]] = []
    for asn, url, fmt in load_asn_range_feeds():
        v4, v6 = fetch_range_intervals(url, fmt, f"AS{asn}")
        if v4 or v6:
            built.append((asn, RangeIndex(v4, v6)))
    return tuple(built)


@lru_cache(maxsize=None)
def asn_for_ip(ip: str) -> int | None:
    """AS number of a configured crawler feed whose announced ranges contain ``ip``.

    Recovers the origin AS when the log doesn't carry it. Needs ``--fetch-ranges``;
    returns None offline or when no feed matches.
    """
    for asn, index in _asn_feed_indexes():
        if index.contains(ip):
            return asn
    return None


@lru_cache(maxsize=None)
def is_datacenter_ip(ip: str) -> bool:
    """True if ``ip`` falls in a known hosting range. Unparseable IPs are False."""
    return datacenter_provider(ip) is not None


@lru_cache(maxsize=None)
def subnet_of(ip: str) -> str | None:
    """The /24 (v4) or /48 (v6) containing ``ip``, or None if unparseable.

    The unit for lumping near-identical addresses (an adjacent fleet) into one
    entry instead of scattering them across rotating IPs.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return format(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


@lru_cache(maxsize=None)
def datacenter_subnet(ip: str) -> str | None:
    """The /24 or /48 of a datacenter IP, or None if it isn't in a hosting range."""
    return subnet_of(ip) if is_datacenter_ip(ip) else None
