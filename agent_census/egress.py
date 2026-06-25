"""Membership test for named shared-egress networks (e.g. iCloud Private Relay).

A privacy relay or proxy fronts many real users behind a rotating address pool,
so its source IPs carry no identity. :func:`lookup` reports which network an IP
belongs to (if any) so the pipeline can collapse that network's traffic into one
entry per User-Agent and tag it. Ranges come from ``data/egress_networks.toml``;
a network's ``ranges_url`` is fetched when range fetching is enabled (on by
default, cached weekly; ``--no-fetch-ranges`` disables it).
"""

from __future__ import annotations

from functools import lru_cache

from .dataload import EgressNetwork, load_egress_networks
from .iprange import Interval, RangeIndex, fetch_range_intervals, network_intervals, remote_enabled


@lru_cache(maxsize=None)
def _networks() -> tuple[tuple[EgressNetwork, RangeIndex], ...]:
    built: list[tuple[EgressNetwork, RangeIndex]] = []
    for network in load_egress_networks():
        inline4, inline6 = network_intervals(network.ranges)
        v4: list[Interval] = list(inline4)
        v6: list[Interval] = list(inline6)
        if remote_enabled() and network.ranges_url:
            fetched4, fetched6 = fetch_range_intervals(
                network.ranges_url, network.fmt, network.name or "egress"
            )
            v4 += fetched4
            v6 += fetched6
        if v4 or v6:
            built.append((network, RangeIndex(v4, v6)))
    return tuple(built)


@lru_cache(maxsize=None)
def lookup(ip: str) -> EgressNetwork | None:
    """Return the egress network whose ranges contain ``ip``, or None."""
    for network, index in _networks():
        if index.contains(ip):
            return network
    return None


@lru_cache(maxsize=None)
def _asn_networks() -> dict[int, EgressNetwork]:
    """Map each configured egress AS number to its network (for VPNs/proxies that
    publish no range list -- the AS is the only stable handle on them)."""
    mapping: dict[int, EgressNetwork] = {}
    for network in load_egress_networks():
        for asn in network.asns:
            mapping.setdefault(asn, network)
    return mapping


def lookup_asn(asn: int | None) -> EgressNetwork | None:
    """Return the egress network configured for AS number ``asn``, or None."""
    return _asn_networks().get(asn) if asn is not None else None
