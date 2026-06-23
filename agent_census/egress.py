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
from .iprange import (
    Network,
    extract_cidrs,
    fetch_ranges_text,
    ip_in,
    parse_networks,
    remote_enabled,
)


@lru_cache(maxsize=None)
def _networks() -> tuple[tuple[EgressNetwork, tuple[Network, ...]], ...]:
    built: list[tuple[EgressNetwork, tuple[Network, ...]]] = []
    for network in load_egress_networks():
        nets = list(parse_networks(network.ranges))
        if remote_enabled() and network.ranges_url:
            text = fetch_ranges_text(network.ranges_url)
            if text:
                nets.extend(parse_networks(extract_cidrs(text, network.fmt)))
        if nets:
            built.append((network, tuple(nets)))
    return tuple(built)


@lru_cache(maxsize=None)
def lookup(ip: str) -> EgressNetwork | None:
    """Return the egress network whose ranges contain ``ip``, or None."""
    for network, nets in _networks():
        if ip_in(ip, nets) is not None:
            return network
    return None
