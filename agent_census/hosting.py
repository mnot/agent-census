"""Heuristic: does an IP belong to a datacenter / cloud hosting range?

A browser User-Agent arriving from hosting infrastructure (rather than an ISP or
mobile network) is the signature of spoofed-browser automation. The range list
in ``data/datacenter_ranges.toml`` is a hand-maintained starter set, not an
exhaustive registry -- a miss means "not known to be hosted", not "residential".
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from .dataload import load_list

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=None)
def _networks() -> tuple[_Network, ...]:
    nets: list[_Network] = []
    for cidr in load_list("datacenter_ranges"):
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue  # skip a malformed entry rather than abort the whole run
    return tuple(nets)


@lru_cache(maxsize=None)
def is_datacenter_ip(ip: str) -> bool:
    """True if ``ip`` falls in a known hosting range. Unparseable IPs are False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _networks() if net.version == addr.version)
