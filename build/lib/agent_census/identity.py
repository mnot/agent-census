"""Grouping log lines into clients.

Identity is the single biggest source of mis-analysis: NAT merges many people
behind one IP, mobile networks and cloud scanners rotate IPs, and User-Agents
are rotated to evade. No strategy is right for every deployment, so the strategy
is pluggable and the default (``ip_ua``) is a pragmatic middle ground. The report
notes how the chosen strategy fragmented or merged so a human can judge it.
"""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod

from .errors import ConfigError
from .model import ClientId, LogEntry


def _subnet_of(ip: str) -> str:
    """Return the /24 (IPv4) or /64 (IPv6) prefix for ``ip``, or ``ip`` itself."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _client_ip(entry: LogEntry, *, trust_forwarded: bool) -> str:
    """The IP to attribute the request to, honoring XFF only when trusted."""
    if trust_forwarded and entry.forwarded_for:
        return entry.forwarded_for[0]
    return entry.remote_host


class ClientKeyStrategy(ABC):
    """Maps a :class:`LogEntry` to the :class:`ClientId` it belongs to."""

    name: str = ""

    @abstractmethod
    def key(self, entry: LogEntry) -> ClientId:
        """Return the identity key for ``entry``."""


class IpStrategy(ClientKeyStrategy):
    """Group by IP only. Coarsest; merges distinct users behind one address."""

    name = "ip"

    def key(self, entry: LogEntry) -> ClientId:
        return ClientId(ip=entry.remote_host)


class IpUaStrategy(ClientKeyStrategy):
    """Group by (IP, User-Agent). The default; separates co-located clients."""

    name = "ip_ua"

    def key(self, entry: LogEntry) -> ClientId:
        return ClientId(ip=entry.remote_host, user_agent=entry.user_agent)


class IpUaSubnetStrategy(ClientKeyStrategy):
    """Group by (subnet, User-Agent) to re-merge IP-rotating bots in one range."""

    name = "ip_ua_subnet"

    def key(self, entry: LogEntry) -> ClientId:
        # Group by the subnet: the subnet is the identity, so it is also the key's
        # ``ip`` (otherwise two hosts in one /24 would not group together).
        subnet = _subnet_of(entry.remote_host)
        return ClientId(ip=subnet, user_agent=entry.user_agent, subnet=subnet)


class ForwardedStrategy(ClientKeyStrategy):
    """Group by the left-most X-Forwarded-For IP and UA (for sites behind a proxy).

    Choosing this strategy is itself the opt-in to trusting XFF, which is
    spoofable; fall back to the connecting IP when no XFF was logged.
    """

    name = "forwarded"

    def key(self, entry: LogEntry) -> ClientId:
        ip = _client_ip(entry, trust_forwarded=True)
        return ClientId(ip=ip, user_agent=entry.user_agent)


_STRATEGIES: dict[str, type[ClientKeyStrategy]] = {
    cls.name: cls for cls in (IpStrategy, IpUaStrategy, IpUaSubnetStrategy, ForwardedStrategy)
}


def available() -> list[str]:
    """Return the registered identity-strategy names."""
    return list(_STRATEGIES)


def get_strategy(name: str) -> ClientKeyStrategy:
    """Instantiate the named identity strategy, or raise :class:`ConfigError`."""
    try:
        return _STRATEGIES[name]()
    except KeyError:
        known = ", ".join(available())
        raise ConfigError(f"unknown identity strategy {name!r}; choose from: {known}") from None
