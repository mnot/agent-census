"""Fetching, caching, and parsing of published IP-range lists.

Shared by crawler verification (:mod:`agent_census.netverify`) and datacenter
detection (:mod:`agent_census.hosting`). A fetched list is cached on disk for a
week so repeated runs stay offline; a failed refresh falls back to the stale
copy. Providers publish ranges in several shapes, so :func:`extract_cidrs`
dispatches on a declared format.
"""

from __future__ import annotations

import bisect
import hashlib
import ipaddress
import json
import os
import time
import urllib.request
from collections.abc import Iterable
from pathlib import Path

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Interval = tuple[int, int]  # (first address, last address) as ints, one IP version
Intervals = tuple[list[Interval], list[Interval]]  # (v4, v6)


class RangeIndex:
    """Fast membership over many CIDRs: O(log n) per query instead of a scan.

    Ranges are stored as integer intervals (split by IP version), sorted by start
    with a running max-end alongside. A query bisects for the last range starting
    at or before the address, then checks whether any range up to there reaches
    it (via the prefix max-end) -- correct even when ranges overlap, with no need
    to merge them. Built once per provider set; the difference between
    milliseconds and microseconds per IP on large logs.
    """

    __slots__ = ("_starts4", "_maxend4", "_starts6", "_maxend6")

    def __init__(self, v4: list[Interval], v6: list[Interval]) -> None:
        self._starts4, self._maxend4 = self._build(v4)
        self._starts6, self._maxend6 = self._build(v6)

    @classmethod
    def from_networks(cls, networks: Iterable[Network]) -> RangeIndex:
        """Build directly from network objects (splitting by IP version)."""
        v4: list[Interval] = []
        v6: list[Interval] = []
        for net in networks:
            (v4 if net.version == 4 else v6).append(
                (int(net.network_address), int(net.broadcast_address))
            )
        return cls(v4, v6)

    @staticmethod
    def _build(intervals: list[Interval]) -> tuple[list[int], list[int]]:
        pairs = sorted(intervals)
        starts = [start for start, _ in pairs]
        maxend: list[int] = []
        running = -1
        for _, end in pairs:
            running = max(running, end)
            maxend.append(running)
        return starts, maxend

    def contains(self, ip: str) -> bool:
        """True if ``ip`` falls in any indexed range. Unparseable IPs are False."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version == 4:
            starts, maxend = self._starts4, self._maxend4
        else:
            starts, maxend = self._starts6, self._maxend6
        value = int(addr)
        idx = bisect.bisect_right(starts, value) - 1
        return idx >= 0 and maxend[idx] >= value


_RANGES_TTL = 7 * 24 * 60 * 60  # refresh fetched range files weekly
_FETCH_TIMEOUT = 10
_INTERVALS_CACHE_VERSION = 1  # bump to invalidate cached parses when a parser changes


def network_intervals(cidrs: tuple[str, ...]) -> Intervals:
    """Parse CIDR strings into (v4, v6) integer intervals, dropping malformed ones."""
    v4: list[Interval] = []
    v6: list[Interval] = []
    for net in parse_networks(cidrs):
        (v4 if net.version == 4 else v6).append(
            (int(net.network_address), int(net.broadcast_address))
        )
    return v4, v6


# Whether fetching providers' published ``ranges_url`` lists is allowed this run
# (controlled by --fetch-ranges / --no-fetch-ranges; on by default). Shared by
# every range-backed feature so one flag governs all network access. Held in a
# dict to stay mutable without `global`.
_remote = {"enabled": False}


def enable_remote() -> None:
    """Allow fetching published range lists over the network this run (cached weekly)."""
    _remote["enabled"] = True


def remote_enabled() -> bool:
    """True if range lists may be fetched this run."""
    return _remote["enabled"]


def parse_networks(cidrs: tuple[str, ...]) -> tuple[Network, ...]:
    """Turn CIDR strings into network objects, silently dropping malformed ones."""
    nets: list[Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def ip_in(ip: str, networks: tuple[Network, ...]) -> Network | None:
    """The first network containing ``ip``, or None (also None for a bad IP)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((net for net in networks if addr.version == net.version and addr in net), None)


def _ranges_cache_path(url: str) -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    directory = Path(base) / "agent-census" / "ranges"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / (hashlib.sha1(url.encode("utf-8")).hexdigest() + ".json")


def _http_get(url: str) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": "agent-census"})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as response:  # noqa: S310
            return str(response.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def fetch_ranges_text(url: str) -> str | None:
    """Return the range list for ``url``, backed by a weekly on-disk cache."""
    path = _ranges_cache_path(url)
    try:
        fresh = path.exists() and (time.time() - path.stat().st_mtime) < _RANGES_TTL
    except OSError:
        fresh = False
    if fresh:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            pass
    text = _http_get(url)
    if text is not None:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError:
            pass
        return text
    try:  # fetch failed -- fall back to a stale cached copy if we have one
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def parse_prefixes(text: str) -> tuple[str, ...]:
    """Google / GCP / OpenAI schema: ``{"prefixes": [{"ipv4Prefix"|"ipv6Prefix"}]}``."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ()
    prefixes = data.get("prefixes", []) if isinstance(data, dict) else []
    out: list[str] = []
    for prefix in prefixes:
        if isinstance(prefix, dict):
            cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            if cidr:
                out.append(cidr)
    return tuple(out)


def parse_aws(text: str) -> tuple[str, ...]:
    """AWS schema: ``prefixes[].ip_prefix`` and ``ipv6_prefixes[].ipv6_prefix``."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ()
    if not isinstance(data, dict):
        return ()
    out: list[str] = []
    for prefix in data.get("prefixes", []):
        if isinstance(prefix, dict) and prefix.get("ip_prefix"):
            out.append(prefix["ip_prefix"])
    for prefix in data.get("ipv6_prefixes", []):
        if isinstance(prefix, dict) and prefix.get("ipv6_prefix"):
            out.append(prefix["ipv6_prefix"])
    return tuple(out)


def parse_azure(text: str) -> tuple[str, ...]:
    """Azure service-tags schema: ``values[].properties.addressPrefixes[]``."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ()
    values = data.get("values", []) if isinstance(data, dict) else []
    out: list[str] = []
    for value in values:
        props = value.get("properties", {}) if isinstance(value, dict) else {}
        for cidr in props.get("addressPrefixes", []) if isinstance(props, dict) else []:
            if isinstance(cidr, str):
                out.append(cidr)
    return tuple(out)


def parse_text(text: str) -> tuple[str, ...]:
    """One CIDR per line; blank lines and ``#`` comments ignored."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return tuple(out)


def parse_csv(text: str) -> tuple[str, ...]:
    """First column of each row is the CIDR (e.g. DigitalOcean / Linode geofeeds)."""
    out: list[str] = []
    for raw in text.splitlines():
        cell = raw.split(",", 1)[0].strip()
        if "/" in cell:  # skip header / comment rows without a prefix
            out.append(cell)
    return tuple(out)


def parse_subnets(text: str) -> tuple[str, ...]:
    """Vultr geofeed JSON schema: ``{"subnets": [{"ip_prefix": "..."}]}``."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ()
    subnets = data.get("subnets", []) if isinstance(data, dict) else []
    out: list[str] = []
    for subnet in subnets:
        if isinstance(subnet, dict) and subnet.get("ip_prefix"):
            out.append(subnet["ip_prefix"])
    return tuple(out)


def parse_oracle(text: str) -> tuple[str, ...]:
    """Oracle Cloud schema: ``{"regions": [{"cidrs": [{"cidr": "..."}]}]}``."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return ()
    regions = data.get("regions", []) if isinstance(data, dict) else []
    out: list[str] = []
    for region in regions:
        cidrs = region.get("cidrs", []) if isinstance(region, dict) else []
        for entry in cidrs:
            if isinstance(entry, dict) and entry.get("cidr"):
                out.append(entry["cidr"])
    return tuple(out)


_PARSERS = {
    "prefixes": parse_prefixes,
    "aws": parse_aws,
    "azure": parse_azure,
    "text": parse_text,
    "csv": parse_csv,
    "subnets": parse_subnets,
    "oracle": parse_oracle,
}


def extract_cidrs(text: str, fmt: str) -> tuple[str, ...]:
    """Extract CIDR strings from ``text`` according to the named ``fmt``."""
    parser = _PARSERS.get(fmt, parse_prefixes)
    return parser(text)


def _intervals_cache_path(url: str, fmt: str) -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    directory = Path(base) / "agent-census" / "ranges"
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha1(f"{url}|{fmt}|v{_INTERVALS_CACHE_VERSION}".encode("utf-8")).hexdigest()
    return directory / (digest + ".intervals.json")


def _read_intervals(path: Path) -> Intervals | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ([tuple(pair) for pair in data["v4"]], [tuple(pair) for pair in data["v6"]])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def fetch_range_intervals(url: str, fmt: str) -> Intervals:
    """(v4, v6) intervals for ``url``'s published list, caching the *parsed* result.

    The parsed integer intervals are cached weekly so repeat runs skip refetching
    and re-parsing tens of thousands of CIDRs into objects. On a cold/stale cache
    the raw text is fetched (itself weekly-cached), parsed, and the intervals are
    written back; if even that fails, a stale interval cache is used if present.
    """
    path = _intervals_cache_path(url, fmt)
    try:
        fresh = path.exists() and (time.time() - path.stat().st_mtime) < _RANGES_TTL
    except OSError:
        fresh = False
    if fresh:
        cached = _read_intervals(path)
        if cached is not None:
            return cached
    text = fetch_ranges_text(url)
    if text is not None:
        v4, v6 = network_intervals(extract_cidrs(text, fmt))
        try:
            path.write_text(json.dumps({"v4": v4, "v6": v6}), encoding="utf-8")
        except OSError:
            pass
        return v4, v6
    stale = _read_intervals(path)  # fetch failed -- fall back to a stale parse if we have one
    return stale if stale is not None else ([], [])
