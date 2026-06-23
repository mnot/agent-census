"""Opt-in reverse/forward DNS verification of declared crawlers.

A client can trivially claim to be Googlebot in its User-Agent. Two ways to check:

* A ``ranges_url`` (or inline ``ranges``) is **authoritative** when present: the
  IP is verified iff it falls in the published CIDRs, and an out-of-range IP
  claiming the crawler is an impersonator -- no DNS involved.
* Otherwise, DNS: reverse-resolve the IP, confirm the hostname ends in an
  expected domain, and forward-resolve it back. A client claiming a DNS-verified
  crawler but having no PTR record at all is treated as an impersonator.

DNS is the slow part, so verification is done as a deduped, concurrent batch:
each distinct IP is resolved once, and the lookups run across a thread pool (they
are I/O-bound, so this is a near-linear speedup over doing them one at a time).
Each lookup is bounded by a timeout -- the stdlib resolver calls cannot be
cancelled and ignore ``socket.setdefaulttimeout``, so each runs in a daemon
thread that is abandoned (treated as "unverified") if it overruns, which also
keeps a dead resolver from stalling the run or delaying exit. Enabled only with
``--verify-bots``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.request
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TypeVar

from . import uas
from .dataload import CrawlerSpec, load_tokens
from .model import BotVerification, ClientId, VerificationStatus

_MAX_WORKERS = 32
_DNS_TIMEOUT = 5.0  # seconds per individual lookup
_RANGES_TTL = 7 * 24 * 60 * 60  # refresh fetched IP-range files weekly
_FETCH_TIMEOUT = 10

_T = TypeVar("_T")
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_networks(cidrs: tuple[str, ...]) -> tuple[_Network, ...]:
    nets: list[_Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _ip_in(ip: str, networks: tuple[_Network, ...]) -> _Network | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((net for net in networks if addr in net), None)


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


def _fetch_ranges_text(url: str) -> str | None:
    """Return the ranges JSON for ``url``, backed by a weekly on-disk cache."""
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


def _parse_prefixes(text: str) -> tuple[str, ...]:
    """Extract CIDRs from the Google/OpenAI ``{"prefixes": [...]}`` schema."""
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


def _bounded(func: Callable[[], _T]) -> _T | None:
    """Run ``func`` in a daemon thread, returning None if it errors or times out."""
    box: list[_T | None] = []

    def runner() -> None:
        try:
            box.append(func())
        except (OSError, socket.herror, socket.gaierror):
            box.append(None)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(_DNS_TIMEOUT)
    if thread.is_alive() or not box:
        return None
    return box[0]


def _known_crawler(ua: str | None) -> tuple[str, CrawlerSpec] | None:
    pairs = load_tokens("search_engine") + load_tokens("social_preview") + load_tokens("ai_crawler")
    return uas.match_known(ua, pairs)


def _reverse_dns(ip: str) -> str | None:
    return _bounded(lambda: socket.gethostbyaddr(ip)[0])


def _forward_ips(host: str) -> set[str]:
    result = _bounded(lambda: {str(info[4][0]) for info in socket.getaddrinfo(host, None)})
    return result if result is not None else set()


def _domain_matches(host: str, domains: tuple[str, ...]) -> bool:
    low = host.lower().rstrip(".")
    return any(low == d or low.endswith("." + d) for d in domains)


class BotVerifier:
    """Verifies declared crawlers via DNS, caching and parallelising the lookups."""

    def __init__(self, max_workers: int = _MAX_WORKERS) -> None:
        self._max_workers = max_workers
        self._lock = threading.Lock()
        self._reverse: dict[str, str | None] = {}
        self._forward: dict[str, frozenset[str]] = {}
        self._ranges: dict[str, tuple[_Network, ...]] = {}

    def needs(self, ua: str | None) -> bool:
        """True if the UA declares a crawler we have something to verify against."""
        known = _known_crawler(ua)
        if known is None:
            return False
        spec = known[1]
        return bool(spec.domains or spec.ranges or spec.ranges_url)

    def _networks_for(self, spec: CrawlerSpec) -> tuple[_Network, ...]:
        """Inline CIDR ranges plus any fetched (and cached) from ``ranges_url``."""
        networks = list(_parse_networks(spec.ranges))
        if spec.ranges_url:
            with self._lock:
                cached = self._ranges.get(spec.ranges_url)
            if cached is None:
                text = _fetch_ranges_text(spec.ranges_url)
                cached = _parse_networks(_parse_prefixes(text)) if text else ()
                with self._lock:
                    self._ranges[spec.ranges_url] = cached
            networks.extend(cached)
        return tuple(networks)

    def _cached_reverse(self, ip: str) -> str | None:
        with self._lock:
            if ip in self._reverse:
                return self._reverse[ip]
        host = _reverse_dns(ip)  # slow; resolved outside the lock
        with self._lock:
            self._reverse[ip] = host
        return host

    def _cached_forward(self, host: str) -> frozenset[str]:
        with self._lock:
            if host in self._forward:
                return self._forward[host]
        ips = frozenset(_forward_ips(host))
        with self._lock:
            self._forward[host] = ips
        return ips

    def verify(  # pylint: disable=too-many-return-statements
        self, ip: str, ua: str | None
    ) -> BotVerification:
        """Verify whether ``ip`` genuinely belongs to the crawler ``ua`` declares."""
        known = _known_crawler(ua)
        if known is None:
            return BotVerification(VerificationStatus.NOT_APPLICABLE)
        substring, spec = known
        if not (spec.domains or spec.ranges or spec.ranges_url):
            return BotVerification(
                VerificationStatus.UNVERIFIED,
                evidence=(f"no verifying domain or IP range known for {substring}",),
            )

        networks = self._networks_for(spec)

        # A ranges_url is authoritative: the published list is the whole truth,
        # so an IP outside it is an impersonator (no DNS fallback). If we could
        # not obtain the list, we cannot judge -- unverified rather than guess.
        if spec.ranges_url:
            if not networks:
                return BotVerification(
                    VerificationStatus.UNVERIFIED,
                    expected_domains=spec.domains,
                    evidence=(f"could not fetch the published {substring} IP ranges",),
                )
            match = _ip_in(ip, networks)
            if match is not None:
                return BotVerification(
                    VerificationStatus.VERIFIED,
                    resolved_host=str(match),
                    expected_domains=spec.domains,
                    evidence=(f"{ip} is within {match}, a published {substring} range",),
                )
            return BotVerification(
                VerificationStatus.IMPERSONATOR,
                expected_domains=spec.domains,
                evidence=(f"{ip} is not in any published {substring} range (authoritative)",),
            )

        # Inline ranges without a ranges_url are a positive signal but not
        # exhaustive, so a miss falls back to DNS when domains are configured.
        if networks:
            match = _ip_in(ip, networks)
            if match is not None:
                return BotVerification(
                    VerificationStatus.VERIFIED,
                    resolved_host=str(match),
                    expected_domains=spec.domains,
                    evidence=(f"{ip} is within {match}, a published {substring} range",),
                )
            if not spec.domains:
                return BotVerification(
                    VerificationStatus.IMPERSONATOR,
                    expected_domains=spec.domains,
                    evidence=(f"{ip} is not in any published {substring} range",),
                )

        # Reverse/forward DNS. A crawler verified this way is expected to have a
        # PTR record, so its absence under this UA is treated as impersonation.
        host = self._cached_reverse(ip)
        if host is None:
            return BotVerification(
                VerificationStatus.IMPERSONATOR,
                expected_domains=spec.domains,
                evidence=(f"{ip} has no reverse-DNS record but its UA claims {substring}",),
            )
        if not _domain_matches(host, spec.domains):
            return BotVerification(
                VerificationStatus.IMPERSONATOR,
                resolved_host=host,
                expected_domains=spec.domains,
                evidence=(
                    f"{ip} resolves to {host}, not a {substring} domain "
                    f"({', '.join(spec.domains)})",
                ),
            )
        forward = self._cached_forward(host)
        if ip in forward:
            return BotVerification(
                VerificationStatus.VERIFIED,
                resolved_host=host,
                expected_domains=spec.domains,
                evidence=(f"{ip} ↔ {host} confirmed for {substring}",),
            )
        if forward:
            status, why = VerificationStatus.IMPERSONATOR, f"{host} does not resolve back to {ip}"
        else:
            status, why = VerificationStatus.UNVERIFIED, f"forward DNS of {host} failed"
        return BotVerification(
            status, resolved_host=host, expected_domains=spec.domains, evidence=(why,)
        )

    def verify_all(
        self, items: Sequence[tuple[ClientId, str | None]]
    ) -> dict[ClientId, BotVerification]:
        """Verify many clients at once, deduping by (IP, UA) and running in parallel."""
        work: dict[tuple[str, str | None], list[ClientId]] = {}
        for client_id, ua in items:
            work.setdefault((client_id.ip, ua), []).append(client_id)
        if not work:
            return {}
        results: dict[ClientId, BotVerification] = {}
        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(work))) as pool:
            futures = {pool.submit(self.verify, ip, ua): (ip, ua) for ip, ua in work}
            for future in futures:
                ip, ua = futures[future]
                verification = future.result()
                for client_id in work[(ip, ua)]:
                    results[client_id] = verification
        return results
