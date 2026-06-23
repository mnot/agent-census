"""Opt-in reverse/forward DNS verification of declared crawlers.

A client can trivially claim to be Googlebot in its User-Agent. The real check is
DNS: reverse-resolve the IP, confirm the hostname ends in an expected domain, then
forward-resolve that hostname and confirm it points back to the same IP.

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

import socket
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from . import uas
from .dataload import load_tokens
from .model import BotVerification, ClientId, VerificationStatus

_MAX_WORKERS = 32
_DNS_TIMEOUT = 5.0  # seconds per individual lookup

_T = TypeVar("_T")


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


def _known_crawler(ua: str | None) -> tuple[str, tuple[str, ...]] | None:
    pairs = (
        load_tokens("search_engines.txt")
        + load_tokens("social_preview.txt")
        + load_tokens("ai_crawlers.txt")
    )
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

    def needs(self, ua: str | None) -> bool:
        """True if the UA declares a crawler we have a domain to verify against."""
        known = _known_crawler(ua)
        return known is not None and bool(known[1])

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

    def verify(self, ip: str, ua: str | None) -> BotVerification:
        """Verify whether ``ip`` genuinely belongs to the crawler ``ua`` declares."""
        known = _known_crawler(ua)
        if known is None:
            return BotVerification(VerificationStatus.NOT_APPLICABLE)
        token, domains = known
        if not domains:
            return BotVerification(
                VerificationStatus.UNVERIFIED,
                expected_domains=domains,
                evidence=(f"no verifying domain known for {token}",),
            )
        host = self._cached_reverse(ip)
        if host is None:
            return BotVerification(
                VerificationStatus.UNVERIFIED,
                expected_domains=domains,
                evidence=(f"reverse DNS lookup of {ip} failed",),
            )
        if not _domain_matches(host, domains):
            return BotVerification(
                VerificationStatus.IMPERSONATOR,
                resolved_host=host,
                expected_domains=domains,
                evidence=(f"{ip} resolves to {host}, not a {token} domain ({', '.join(domains)})",),
            )
        forward = self._cached_forward(host)
        if ip in forward:
            return BotVerification(
                VerificationStatus.VERIFIED,
                resolved_host=host,
                expected_domains=domains,
                evidence=(f"{ip} ↔ {host} confirmed for {token}",),
            )
        if forward:
            status, why = VerificationStatus.IMPERSONATOR, f"{host} does not resolve back to {ip}"
        else:
            status, why = VerificationStatus.UNVERIFIED, f"forward DNS of {host} failed"
        return BotVerification(
            status, resolved_host=host, expected_domains=domains, evidence=(why,)
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
