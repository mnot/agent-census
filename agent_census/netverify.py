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

import socket
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

from . import uas
from .dataload import CrawlerSpec, load_tokens
from .iprange import Network as _Network
from .iprange import fetch_ranges_text as _fetch_ranges_text
from .iprange import ip_in as _ip_in
from .iprange import parse_networks as _parse_networks
from .iprange import parse_prefixes as _parse_prefixes
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


def _known_crawler(ua: str | None) -> tuple[str, CrawlerSpec] | None:
    # Not a hot path (runs per deduped candidate under --verify-bots), so this
    # builds the combined token list rather than using the cached per-category
    # match -- and lets tests inject synthetic specs via load_tokens.
    pairs = (
        load_tokens("search_engine")
        + load_tokens("social_preview")
        + load_tokens("archiver")
        + load_tokens("ai_crawler")
    )
    return uas.match_known(ua, pairs)


# POSIX netdb.h h_errno values for socket.herror: a genuinely-absent record vs.
# a transient resolver failure (TRY_AGAIN / NO_RECOVERY).
_HOST_NOT_FOUND = 1
_NO_DATA = 4


def _reverse_lookup(ip: str) -> tuple[str | None, bool]:
    """Return (hostname, no_ptr): no_ptr is True only for a definitive no-record."""
    try:
        return socket.gethostbyaddr(ip)[0], False
    except socket.herror as exc:
        return None, bool(exc.args) and exc.args[0] in (_HOST_NOT_FOUND, _NO_DATA)
    except OSError:
        return None, False


def _reverse_dns(ip: str) -> tuple[str | None, bool]:
    """Reverse DNS bounded by a timeout; a timeout is transient, not a no-record."""
    result = _bounded(lambda: _reverse_lookup(ip))
    return result if result is not None else (None, False)


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
        self._reverse: dict[str, tuple[str | None, bool]] = {}
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

    def _cached_reverse(self, ip: str) -> tuple[str | None, bool]:
        with self._lock:
            if ip in self._reverse:
                return self._reverse[ip]
        result = _reverse_dns(ip)  # slow; resolved outside the lock
        with self._lock:
            self._reverse[ip] = result
        return result

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

        # Published ranges -- inline and/or fetched -- are authoritative: the IP
        # is verified iff it falls in them, and an out-of-range IP under this UA
        # is an impersonator (no DNS fallback). If a ranges_url could not be
        # fetched and there are no inline ranges, we cannot judge -- unverified.
        if spec.ranges or spec.ranges_url:
            if not networks:
                return BotVerification(
                    VerificationStatus.UNVERIFIED,
                    expected_domains=spec.domains,
                    evidence=(f"could not obtain the published {substring} IP ranges",),
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

        # Reverse/forward DNS. A crawler verified this way is expected to have a
        # PTR record, so its absence under this UA is treated as impersonation.
        host, no_ptr = self._cached_reverse(ip)
        if host is None:
            if no_ptr:
                return BotVerification(
                    VerificationStatus.IMPERSONATOR,
                    expected_domains=spec.domains,
                    evidence=(f"{ip} has no reverse-DNS record but its UA claims {substring}",),
                )
            return BotVerification(
                VerificationStatus.UNVERIFIED,
                expected_domains=spec.domains,
                evidence=(f"reverse DNS lookup of {ip} failed (transient)",),
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
