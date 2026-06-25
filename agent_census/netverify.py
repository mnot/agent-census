"""Opt-in reverse/forward DNS verification of declared crawlers.

A client can trivially claim to be Googlebot in its User-Agent. Two checks:

* IP ranges: a ``ranges_url`` (or inline ``ranges``) lists the crawler's CIDRs;
  the IP is verified iff it falls in them, and a definitely out-of-range IP is an
  impersonator.
* DNS: reverse-resolve the IP, confirm the hostname ends in an expected domain,
  and forward-resolve it back; a definite wrong or absent PTR is an impersonator.

An agent that declares **both** must pass both by default -- either definitive
failure is impersonation -- unless its spec sets ``rdns_fallback``, which makes
the ranges primary and falls back to DNS only when they can't be obtained.
Inconclusive checks (unfetchable ranges, a DNS timeout) leave the verdict
unverified, never impersonator.

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

import ipaddress
import json
import socket
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import NamedTuple, TypeVar

from . import uas
from .dataload import KNOWN_AGENT_CATEGORIES, CrawlerSpec, load_tokens
from .iprange import Network as _Network
from .iprange import cache_dir
from .iprange import fetch_ranges_text as _fetch_ranges_text
from .iprange import ip_in as _ip_in
from .iprange import parse_networks as _parse_networks
from .iprange import parse_prefixes as _parse_prefixes
from .model import BotVerification, ClientId, VerificationStatus

# Outcome of one verification check (range or reverse DNS): a definitive pass or
# fail, or an inconclusive result (unfetchable ranges, a DNS timeout) that must
# never be read as impersonation.
_PASS, _FAIL, _UNKNOWN = "pass", "fail", "unknown"


class _Check(NamedTuple):
    state: str  # _PASS | _FAIL | _UNKNOWN
    host: str | None  # resolved host or matched range, for the report
    why: str  # human-readable evidence line


_MAX_WORKERS = 64
_DNS_TIMEOUT = 3.0  # seconds per individual lookup
_DNS_CACHE_TTL = 24 * 60 * 60  # re-resolve a resolved/authoritative answer at most daily
_DNS_NEG_TTL = 60 * 60  # but re-probe a non-answer (timeout / empty) after an hour


def _dns_cache_path() -> Path:
    return cache_dir() / "dns.json"


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
    # match -- and lets tests inject synthetic specs via load_tokens. Drawn from
    # the canonical category list so a new category (e.g. seo_marketing, whose
    # AhrefsBot publishes ranges and rDNS) is verifiable without editing here.
    pairs = tuple(pair for category in KNOWN_AGENT_CATEGORIES for pair in load_tokens(category))
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


def _norm_ip(ip: str) -> str:
    """Canonical text form of an IP, so non-canonical IPv6 spellings (e.g.
    ``2001:0db8:0:0:0:0:0:1`` vs ``2001:db8::1``) compare equal. Returns the
    input unchanged if it isn't a parseable address."""
    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return ip


def _forward_ips(host: str) -> set[str]:
    result = _bounded(
        lambda: {_norm_ip(str(info[4][0])) for info in socket.getaddrinfo(host, None)}
    )
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
        # When each entry was resolved, so the on-disk cache can expire per-entry.
        self._reverse_ts: dict[str, float] = {}
        self._forward_ts: dict[str, float] = {}
        self._load_dns_cache()

    def _load_dns_cache(self) -> None:
        """Seed the in-memory DNS caches from disk, dropping entries past their TTL.

        Answers (a resolved host, a definitive no-record, a non-empty forward set)
        live for ``_DNS_CACHE_TTL``; non-answers -- a timed-out / transient lookup
        cached so a dead IP isn't re-probed every run -- expire after the shorter
        ``_DNS_NEG_TTL``.
        """
        try:
            data = json.loads(_dns_cache_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        now = time.time()
        for ip, entry in data.get("reverse", {}).items():
            if not (isinstance(entry, list) and len(entry) == 3):
                continue
            host, no_ptr = entry[0], bool(entry[1])
            ttl = _DNS_CACHE_TTL if host is not None or no_ptr else _DNS_NEG_TTL
            if now - entry[2] < ttl:
                self._reverse[ip] = (host, no_ptr)
                self._reverse_ts[ip] = entry[2]
        for host, entry in data.get("forward", {}).items():
            if not (isinstance(entry, list) and len(entry) == 2):
                continue
            ttl = _DNS_CACHE_TTL if entry[0] else _DNS_NEG_TTL
            if now - entry[1] < ttl:
                self._forward[host] = frozenset(entry[0])
                self._forward_ts[host] = entry[1]

    def _save_dns_cache(self) -> None:
        """Persist DNS results so the next run skips re-resolving them.

        Both answers and non-answers are written; :meth:`_load_dns_cache` ages
        non-answers out sooner (``_DNS_NEG_TTL``) so a transient failure is a
        short-lived negative cache entry, not a permanent verdict.
        """
        now = time.time()
        reverse = {
            ip: [host, no_ptr, self._reverse_ts.get(ip, now)]
            for ip, (host, no_ptr) in self._reverse.items()
        }
        forward = {
            host: [sorted(ips), self._forward_ts.get(host, now)]
            for host, ips in self._forward.items()
        }
        try:
            _dns_cache_path().write_text(
                json.dumps({"reverse": reverse, "forward": forward}), encoding="utf-8"
            )
        except OSError:
            pass

    def needs(self, ua: str | None) -> bool:
        """True if the UA declares a crawler we have something to verify against."""
        known = _known_crawler(ua)
        if known is None:
            return False
        spec = known[1]
        return bool(spec.domains or spec.ranges or spec.ranges_url)

    def _networks_for(self, spec: CrawlerSpec, name: str | None = None) -> tuple[_Network, ...]:
        """Inline CIDR ranges plus any fetched (and cached) from ``ranges_url``."""
        networks = list(_parse_networks(spec.ranges))
        if spec.ranges_url:
            with self._lock:
                cached = self._ranges.get(spec.ranges_url)
            if cached is None:
                text = _fetch_ranges_text(spec.ranges_url, name)
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
            self._reverse_ts[ip] = time.time()
        return result

    def _cached_forward(self, host: str) -> frozenset[str]:
        with self._lock:
            if host in self._forward:
                return self._forward[host]
        ips = frozenset(_forward_ips(host))
        with self._lock:
            self._forward[host] = ips
            self._forward_ts[host] = time.time()
        return ips

    def _check_range(self, ip: str, spec: CrawlerSpec, substring: str) -> _Check:
        """Tri-state IP-range check. Unobtainable ranges are inconclusive, not a fail."""
        networks = self._networks_for(spec, substring)
        if not networks:
            return _Check(_UNKNOWN, None, f"could not obtain the published {substring} IP ranges")
        match = _ip_in(ip, networks)
        if match is not None:
            return _Check(
                _PASS, str(match), f"{ip} is within {match}, a published {substring} range"
            )
        return _Check(_FAIL, None, f"{ip} is not in any published {substring} range")

    def _check_rdns(self, ip: str, spec: CrawlerSpec, substring: str) -> _Check:
        """Tri-state reverse/forward DNS check. Transient lookup failures are inconclusive."""
        host, no_ptr = self._cached_reverse(ip)
        if host is None:
            if no_ptr:
                return _Check(
                    _FAIL, None, f"{ip} has no reverse-DNS record but its UA claims {substring}"
                )
            return _Check(_UNKNOWN, None, f"reverse DNS lookup of {ip} failed (transient)")
        if not _domain_matches(host, spec.domains):
            return _Check(
                _FAIL,
                host,
                f"{ip} resolves to {host}, not a {substring} domain ({', '.join(spec.domains)})",
            )
        if _norm_ip(ip) in self._cached_forward(host):
            return _Check(_PASS, host, f"{ip} ↔ {host} confirmed for {substring}")
        if self._cached_forward(host):
            return _Check(_FAIL, host, f"{host} does not resolve back to {ip}")
        return _Check(_UNKNOWN, host, f"forward DNS of {host} failed")

    def verify(self, ip: str, ua: str | None) -> BotVerification:
        """Verify whether ``ip`` genuinely belongs to the crawler ``ua`` declares.

        An agent declaring both IP ranges and reverse-DNS domains must pass *both*
        by default -- either failing is impersonation. Set ``rdns_fallback`` on a
        spec to make ranges primary, with the domains used only as a fallback when
        the ranges can't be obtained. Definitive failures (out-of-range, wrong/no
        PTR) impersonate; merely inconclusive checks (unfetchable ranges, a DNS
        timeout) leave it unverified.
        """
        known = _known_crawler(ua)
        if known is None:
            return BotVerification(VerificationStatus.NOT_APPLICABLE)
        substring, spec = known
        has_ranges = bool(spec.ranges or spec.ranges_url)
        has_domains = bool(spec.domains)
        if not (has_ranges or has_domains):
            return BotVerification(
                VerificationStatus.UNVERIFIED,
                evidence=(f"no verifying domain or IP range known for {substring}",),
            )

        if has_ranges and has_domains and not spec.rdns_fallback:
            return self._verify_strict(ip, spec, substring)
        if has_ranges and has_domains:  # rdns_fallback: ranges first, DNS only if unobtainable
            check = self._check_range(ip, spec, substring)
            if check.state is _UNKNOWN:
                check = self._check_rdns(ip, spec, substring)
        elif has_ranges:
            check = self._check_range(ip, spec, substring)
        else:
            check = self._check_rdns(ip, spec, substring)
        return self._verdict(check, spec)

    def _verify_strict(self, ip: str, spec: CrawlerSpec, substring: str) -> BotVerification:
        """Both range and reverse DNS must pass; either definitive failure impersonates."""
        rng = self._check_range(ip, spec, substring)
        if rng.state is _FAIL:
            return self._verdict(rng, spec)
        dns = self._check_rdns(ip, spec, substring)
        if dns.state is _FAIL:
            return self._verdict(dns, spec)
        if rng.state is _PASS and dns.state is _PASS:
            return BotVerification(
                VerificationStatus.VERIFIED,
                resolved_host=dns.host or rng.host,
                expected_domains=spec.domains,
                evidence=(rng.why, dns.why),
            )
        return BotVerification(  # nothing failed, but a check was inconclusive
            VerificationStatus.UNVERIFIED,
            resolved_host=dns.host,
            expected_domains=spec.domains,
            evidence=(rng.why, dns.why),
        )

    def _verdict(self, check: _Check, spec: CrawlerSpec) -> BotVerification:
        status = {
            _PASS: VerificationStatus.VERIFIED,
            _FAIL: VerificationStatus.IMPERSONATOR,
            _UNKNOWN: VerificationStatus.UNVERIFIED,
        }[check.state]
        return BotVerification(
            status, resolved_host=check.host, expected_domains=spec.domains, evidence=(check.why,)
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
        self._save_dns_cache()  # persist this run's resolutions for the next one
        return results
