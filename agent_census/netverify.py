"""Opt-in reverse/forward DNS verification of declared crawlers.

A client can trivially claim to be Googlebot in its User-Agent. The real check is
DNS: reverse-resolve the IP, confirm the hostname ends in an expected domain, then
forward-resolve that hostname and confirm it points back to the same IP. Enabled
only with ``--verify-bots`` because it makes network calls; without it,
impersonation is still inferred from behavior (see :mod:`agent_census.classify.tags`).
"""

from __future__ import annotations

import socket

from . import uas
from .dataload import load_tokens
from .model import BotVerification, ClientFeatures, ClientId, VerificationStatus
from .pipeline import VerifyFn


def _known_crawler(ua: str | None) -> tuple[str, tuple[str, ...]] | None:
    pairs = load_tokens("good_bots.txt") + load_tokens("ai_crawlers.txt")
    return uas.match_known(ua, pairs)


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


def _forward_ips(host: str) -> set[str]:
    try:
        return {str(info[4][0]) for info in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def _domain_matches(host: str, domains: tuple[str, ...]) -> bool:
    low = host.lower().rstrip(".")
    return any(low == d or low.endswith("." + d) for d in domains)


def verify(ip: str, ua: str | None) -> BotVerification:
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

    host = _reverse_dns(ip)
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

    forward = _forward_ips(host)
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
    return BotVerification(status, resolved_host=host, expected_domains=domains, evidence=(why,))


def make_verify_fn() -> VerifyFn:
    """Build a pipeline verify callable with a per-IP/UA cache."""
    cache: dict[tuple[str, str | None], BotVerification | None] = {}

    def verify_fn(client_id: ClientId, features: ClientFeatures) -> BotVerification | None:
        if _known_crawler(features.user_agent) is None:
            return None
        key = (client_id.ip, features.user_agent)
        if key not in cache:
            cache[key] = verify(client_id.ip, features.user_agent)
        return cache[key]

    return verify_fn
