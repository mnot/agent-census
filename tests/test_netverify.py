"""Tests for DNS bot verification (with the network mocked out)."""

from __future__ import annotations

import pytest

from agent_census import netverify
from agent_census.model import ClientId, VerificationStatus
from agent_census.netverify import BotVerifier

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def test_needs_only_declared_crawlers() -> None:
    verifier = BotVerifier()
    assert verifier.needs(GOOGLEBOT)
    assert not verifier.needs("Mozilla/5.0 (a normal browser)")
    assert not verifier.needs(None)


def test_verified_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "crawl-66-1.googlebot.com")
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1"})
    result = BotVerifier().verify("66.249.66.1", GOOGLEBOT)
    assert result.status is VerificationStatus.VERIFIED


def test_impersonator_on_domain_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "host.evil.example")
    result = BotVerifier().verify("203.0.113.9", GOOGLEBOT)
    assert result.status is VerificationStatus.IMPERSONATOR


def test_unverified_on_reverse_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: None)
    result = BotVerifier().verify("203.0.113.9", GOOGLEBOT)
    assert result.status is VerificationStatus.UNVERIFIED


def test_verify_all_dedupes_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_reverse(ip: str) -> str:
        calls.append(ip)
        return "crawl.googlebot.com"

    monkeypatch.setattr(netverify, "_reverse_dns", fake_reverse)
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1", "66.249.66.2"})

    # Three clients, two share an IP -> reverse DNS should run once per IP.
    items = [
        (ClientId(ip="66.249.66.1", user_agent=GOOGLEBOT), GOOGLEBOT),
        (ClientId(ip="66.249.66.1", user_agent=GOOGLEBOT), GOOGLEBOT),
        (ClientId(ip="66.249.66.2", user_agent=GOOGLEBOT), GOOGLEBOT),
    ]
    results = BotVerifier().verify_all(items)
    assert len(results) == 2  # deduped by (ip, ua)
    assert sorted(calls) == ["66.249.66.1", "66.249.66.2"]
    assert all(r.status is VerificationStatus.VERIFIED for r in results.values())


def test_verify_all_empty() -> None:
    assert BotVerifier().verify_all([]) == {}
