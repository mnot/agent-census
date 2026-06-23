"""Tests for DNS bot verification (with the network mocked out)."""

from __future__ import annotations

import time

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


def test_verified_bot_ips_merge_into_one_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    from agent_census import identity, pipeline
    from agent_census.model import Kind
    from agent_census.parsing import resolve
    from agent_census.parsing.apache import PRESETS

    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "crawl.googlebot.com")
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {f"66.249.66.{i}" for i in range(5)})

    lines = [
        f'66.249.66.{i} - - [10/Oct/2023:13:0{i}:00 -0700] "GET /p{i} HTTP/1.1" 200 100 "-" '
        '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"'
        for i in range(4)
    ]
    tmp = Path("/tmp/agent_census_merge.log")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        parser = resolve("apache", {"format": PRESETS["combined"]})
        result = pipeline.analyze(
            tmp, parser, identity.get_strategy("ip_ua"), verifier=BotVerifier()
        )
    finally:
        tmp.unlink()

    bots = [p for p in result.profiles if p.classification.primary is Kind.SEARCH_ENGINE]
    assert len(bots) == 1  # four IPs collapsed into one entry
    bot = bots[0]
    assert bot.client_id.ip == "googlebot.com"  # keyed by verified domain, not an IP
    assert bot.features.request_count == 4  # requests summed across the IPs
    assert len(bot.member_ips) == 4


def test_reverse_dns_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netverify, "_DNS_TIMEOUT", 0.1)
    monkeypatch.setattr(netverify.socket, "gethostbyaddr", lambda ip: time.sleep(5))
    start = time.time()
    assert netverify._reverse_dns("1.2.3.4") is None
    assert time.time() - start < 1.0  # bounded by the timeout, not the 5s sleep
