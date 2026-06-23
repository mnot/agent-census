"""Tests for DNS / IP-range bot verification (with the network mocked out)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_census import identity, netverify, pipeline
from agent_census.dataload import CrawlerSpec
from agent_census.model import ClientId, Kind, VerificationStatus
from agent_census.netverify import BotVerifier
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def _patch_spec(monkeypatch: pytest.MonkeyPatch, substring: str, spec: CrawlerSpec) -> None:
    """Make _known_crawler resolve a single synthetic (substring, spec)."""
    monkeypatch.setattr(netverify, "load_tokens", lambda _category: ((substring, spec),))


def test_needs_only_declared_crawlers() -> None:
    verifier = BotVerifier()
    assert verifier.needs(GOOGLEBOT)  # real Googlebot has domains + ranges_url
    assert not verifier.needs("Mozilla/5.0 (a normal browser)")
    assert not verifier.needs(None)


# --- DNS path (domains, no ranges_url) ---


def test_verified_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "crawl-1.example.com")
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1"})
    assert BotVerifier().verify("66.249.66.1", "DnsBot/1.0").status is VerificationStatus.VERIFIED


def test_impersonator_on_domain_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "host.evil.example")
    assert BotVerifier().verify("203.0.113.9", "DnsBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_missing_ptr_is_impersonator(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: None)
    assert BotVerifier().verify("203.0.113.9", "DnsBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_verify_all_dedupes_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    calls: list[str] = []

    def fake_reverse(ip: str) -> str:
        calls.append(ip)
        return "crawl.example.com"

    monkeypatch.setattr(netverify, "_reverse_dns", fake_reverse)
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1", "66.249.66.2"})
    items = [
        (ClientId(ip="66.249.66.1", user_agent="DnsBot"), "DnsBot"),
        (ClientId(ip="66.249.66.1", user_agent="DnsBot"), "DnsBot"),
        (ClientId(ip="66.249.66.2", user_agent="DnsBot"), "DnsBot"),
    ]
    results = BotVerifier().verify_all(items)
    assert len(results) == 2  # deduped by (ip, ua)
    assert sorted(calls) == ["66.249.66.1", "66.249.66.2"]
    assert all(r.status is VerificationStatus.VERIFIED for r in results.values())


def test_verify_all_empty() -> None:
    assert BotVerifier().verify_all([]) == {}


# --- IP-range path ---


def test_inline_range_verifies_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "RangeBot", CrawlerSpec(ranges=("160.79.104.0/21",)))

    def fail(_arg: str) -> None:
        raise AssertionError("DNS must not be called for a CIDR match")

    monkeypatch.setattr(netverify, "_reverse_dns", fail)
    result = BotVerifier().verify("160.79.104.5", "RangeBot/1.0")
    assert result.status is VerificationStatus.VERIFIED
    assert "160.79.104.0/21" in (result.resolved_host or "")


def test_ip_outside_only_range_is_impersonator(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "RangeBot", CrawlerSpec(ranges=("10.0.0.0/24",)))
    assert BotVerifier().verify("203.0.113.9", "RangeBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_ranges_url_fetched_and_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_url="https://example.test/r.json"))
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}'
    )
    verifier = BotVerifier()
    assert verifier.verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("198.51.100.1", "FetchBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_ranges_url_is_authoritative_over_domains(monkeypatch: pytest.MonkeyPatch) -> None:
    # Out-of-range is an impersonator even though rDNS would match a domain.
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_url="https://example.test/r.json"),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}')
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: "host.example.com")  # would pass DNS
    assert BotVerifier().verify("198.51.100.1", "BothBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_ranges_url_fetch_failure_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_url="https://example.test/r.json"))
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: None)
    assert BotVerifier().verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.UNVERIFIED


def test_verified_bot_ips_merge_into_one_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Real Googlebot entry verifies by published range; its IPs collapse to one.
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "66.249.66.0/24"}]}'
    )
    lines = [
        f'66.249.66.{i} - - [10/Oct/2023:13:0{i}:00 -0700] "GET /p{i} HTTP/1.1" 200 100 "-" '
        f'"{GOOGLEBOT}"'
        for i in range(4)
    ]
    tmp = Path("/tmp/agent_census_merge.log")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        parser = resolve("apache", {"format": PRESETS["combined"]})
        result = pipeline.analyze(tmp, parser, identity.get_strategy("ip_ua"), verifier=BotVerifier())
    finally:
        tmp.unlink()

    bots = [p for p in result.profiles if p.classification.primary is Kind.SEARCH_ENGINE]
    assert len(bots) == 1
    assert bots[0].client_id.ip == "googlebot.com"
    assert bots[0].features.request_count == 4
    assert len(bots[0].member_ips) == 4


def test_reverse_dns_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netverify, "_DNS_TIMEOUT", 0.1)
    monkeypatch.setattr(netverify.socket, "gethostbyaddr", lambda ip: time.sleep(5))
    start = time.time()
    assert netverify._reverse_dns("1.2.3.4") is None
    assert time.time() - start < 1.0  # bounded by the timeout, not the 5s sleep
