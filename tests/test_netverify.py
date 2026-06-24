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


def test_needs_covers_every_known_category() -> None:
    # AhrefsBot is an seo_marketing agent with domains + ranges_url. The verifier
    # must consider every known category, not a hand-picked subset -- otherwise a
    # verifiable crawler can never be verified or flagged as an impersonator.
    verifier = BotVerifier()
    assert verifier.needs("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)")


# --- DNS path (domains, no ranges_url) ---


def test_verified_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("crawl-1.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1"})
    assert BotVerifier().verify("66.249.66.1", "DnsBot/1.0").status is VerificationStatus.VERIFIED


def test_impersonator_on_domain_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("host.evil.example", False))
    assert BotVerifier().verify("203.0.113.9", "DnsBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_missing_ptr_is_impersonator(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, True))  # definitive no-PTR
    assert BotVerifier().verify("203.0.113.9", "DnsBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_transient_reverse_failure_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, False))  # timeout / SERVFAIL
    assert BotVerifier().verify("203.0.113.9", "DnsBot/1.0").status is VerificationStatus.UNVERIFIED


def test_verify_all_dedupes_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    calls: list[str] = []

    def fake_reverse(ip: str) -> tuple[str | None, bool]:
        calls.append(ip)
        return "crawl.example.com", False

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


def test_dns_lookups_persist_across_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    # A second verifier (a later run) loads the on-disk cache and re-resolves nothing.
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    calls: list[str] = []

    def fake_reverse(ip: str) -> tuple[str | None, bool]:
        calls.append(ip)
        return "crawl.example.com", False

    monkeypatch.setattr(netverify, "_reverse_dns", fake_reverse)
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1"})
    items = [(ClientId(ip="66.249.66.1", user_agent="DnsBot"), "DnsBot")]

    first = BotVerifier().verify_all(items)
    assert first[items[0][0]].status is VerificationStatus.VERIFIED
    assert calls == ["66.249.66.1"]  # resolved once, then written to disk

    second = BotVerifier().verify_all(items)  # fresh instance reads the cache
    assert second[items[0][0]].status is VerificationStatus.VERIFIED
    assert calls == ["66.249.66.1"]  # no new lookup


def test_transient_dns_failure_negative_cached_within_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    # A timeout (None, False) is negative-cached, so a run within the TTL reuses it.
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    calls: list[str] = []

    def failing_reverse(ip: str) -> tuple[str | None, bool]:
        calls.append(ip)
        return None, False  # transient failure / timeout

    monkeypatch.setattr(netverify, "_reverse_dns", failing_reverse)
    items = [(ClientId(ip="66.249.66.1", user_agent="DnsBot"), "DnsBot")]

    assert BotVerifier().verify_all(items)[items[0][0]].status is VerificationStatus.UNVERIFIED
    assert calls == ["66.249.66.1"]  # probed once, then written as a negative
    assert BotVerifier().verify_all(items)[items[0][0]].status is VerificationStatus.UNVERIFIED
    assert calls == ["66.249.66.1"]  # served from the negative cache, not re-probed


def test_stale_negative_dns_is_reprobed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A negative older than _DNS_NEG_TTL is dropped on load, so the IP is re-probed.
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    stale = time.time() - netverify._DNS_NEG_TTL - 1
    netverify._dns_cache_path().write_text(
        f'{{"reverse": {{"66.249.66.1": [null, false, {stale}]}}, "forward": {{}}}}',
        encoding="utf-8",
    )
    calls: list[str] = []

    def good_reverse(ip: str) -> tuple[str | None, bool]:
        calls.append(ip)
        return "crawl.example.com", False

    monkeypatch.setattr(netverify, "_reverse_dns", good_reverse)
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"66.249.66.1"})
    items = [(ClientId(ip="66.249.66.1", user_agent="DnsBot"), "DnsBot")]

    assert BotVerifier().verify_all(items)[items[0][0]].status is VerificationStatus.VERIFIED
    assert calls == ["66.249.66.1"]  # stale negative ignored, freshly resolved


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


def test_out_of_range_is_impostor_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    # A definite out-of-range IP fails the range check, which short-circuits to
    # impersonator before reverse DNS is ever consulted.
    _patch_spec(monkeypatch, "RangeBot", CrawlerSpec(domains=("example.com",), ranges=("10.0.0.0/24",)))

    def fail(_arg: str) -> None:
        raise AssertionError("DNS must not be consulted once the range check fails")

    monkeypatch.setattr(netverify, "_reverse_dns", fail)
    assert BotVerifier().verify("203.0.113.9", "RangeBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_internet_archive_verified_by_published_range(monkeypatch: pytest.MonkeyPatch) -> None:
    # archive.org_bot declares both a published range feed and an archive.org rDNS
    # domain, so by default both must check out. In-feed + matching rDNS verifies;
    # the same UA elsewhere fails the range check and impersonates.
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "207.241.224.0/20"}]}'
    )
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("crawl.archive.org", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"207.241.224.5"})
    verifier = BotVerifier()
    ua = "Mozilla/5.0 (compatible; archive.org_bot; +http://archive.org/details/archive.org_bot)"
    assert verifier.needs(ua)
    assert verifier.verify("207.241.224.5", ua).status is VerificationStatus.VERIFIED
    assert verifier.verify("8.8.8.8", ua).status is VerificationStatus.IMPERSONATOR


def test_ranges_url_fetched_and_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_url="https://example.test/r.json"))
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}'
    )
    verifier = BotVerifier()
    assert verifier.verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("198.51.100.1", "FetchBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_out_of_fetched_range_is_impostor_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    # Out-of-range against a fetched feed fails first, before reverse DNS.
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_url="https://example.test/r.json"),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}')

    def fail(_arg: str) -> None:
        raise AssertionError("DNS must not run once the range check fails")

    monkeypatch.setattr(netverify, "_reverse_dns", fail)
    assert BotVerifier().verify("198.51.100.1", "BothBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_ranges_url_fetch_failure_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_url="https://example.test/r.json"))
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: None)
    assert BotVerifier().verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.UNVERIFIED


# --- combined ranges + rDNS: both required by default; rdns_fallback relaxes ---

_BOTH = {"domains": ("example.com",), "ranges": ("160.79.104.0/21",)}


def test_strict_requires_both_range_and_rdns(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"160.79.104.5"})
    assert BotVerifier().verify("160.79.104.5", "BothBot/1.0").status is VerificationStatus.VERIFIED


def test_strict_in_range_but_wrong_rdns_is_impostor(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.evil.example", False))
    assert BotVerifier().verify("160.79.104.5", "BothBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_strict_in_range_transient_rdns_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, False))  # transient
    assert BotVerifier().verify("160.79.104.5", "BothBot/1.0").status is VerificationStatus.UNVERIFIED


def test_rdns_fallback_in_range_skips_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH, rdns_fallback=True))

    def fail(_arg: str) -> None:
        raise AssertionError("DNS must not run when the range already verifies")

    monkeypatch.setattr(netverify, "_reverse_dns", fail)
    assert BotVerifier().verify("160.79.104.5", "BothBot/1.0").status is VerificationStatus.VERIFIED


def test_rdns_fallback_uses_dns_when_ranges_unobtainable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_url="https://x/r.json", rdns_fallback=True),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: "")  # ranges unavailable
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"203.0.113.5"})
    assert BotVerifier().verify("203.0.113.5", "BothBot/1.0").status is VerificationStatus.VERIFIED


def test_rdns_fallback_impostor_when_dns_also_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_url="https://x/r.json", rdns_fallback=True),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url: "")
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, True))  # definitive no PTR
    assert BotVerifier().verify("203.0.113.5", "BothBot/1.0").status is VerificationStatus.IMPERSONATOR


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
    assert netverify._reverse_dns("1.2.3.4") == (None, False)  # timeout -> transient
    assert time.time() - start < 1.0  # bounded by the timeout, not the 5s sleep
