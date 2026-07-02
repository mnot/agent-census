"""Tests for DNS / IP-range bot verification (with the network mocked out)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_census import identity, netverify, pipeline
from agent_census.dataload import CrawlerSpec
from agent_census.model import ChannelVerdict, ClientId, Kind, VerificationStatus
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


def test_network_checked_flag_tracks_whether_a_check_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    # A network-derived verdict records that a check actually ran (the `unverified` tag
    # depends on this to tell a failed/inconclusive check from nothing to check against).
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("host.evil.example", False))
    failed = BotVerifier().verify("203.0.113.9", "DnsBot/1.0")
    assert failed.status is VerificationStatus.IMPERSONATOR and failed.network_checked

    # An agent with no rdns/range info is UNVERIFIED but no check ran.
    _patch_spec(monkeypatch, "BareBot", CrawlerSpec())
    bare = BotVerifier().verify("203.0.113.9", "BareBot/1.0")
    assert bare.status is VerificationStatus.UNVERIFIED and not bare.network_checked


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


def test_subnet_key_is_unverified_not_impersonator(monkeypatch: pytest.MonkeyPatch) -> None:
    # Under the ip_ua_subnet strategy the identity key's ``ip`` is a CIDR, not a
    # single address. A range/rDNS check can't run on it, so the verdict must be
    # inconclusive -- never IMPERSONATOR for a genuine crawler keyed by subnet.
    _patch_spec(monkeypatch, "RangeBot", CrawlerSpec(ranges=("160.79.104.0/21",)))
    result = BotVerifier().verify("160.79.104.0/24", "RangeBot/1.0")
    assert result.status is VerificationStatus.UNVERIFIED


def test_out_of_range_is_impostor_even_when_dns_confirms(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both channels are always checked when both are declared (not short-circuited),
    # so the independent `ip`/`dns` channel verdicts stay accurate -- here the ip
    # channel violates even though dns confirms, and the merged verdict is still
    # impersonator (either channel failing is enough).
    _patch_spec(monkeypatch, "RangeBot", CrawlerSpec(domains=("example.com",), ranges=("10.0.0.0/24",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("host.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"203.0.113.9"})
    verification = BotVerifier().verify("203.0.113.9", "RangeBot/1.0")
    assert verification.status is VerificationStatus.IMPERSONATOR
    assert verification.ip is ChannelVerdict.VIOLATION
    assert verification.dns is ChannelVerdict.VERIFIED


def test_internet_archive_verified_by_published_range(monkeypatch: pytest.MonkeyPatch) -> None:
    # archive.org_bot declares both a published range feed and an archive.org rDNS
    # domain, so by default both must check out. In-feed + matching rDNS verifies;
    # the same UA elsewhere fails the range check and impersonates.
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url, name=None: '{"prefixes": [{"ipv4Prefix": "207.241.224.0/20"}]}'
    )
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("crawl.archive.org", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"207.241.224.5"})
    verifier = BotVerifier()
    ua = "Mozilla/5.0 (compatible; archive.org_bot; +http://archive.org/details/archive.org_bot)"
    assert verifier.needs(ua)
    # (archive.org_bot's real spec declares only `domains`, no ranges -- so this
    # exercises the dns-only channel; `ip` stays not_checked either way.)
    verified = verifier.verify("207.241.224.5", ua)
    assert verified.status is VerificationStatus.VERIFIED
    assert verified.dns is ChannelVerdict.VERIFIED
    assert verified.ip is ChannelVerdict.NOT_CHECKED
    impersonator = verifier.verify("8.8.8.8", ua)
    assert impersonator.status is VerificationStatus.IMPERSONATOR
    assert impersonator.dns is ChannelVerdict.VIOLATION
    assert impersonator.ip is ChannelVerdict.NOT_CHECKED


def test_ranges_url_fetched_and_used(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_urls=("https://example.test/r.json",)))
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url, name=None: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}'
    )
    verifier = BotVerifier()
    assert verifier.verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("198.51.100.1", "FetchBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_out_of_fetched_range_is_impostor_even_when_dns_confirms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Same as the inline-ranges case, with a fetched (not inline) range feed: both
    # channels still run, ip violates and dns confirms, merged verdict stays
    # impersonator.
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_urls=("https://example.test/r.json",)),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url, name=None: '{"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}')
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("host.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"198.51.100.1"})
    verification = BotVerifier().verify("198.51.100.1", "BothBot/1.0")
    assert verification.status is VerificationStatus.IMPERSONATOR
    assert verification.ip is ChannelVerdict.VIOLATION
    assert verification.dns is ChannelVerdict.VERIFIED


def test_ranges_url_fetch_failure_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "FetchBot", CrawlerSpec(ranges_urls=("https://example.test/r.json",)))
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url, name=None: None)
    assert BotVerifier().verify("192.0.2.7", "FetchBot/1.0").status is VerificationStatus.UNVERIFIED


def test_ranges_url_honours_declared_format(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-"prefixes" feed (here a plain text CIDR list) must be parsed with the
    # agent's declared format, not blindly as JSON -- otherwise a real client is
    # left UNVERIFIED and an impersonator is never caught.
    _patch_spec(
        monkeypatch,
        "TextBot",
        CrawlerSpec(ranges_urls=("https://example.test/ips.txt",), fmt="text"),
    )
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url, name=None: "192.0.2.0/24\n# comment\n"
    )
    verifier = BotVerifier()
    assert verifier.verify("192.0.2.7", "TextBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("198.51.100.1", "TextBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_multiple_ranges_url_feeds_are_merged(monkeypatch: pytest.MonkeyPatch) -> None:
    # An operator that splits its list across feeds (e.g. Pingdom's per-family IPv4
    # and IPv6 lists) must be covered by the union: an IP in *either* feed verifies,
    # and only an IP in neither is an impersonator -- otherwise a genuine probe from
    # the family not in the first feed would be wrongly flagged.
    feeds = {
        "https://example.test/ipv4.txt": "192.0.2.0/24\n",
        "https://example.test/ipv6.txt": "2001:db8::/32\n",
    }
    _patch_spec(
        monkeypatch,
        "MultiBot",
        CrawlerSpec(ranges_urls=tuple(feeds), fmt="text"),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url, name=None: feeds[url])
    verifier = BotVerifier()
    assert verifier.verify("192.0.2.7", "MultiBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("2001:db8::1", "MultiBot/1.0").status is VerificationStatus.VERIFIED
    assert verifier.verify("198.51.100.1", "MultiBot/1.0").status is VerificationStatus.IMPERSONATOR


def test_forward_dns_matches_noncanonical_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    # The log may carry a non-canonical IPv6 spelling while getaddrinfo returns the
    # canonical one; the forward-confirm must compare them as addresses, not strings,
    # so a legitimate IPv6 crawler isn't flagged IMPERSONATOR.
    _patch_spec(monkeypatch, "DnsBot", CrawlerSpec(domains=("example.com",)))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("crawl.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"2001:db8::1"})
    status = BotVerifier().verify("2001:0db8:0000:0000:0000:0000:0000:0001", "DnsBot/1.0").status
    assert status is VerificationStatus.VERIFIED


# --- combined ranges + rDNS: both required by default; rdns_fallback relaxes ---

_BOTH = {"domains": ("example.com",), "ranges": ("160.79.104.0/21",)}


def test_strict_requires_both_range_and_rdns(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"160.79.104.5"})
    verification = BotVerifier().verify("160.79.104.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.VERIFIED
    assert verification.ip is ChannelVerdict.VERIFIED
    assert verification.dns is ChannelVerdict.VERIFIED


def test_strict_in_range_but_wrong_rdns_is_impostor(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both channels are checked (not short-circuited): the range verifies while
    # DNS violates -- an independent per-channel disagreement, and either channel
    # failing is enough for the merged impersonator verdict.
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.evil.example", False))
    verification = BotVerifier().verify("160.79.104.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.IMPERSONATOR
    assert verification.ip is ChannelVerdict.VERIFIED
    assert verification.dns is ChannelVerdict.VIOLATION


def test_strict_in_range_transient_rdns_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH))
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, False))  # transient
    verification = BotVerifier().verify("160.79.104.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.UNVERIFIED
    assert verification.ip is ChannelVerdict.VERIFIED
    assert verification.dns is ChannelVerdict.UNVERIFIED


def test_rdns_fallback_in_range_skips_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(monkeypatch, "BothBot", CrawlerSpec(**_BOTH, rdns_fallback=True))

    def fail(_arg: str) -> None:
        raise AssertionError("DNS must not run when the range already verifies")

    monkeypatch.setattr(netverify, "_reverse_dns", fail)
    verification = BotVerifier().verify("160.79.104.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.VERIFIED
    assert verification.ip is ChannelVerdict.VERIFIED
    assert verification.dns is ChannelVerdict.NOT_CHECKED  # never ran -- ranges already decided


def test_rdns_fallback_uses_dns_when_ranges_unobtainable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_urls=("https://x/r.json",), rdns_fallback=True),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url, name=None: "")  # ranges unavailable
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("c.example.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {"203.0.113.5"})
    verification = BotVerifier().verify("203.0.113.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.VERIFIED
    assert verification.dns is ChannelVerdict.VERIFIED
    # The range check did run (and was inconclusive) before falling back to DNS --
    # that's carried on `ip` too, rather than silently dropped as not_checked.
    assert verification.ip is ChannelVerdict.UNVERIFIED


def test_rdns_fallback_impostor_when_dns_also_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_spec(
        monkeypatch,
        "BothBot",
        CrawlerSpec(domains=("example.com",), ranges_urls=("https://x/r.json",), rdns_fallback=True),
    )
    monkeypatch.setattr(netverify, "_fetch_ranges_text", lambda url, name=None: "")
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: (None, True))  # definitive no PTR
    verification = BotVerifier().verify("203.0.113.5", "BothBot/1.0")
    assert verification.status is VerificationStatus.IMPERSONATOR
    assert verification.dns is ChannelVerdict.VIOLATION
    assert verification.ip is ChannelVerdict.UNVERIFIED


def test_verified_bot_ips_merge_into_one_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    # Real Googlebot entry verifies by published range; its IPs collapse to one.
    # Googlebot declares both ranges and domains, so strict verification also runs
    # reverse/forward DNS -- stub it so the test never touches the live network.
    monkeypatch.setattr(
        netverify, "_fetch_ranges_text", lambda url, name=None: '{"prefixes": [{"ipv4Prefix": "66.249.66.0/24"}]}'
    )
    monkeypatch.setattr(netverify, "_reverse_dns", lambda ip: ("crawl.googlebot.com", False))
    monkeypatch.setattr(netverify, "_forward_ips", lambda host: {f"66.249.66.{i}" for i in range(4)})
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
