"""Tests for individual classifiers and the combiner."""

from __future__ import annotations

from dataclasses import replace

from agent_census.classify import classify_client
from agent_census.classify.browser import BrowserClassifier
from agent_census.classify.combiner import combine
from agent_census.classify.feed_reader import FeedReaderClassifier
from agent_census.classify.vuln_scanner import VulnScannerClassifier
from agent_census.model import (
    BotVerification,
    ClientFeatures,
    ComplianceReport,
    Kind,
    RobotsVerdict,
    Signal,
    VerificationStatus,
)


def test_vuln_scanner_fires_on_probes() -> None:
    feats = ClientFeatures(
        request_count=10,
        ratio_404=0.9,
        distinct_404_paths=20,
        vuln_path_hits=8,
        sample_vuln_paths=("/.env", "/wp-login.php"),
        traversal_hits=1,
    )
    signals = VulnScannerClassifier().evaluate(feats)
    assert signals and signals[0].kind is Kind.VULN_SCANNER
    assert signals[0].confidence >= 0.45


def test_vuln_scanner_silent_on_clean_client() -> None:
    feats = ClientFeatures(request_count=10, ratio_2xx=1.0)
    assert VulnScannerClassifier().evaluate(feats) == []


def test_browser_fires_on_coloading() -> None:
    feats = ClientFeatures(
        request_count=10,
        asset_coload_ratio=0.8,
        ua_looks_like_browser=True,
        static_ratio=0.5,
        ratio_404=0.0,
    )
    signals = BrowserClassifier().evaluate(feats)
    assert signals and signals[0].kind is Kind.BROWSER
    assert signals[0].confidence >= 0.45


def test_self_referer_browser_is_demoted_and_tagged() -> None:
    # Chrome UA, but every request's Referer is the requested URL itself (fabricated
    # navigation). Not a real browser; the forged referers must not pass as
    # link-following, and the pattern is tagged.
    feats = ClientFeatures(
        request_count=30,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,  # self-referers are excluded from this
        self_referer_ratio=1.0,
    )
    result = classify_client(feats)
    assert result.primary is not Kind.BROWSER
    assert "forged-referer" in result.tags


def test_self_referer_on_non_browser_ua_is_not_tagged() -> None:
    # A non-browser UA self-referring isn't faking browser navigation -> no tag.
    feats = ClientFeatures(
        request_count=30,
        ua_looks_like_browser=False,
        self_referer_ratio=1.0,
        user_agent="python-requests/2.31.0",
    )
    assert "forged-referer" not in classify_client(feats).tags


def test_probing_browser_is_not_a_confident_browser() -> None:
    # Headless-browser automation co-loads assets like a real browser, but a
    # person never fetches attack paths -- probing must sink the browser verdict.
    feats = ClientFeatures(
        request_count=1000,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.5,
        traversal_hits=3,
        vuln_path_hits=5,
    )
    assert classify_client(feats).primary is not Kind.BROWSER
    # plain co-loading browser with no probing stays a browser
    clean = ClientFeatures(request_count=1000, ua_looks_like_browser=True, asset_coload_ratio=0.5)
    assert classify_client(clean).primary is Kind.BROWSER


def test_self_declared_bot_harvesting_is_a_crawler() -> None:
    # AlexCollieBot: declares a crawler, walks many pages, no browser behaviour.
    # Re-requests a modest path set (low coverage), so it must still clear as a
    # crawler rather than fall to unknown.
    feats = ClientFeatures(
        request_count=199,
        distinct_paths=47,
        coverage=47 / 199,
        asset_coload_ratio=0.0,
        ua_looks_like_browser=False,
        ua_declares_bot=True,
        ua_empty=False,
        referer_following_ratio=0.2,
        ratio_2xx=0.5,
        user_agent="AlexCollieBot/1.0 (+https://alexcollie.com/bot; crawler@alexcollie.com)",
    )
    result = classify_client(feats, datacenter=True)
    assert result.primary is Kind.CRAWLER


def test_crawler_recognised_by_origin_asn() -> None:
    # AS35237 (Sberbank) crawls behind spoofed browser UAs; recognised by ASN,
    # classified ai_crawler and tagged asn-attributed.
    feats = ClientFeatures(
        request_count=80,
        distinct_paths=40,
        coverage=0.5,
        asset_coload_ratio=0.0,
        ua_looks_like_browser=True,
        ua_empty=False,
        referer_following_ratio=1.0,
        ratio_2xx=0.9,
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML) "
        "Chrome/91.0.4472.124 Safari/537.36",
        as_number="35237",
    )
    result = classify_client(feats)
    assert result.primary is Kind.AI_CRAWLER
    assert "asn-attributed" in result.tags


def test_asn_crawler_with_browser_behaviour_is_not_a_browser() -> None:
    # The reported Sberbank case: a spoofed browser UA that even co-loads sub-
    # resources like a real browser (87%). The origin AS still gives it away, so
    # the strong browser signal must bow to the ai_crawler classification.
    feats = ClientFeatures(
        request_count=22509,
        asset_coload_ratio=0.87,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML) "
        "Chrome/91.0.4472.124 Safari/537.36",
        as_number="35237",
    )
    result = classify_client(feats)
    assert result.primary is Kind.AI_CRAWLER
    assert "asn-attributed" in result.tags


def test_combiner_unknown_below_threshold() -> None:
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, ClientFeatures(request_count=5), unknown_threshold=0.45)
    assert result.primary is Kind.UNKNOWN
    assert result.all_signals == tuple(signals)


def test_threshold_boundary_survives_float_error() -> None:
    # 0.3 + 0.15 == 0.44999999996 in float; a sum that equals the threshold must
    # still meet it, not fall to UNKNOWN (the panscient.com scraper case).
    signals = [Signal(Kind.SCRAPER, 0.3 + 0.15, ("harvests many pages",), "scraper")]
    result = combine(signals, ClientFeatures(request_count=414), unknown_threshold=0.45)
    assert result.primary is Kind.SCRAPER
    assert result.confidence == 0.45


def test_combiner_singleton_for_one_request_would_be_unknown() -> None:
    # A single-request client with no strong signal is bucketed as a singleton.
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, ClientFeatures(request_count=1), unknown_threshold=0.45)
    assert result.primary is Kind.SINGLETON


def test_combiner_one_request_keeps_confident_kind() -> None:
    # One request that clearly matches a kind keeps that kind, not singleton.
    signals = [Signal(Kind.VULN_SCANNER, 0.8, ("probe",), "vuln_scanner")]
    result = combine(signals, ClientFeatures(request_count=1), unknown_threshold=0.45)
    assert result.primary is Kind.VULN_SCANNER


_FAKE_BROWSER = ClientFeatures(
    request_count=5,
    ua_looks_like_browser=True,
    asset_coload_ratio=0.0,
    referer_following_ratio=0.0,
)


def test_combiner_spoofed_browser_from_datacenter() -> None:
    # Browser UA + hosting IP + no browser behaviour, otherwise unknown -> spoofed.
    signals = [Signal(Kind.BROWSER, 0.3, ("ua only",), "browser")]
    result = combine(signals, _FAKE_BROWSER, datacenter=True, unknown_threshold=0.45)
    assert result.primary is Kind.SPOOFED_BROWSER
    assert {"fake-browser", "datacenter"} <= result.tags


def test_combiner_fake_browser_without_datacenter_stays_unknown() -> None:
    # The same costume from a non-hosting IP is only tagged, not promoted.
    signals = [Signal(Kind.BROWSER, 0.3, ("ua only",), "browser")]
    result = combine(signals, _FAKE_BROWSER, datacenter=False, unknown_threshold=0.45)
    assert result.primary is Kind.UNKNOWN
    assert "fake-browser" in result.tags
    assert "datacenter" not in result.tags


def test_feed_reader_with_safari_prefix_is_not_fake_browser() -> None:
    # macOS feed readers wear a Safari UA with the product appended; the browser
    # prefix + no co-loading must not be mistaken for a browser costume.
    feats = ClientFeatures(
        request_count=50,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) NetNewsWire/6.1",
    )
    tags = combine([Signal(Kind.FEED_READER, 0.5, ("feed UA",), "feed_reader")], feats).tags
    assert "fake-browser" not in tags


def test_combiner_real_browser_behaviour_from_datacenter_is_not_spoofed() -> None:
    # Asset co-loading means real browsing; a hosting IP alone doesn't condemn it.
    feats = ClientFeatures(request_count=5, ua_looks_like_browser=True, asset_coload_ratio=0.6)
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, feats, datacenter=True, unknown_threshold=0.45)
    assert result.primary is not Kind.SPOOFED_BROWSER
    assert "fake-browser" not in result.tags


def test_many_uas_on_residential_ip_is_shared_not_rotating() -> None:
    # A real browser sharing an IP with many others (NAT/VPN) -> benign shared-ip.
    feats = ClientFeatures(
        request_count=20, ua_looks_like_browser=True, asset_coload_ratio=0.7, ua_count_for_ip=8
    )
    tags = combine([Signal(Kind.BROWSER, 0.9, ("real",), "browser")], feats).tags
    assert "shared-ip" in tags
    assert "ua-rotating" not in tags


def test_many_uas_from_datacenter_is_rotating() -> None:
    # The same UA diversity from a hosting IP reads as evasive rotation.
    feats = ClientFeatures(request_count=20, ua_looks_like_browser=True, ua_count_for_ip=8)
    tags = combine([Signal(Kind.BROWSER, 0.3, ("ua",), "browser")], feats, datacenter=True).tags
    assert "ua-rotating" in tags
    assert "shared-ip" not in tags


def test_combiner_picks_strongest_label() -> None:
    signals = [
        Signal(Kind.CRAWLER, 0.5, ("a",), "crawler"),
        Signal(Kind.SCRAPER, 0.8, ("b",), "scraper"),
    ]
    result = combine(signals, ClientFeatures())
    assert result.primary is Kind.SCRAPER
    assert result.confidence == 0.8


def test_combiner_tie_breaks_by_priority() -> None:
    signals = [
        Signal(Kind.CRAWLER, 0.6, ("a",), "crawler"),
        Signal(Kind.BROWSER, 0.6, ("b",), "browser"),
    ]
    # BROWSER outranks CRAWLER in the priority table.
    assert combine(signals, ClientFeatures()).primary is Kind.BROWSER


def test_probing_declared_crawler_is_tagged_not_impersonator() -> None:
    # Declares Googlebot and probes vuln paths: keeps its kind, gets a 'probing'
    # tag. Probing is misbehaviour, not a forged identity (that's DNS's call).
    feats = ClientFeatures(
        request_count=5, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)", vuln_path_hits=3
    )
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats)
    assert result.primary is Kind.SEARCH_ENGINE
    assert "probing" in result.tags
    assert result.primary is not Kind.IMPERSONATOR


def test_dns_mismatch_is_impersonator() -> None:
    feats = ClientFeatures(request_count=5, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
    verification = BotVerification(VerificationStatus.IMPERSONATOR, resolved_host="x.evil.example")
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert result.primary is Kind.IMPERSONATOR


def test_seo_marketing_classified() -> None:
    feats = ClientFeatures(request_count=20, user_agent="Mozilla/5.0 (compatible; AhrefsBot/7.0)")
    assert classify_client(feats).primary is Kind.SEO_MARKETING


def test_scanner_user_agent_classified() -> None:
    feats = ClientFeatures(request_count=4, user_agent="sqlmap/1.7")
    assert classify_client(feats).primary is Kind.VULN_SCANNER


def test_internet_archive_classified_as_archiver() -> None:
    feats = ClientFeatures(
        request_count=30,
        user_agent="Mozilla/5.0 (compatible; archive.org_bot; +http://archive.org/details/archive.org_bot)",
    )
    assert classify_client(feats).primary is Kind.ARCHIVER


def test_verified_tag_from_verification() -> None:
    feats = ClientFeatures(request_count=5, user_agent="Googlebot/2.1")
    verification = BotVerification(VerificationStatus.VERIFIED, resolved_host="x.googlebot.com")
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert "verified" in result.tags
    assert result.primary is Kind.SEARCH_ENGINE


def test_has_cache_tag_on_304() -> None:
    cached = ClientFeatures(request_count=5, status_counts={200: 4, 304: 1})
    signals = [Signal(Kind.BROWSER, 0.6, ("browses",), "browser")]
    assert "has-cache" in combine(signals, cached).tags
    # No 304 -> no tag.
    plain = ClientFeatures(request_count=5, status_counts={200: 5})
    assert "has-cache" not in combine(signals, plain).tags


def test_uses_head_tag() -> None:
    signals = [Signal(Kind.MONITOR, 0.6, ("monitors",), "monitor")]
    heading = ClientFeatures(request_count=10, head_ratio=0.5)
    assert "uses-HEAD" in combine(signals, heading).tags
    # Incidental HEAD (at or below the bar) is not tagged.
    incidental = ClientFeatures(request_count=10, head_ratio=0.1)
    assert "uses-HEAD" not in combine(signals, incidental).tags


def test_304_lifts_browser_and_feed_reader_confidence() -> None:
    base = dict(request_count=10, asset_coload_ratio=0.6, ua_looks_like_browser=True, ratio_404=0.0)
    without = BrowserClassifier().evaluate(ClientFeatures(**base, status_counts={200: 10}))
    with_cache = BrowserClassifier().evaluate(ClientFeatures(**base, status_counts={304: 2}))
    assert with_cache[0].confidence > without[0].confidence

    feed = dict(request_count=10, feed_requests=10, feed_ratio=1.0)
    f_without = FeedReaderClassifier().evaluate(ClientFeatures(**feed, status_counts={200: 10}))
    f_with = FeedReaderClassifier().evaluate(ClientFeatures(**feed, status_counts={304: 5}))
    assert f_with[0].confidence > f_without[0].confidence


def test_respecting_robots_is_not_tagged() -> None:
    # Respecting robots is the quiet norm -- it carries no per-client tag anymore.
    feats = ClientFeatures(request_count=10)
    compliance = ComplianceReport(
        verdict=RobotsVerdict.RESPECTS,
        matched_group="*",
        disallowed_hits=0,
        sample_disallowed=(),
        fetched_robots_first=True,
        crawl_delay=None,
        crawl_delay_respected=None,
    )
    signals = [Signal(Kind.BROWSER, 0.6, ("browses",), "browser")]
    tags = combine(signals, feats, compliance=compliance).tags
    assert "respects-robots" not in tags and "ignores-robots" not in tags


def test_compliance_tags_applied() -> None:
    feats = ClientFeatures(request_count=10)
    compliance = ComplianceReport(
        verdict=RobotsVerdict.IGNORES,
        matched_group="*",
        disallowed_hits=3,
        sample_disallowed=("/private/",),
        fetched_robots_first=False,
        crawl_delay=None,
        crawl_delay_respected=None,
    )
    signals = [Signal(Kind.CRAWLER, 0.6, ("crawls",), "crawler")]
    result = combine(signals, feats, compliance=compliance)
    assert "ignores-robots" in result.tags


def test_feed_reader_from_behaviour_without_feed_ua() -> None:
    # A generic client that mostly polls a feed should classify as a feed reader.
    feats = ClientFeatures(
        request_count=12,
        feed_requests=12,
        feed_ratio=1.0,
        distinct_paths=1,
        rate_regularity=0.1,
        user_agent="Mozilla/5.0 (some generic client)",
    )
    result = classify_client(feats)
    assert result.primary is Kind.FEED_READER


def test_feed_reader_fetching_non_feeds_is_tagged() -> None:
    feats = ClientFeatures(
        request_count=10,
        feed_requests=7,  # 3 non-feed requests
        feed_ratio=0.7,
        distinct_paths=4,
        user_agent="Feedbin feed-id:1 - 5 subscribers",
    )
    result = classify_client(feats)
    assert result.primary is Kind.FEED_READER
    assert "fetches-non-feeds" in result.tags


def test_declared_bot_is_not_a_browser_even_when_co_loading() -> None:
    # amazon-Quick declares itself a bot; co-loading sub-resources (it renders
    # pages) must not make it a browser -- its declared identity wins.
    feats = ClientFeatures(
        request_count=23, asset_coload_ratio=1.0, user_agent="amazon-Quick-on-behalf-of-abc123"
    )
    assert classify_client(feats).primary is Kind.AI_CRAWLER


def test_coloading_feed_reader_is_not_a_browser_and_not_forged_referer() -> None:
    feats = ClientFeatures(
        request_count=166,
        feed_requests=150,
        feed_ratio=0.9,
        asset_coload_ratio=1.0,
        self_referer_ratio=1.0,  # would tag forged-referer on a would-be browser
        distinct_paths=10,
        user_agent="FreshRSS/1.28.1 (Linux; https://freshrss.org)",
    )
    result = classify_client(feats)
    assert result.primary is Kind.FEED_READER
    assert "forged-referer" not in result.tags  # browser-only signal, not for agents


def test_datacenter_browser_ua_without_behaviour_is_spoofed() -> None:
    feats = ClientFeatures(
        request_count=26,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
        static_ratio=0.4,
        ratio_404=0.0,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/103.0 Safari/537.36",
    )
    assert classify_client(feats, datacenter=True).primary is Kind.SPOOFED_BROWSER


def test_feed_minority_is_not_a_feed_reader() -> None:
    # Grazes a feed but mostly hammers pages, no feed-reader UA -> not a feed reader.
    feats = ClientFeatures(
        request_count=20,
        feed_requests=4,
        feed_ratio=0.2,
        distinct_paths=6,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/103.0 Safari/537.36",
    )
    assert classify_client(feats).primary is not Kind.FEED_READER


def test_datacenter_nudges_a_borderline_browser_out() -> None:
    sig = [Signal(Kind.BROWSER, 0.5, ("x",), "browser")]
    feats = ClientFeatures(request_count=10, ua_looks_like_browser=True)
    assert combine(sig, feats).primary is Kind.BROWSER
    assert combine(sig, feats, datacenter=True).primary is not Kind.BROWSER


def test_metronomic_timing_penalises_browser() -> None:
    # Browser-ish signals but machine-regular cadence -> not a person.
    feats = ClientFeatures(
        request_count=10,
        ua_looks_like_browser=True,
        referer_following_ratio=0.5,
        static_ratio=0.4,
        ratio_404=0.0,
        distinct_paths=8,
        rate_regularity=0.05,
    )
    assert classify_client(feats).primary is not Kind.BROWSER


def test_head_heavy_browser_is_not_a_browser() -> None:
    # Browser-shaped (browser UA, co-loads assets) but mostly HEAD: a real
    # browser fetches with GET and never issues HEAD, so this is automation
    # behind a browser UA and must not pass as a browser.
    feats = ClientFeatures(
        request_count=20,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.6,
        ratio_404=0.0,
        head_ratio=0.8,
    )
    signals = BrowserClassifier().evaluate(feats)
    assert signals and signals[0].confidence <= 0.3  # capped below the threshold
    assert classify_client(feats).primary is not Kind.BROWSER


def test_incidental_head_does_not_sink_a_browser() -> None:
    # A stray HEAD (below the threshold) leaves a real browser alone.
    feats = ClientFeatures(
        request_count=20,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.8,
        static_ratio=0.5,
        ratio_404=0.0,
        head_ratio=0.05,
    )
    assert classify_client(feats).primary is Kind.BROWSER


def test_head_corroborates_a_feed_reader() -> None:
    # A declared reader that HEADs feeds to check freshness gets a small lift,
    # and stays a feed reader (HEAD is not penalised the way it is for browsers).
    base = ClientFeatures(
        request_count=8,
        feed_requests=8,
        feed_ratio=1.0,
        distinct_paths=5,  # above the "polls few URLs" bonus, so we're off the ceiling
        user_agent="NetNewsWire (RSS reader)",
    )
    heading = replace(base, head_ratio=0.5)
    with_head = FeedReaderClassifier().evaluate(heading)[0].confidence
    without = FeedReaderClassifier().evaluate(base)[0].confidence
    assert with_head > without
    assert classify_client(heading).primary is Kind.FEED_READER


def test_pure_feed_reader_not_tagged() -> None:
    feats = ClientFeatures(
        request_count=8,
        feed_requests=8,
        feed_ratio=1.0,
        distinct_paths=1,
        user_agent="NetNewsWire (RSS reader)",
    )
    result = classify_client(feats)
    assert result.primary is Kind.FEED_READER
    assert "fetches-non-feeds" not in result.tags


def test_search_engine_and_social_preview_are_distinct() -> None:
    google = classify_client(
        ClientFeatures(request_count=4, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
    )
    assert google.primary is Kind.SEARCH_ENGINE
    facebook = classify_client(ClientFeatures(request_count=2, user_agent="facebookexternalhit/1.1"))
    assert facebook.primary is Kind.SOCIAL_PREVIEW


def test_classify_client_runs_all() -> None:
    feats = ClientFeatures(
        request_count=10,
        asset_coload_ratio=0.8,
        ua_looks_like_browser=True,
        ratio_404=0.0,
    )
    result = classify_client(feats)
    assert result.primary is Kind.BROWSER
