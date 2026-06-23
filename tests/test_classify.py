"""Tests for individual classifiers and the combiner."""

from __future__ import annotations

from agent_census.classify import classify_client
from agent_census.classify.browser import BrowserClassifier
from agent_census.classify.combiner import combine
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


def test_combiner_unknown_below_threshold() -> None:
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, ClientFeatures(), unknown_threshold=0.45)
    assert result.primary is Kind.UNKNOWN
    assert result.all_signals == tuple(signals)


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


def test_verified_tag_from_verification() -> None:
    feats = ClientFeatures(request_count=5, user_agent="Googlebot/2.1")
    verification = BotVerification(VerificationStatus.VERIFIED, resolved_host="x.googlebot.com")
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert "verified" in result.tags
    assert result.primary is Kind.SEARCH_ENGINE


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
