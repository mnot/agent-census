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


def test_lone_probe_is_a_scanner_not_a_singleton() -> None:
    # A single request, and it's a probe: its whole footprint is hostile, so it
    # clears as a vuln_scanner rather than falling into the singleton bucket.
    feats = ClientFeatures(
        request_count=1, vuln_path_hits=1, sample_vuln_paths=("/.env",), ratio_404=1.0
    )
    assert classify_client(feats).primary is Kind.VULN_SCANNER


def test_one_probe_amid_normal_traffic_stays_incidental() -> None:
    # A single probe buried in otherwise normal traffic is not enough on its own.
    feats = ClientFeatures(
        request_count=50, vuln_path_hits=1, sample_vuln_paths=("/.env",), ratio_2xx=0.95
    )
    signals = VulnScannerClassifier().evaluate(feats)
    assert signals and signals[0].confidence < 0.45  # incidental tier, below threshold


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


def test_modest_self_declared_bot_clears_unknown() -> None:
    # ThinkBot-style: a self-declared bot following links from a datacenter, but
    # only a couple of distinct paths. It must clear the unknown floor as a crawler.
    feats = ClientFeatures(
        request_count=13,
        distinct_paths=2,
        coverage=2 / 13,
        asset_coload_ratio=0.0,
        ua_looks_like_browser=False,
        ua_declares_bot=True,
        ua_empty=False,
        referer_following_ratio=0.56,
        ratio_2xx=0.8,
        user_agent="Mozilla/5.0 (compatible; ThinkBot/0.5.8; +http://example.com/bot)",
    )
    assert classify_client(feats, datacenter=True).primary is Kind.CRAWLER


def test_headless_browser_is_tagged() -> None:
    feats = ClientFeatures(
        request_count=50,
        page_count=10,
        asset_coload_ratio=0.9,
        ua_looks_like_browser=False,  # 'headless' makes declares_bot true, so not a browser
        ua_declares_bot=True,
        ua_empty=False,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36",
    )
    assert "headless-browser" in classify_client(feats).tags


def test_no_browser_cache_is_tagged() -> None:
    # Re-fetches the same handful of paths many times, never a 304 -> holds no cache.
    feats = ClientFeatures(
        request_count=300,
        distinct_paths=10,
        coverage=10 / 300,
        status_counts={200: 300},
        ua_looks_like_browser=True,
        ua_empty=False,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    )
    assert feats.holds_no_cache
    result = classify_client(feats)
    assert "no-browser-cache" in result.tags
    # The REDbot tool-driver shape: browser UA, but no cache and no purpose -> automation.
    assert result.primary is Kind.AUTOMATION


def test_headless_with_no_purpose_is_automation() -> None:
    feats = ClientFeatures(
        request_count=40,
        page_count=8,
        asset_coload_ratio=0.9,  # a real headless engine does render sub-resources
        ua_looks_like_browser=False,
        ua_declares_bot=True,
        ua_empty=False,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36",
    )
    assert classify_client(feats).primary is Kind.AUTOMATION


def test_automation_loses_to_an_identified_purpose() -> None:
    # A headless client that walks the site is a crawler, not automation: the
    # machine tell only decides when no purpose classifier clears the bar.
    feats = ClientFeatures(
        request_count=50,
        distinct_paths=50,
        coverage=1.0,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.9,
        ratio_2xx=0.9,
        ua_looks_like_browser=False,
        ua_declares_bot=True,
        ua_empty=False,
        user_agent="HeadlessChrome/149.0.0.0 Safari/537.36",
    )
    result = classify_client(feats)
    assert result.primary is not Kind.AUTOMATION  # a real purpose (crawler) outranks the tell
    assert "headless-browser" in result.tags  # the tell is still recorded


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


def test_claude_user_is_an_ai_crawler_not_a_spoofed_browser() -> None:
    # Claude-User wears a KHTML/compatible browser shell; from a datacenter with
    # no browser behaviour it would read as spoofed_browser, but it is a declared
    # agent and must classify as ai_crawler.
    feats = ClientFeatures(
        request_count=40,
        ua_looks_like_browser=True,  # the KHTML shell trips the browser-UA regex
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
        user_agent="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "Claude-User/1.0; +claude-user@anthropic.com)",
    )
    result = classify_client(feats, datacenter=True)
    assert result.primary is Kind.AI_CRAWLER
    assert result.primary is not Kind.SPOOFED_BROWSER


def test_stale_browser_version_is_not_a_browser() -> None:
    # The reported case: Chrome 106 (shipped 2022) seen in mid-2026 -- ~3.7 years
    # behind the auto-update cadence, with browser-shaped behaviour. The frozen
    # version caps the browser verdict.
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=18000,
        distinct_paths=600,
        asset_coload_ratio=0.7,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        status_counts={200: 17000, 304: 50},  # has some 304s, so only the age bites
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
    )
    assert classify_client(feats).primary is not Kind.BROWSER


def test_impossible_future_version_is_not_current() -> None:
    # A UA claiming a version far beyond the release cadence (e.g. Chrome/999 to
    # look maximally fresh) must not be rated "current" and rewarded the freshness
    # bonus -- it's a forged string.
    from datetime import datetime, timezone

    from agent_census import uas

    as_of = datetime(2026, 6, 1, tzinfo=timezone.utc)
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/999.0.0.0 Safari/537.36"
    )
    assert uas.version_age_band(ua, as_of) == "impossible"


def test_current_safari_year_numbering_is_not_impossible() -> None:
    # Apple renumbered Safari to track the OS year (18 in 2024 -> 26 in 2025), so a
    # current iPhone UA reads as far "ahead" of the linear cadence. Safari must not
    # be flagged impossible for that -- it's the real, current string.
    from datetime import datetime, timezone

    from agent_census import uas

    as_of = datetime(2026, 6, 1, tzinfo=timezone.utc)
    ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1"
    )
    assert uas.browser_version(ua) == ("safari", 26)
    assert uas.version_age_band(ua, as_of) == "current"


def test_safari_year_numbering_ages_on_continuous_scale() -> None:
    # With the 18 -> 26 jump undone, Safari ages one major per year, so staleness is
    # measured on the real timeline rather than the broken raw numbers.
    from datetime import datetime, timezone

    from agent_census import uas

    jun26 = datetime(2026, 6, 1, tzinfo=timezone.utc)
    safari26 = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1"
    )
    months = uas.version_age_months(safari26, jun26)
    assert months is not None and 0 < months < 14  # ~9mo old, not the broken ~-70

    def band(major: str) -> str | None:
        ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            f"(KHTML, like Gecko) Version/{major} Safari/605.1.15"
        )
        return uas.version_age_band(ua, jun26)

    assert band("18.0") is None  # last year's release -- not yet stale
    assert band("17.0") == "stale"  # ~2+ years behind by mid-2026
    assert band("14.1") == "stale"  # but still only stale, never ancient


def test_impossible_version_browser_is_capped() -> None:
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=18000,
        distinct_paths=600,
        asset_coload_ratio=0.7,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        status_counts={200: 17000, 304: 50},
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/999.0.0.0 Safari/537.36",
    )
    assert classify_client(feats).primary is not Kind.BROWSER


def test_old_safari_is_only_mildly_dinged_not_capped() -> None:
    # Safari is OS-bundled and common in old versions on old Apple hardware, so a
    # well-behaved old Safari stays a browser (mild ding, never the cap Chrome
    # and Firefox get).
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=40,
        distinct_paths=40,
        asset_coload_ratio=0.7,
        ua_looks_like_browser=True,
        ua_empty=False,
        ratio_404=0.0,
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/14.1 Safari/605.1.15",
    )
    result = classify_client(feats)
    assert result.primary is Kind.BROWSER  # not capped
    assert "stale-browser-ua" in result.tags  # but flagged stale, never ancient


def test_bot_ua_only_for_unrecognised_bots() -> None:
    # A recognised crawler is the declares-known-bot fact, never doubled by bot-ua.
    known = classify_client(
        ClientFeatures(
            request_count=5,
            ua_empty=False,
            ua_declares_bot=True,
            user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        )
    )
    assert "declares-known-bot" in known.tags and "bot-ua" not in known.tags
    # A self-declared bot we don't recognise gets bot-ua, and no declares-known-bot.
    unknown = classify_client(
        ClientFeatures(request_count=5, ua_empty=False, ua_declares_bot=True, user_agent="FooBot/1.0")
    )
    assert "bot-ua" in unknown.tags and "declares-known-bot" not in unknown.tags


def test_ua_age_tags() -> None:
    from datetime import datetime, timezone

    def tags_for(ua: str, when: datetime) -> frozenset[str]:
        feats = ClientFeatures(request_count=10, ua_empty=False, last_seen=when, user_agent=ua)
        return classify_client(feats).tags

    y2026 = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert "ancient-browser-ua" in tags_for("Chrome/106.0.0.0 Safari/537.36", y2026)
    assert "current-browser-ua" in tags_for(
        "Chrome/120.0.0.0 Safari/537.36", datetime(2024, 1, 1, tzinfo=timezone.utc)
    )
    assert "stale-browser-ua" in tags_for("Firefox/100.0", datetime(2024, 6, 1, tzinfo=timezone.utc))
    # A generic library has no browser version -> generic-ua, no browser/age tag.
    curl_tags = tags_for("curl/8.0", y2026)
    assert "generic-ua" in curl_tags
    assert not any(t.endswith("-browser-ua") for t in curl_tags)


def test_current_browser_version_stays_a_browser() -> None:
    # A version roughly current for the log's date is no mark against it.
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=40,
        distinct_paths=40,
        asset_coload_ratio=0.7,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36",
    )
    assert classify_client(feats).primary is Kind.BROWSER


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
    ua_empty=False,
    asset_coload_ratio=0.0,
    referer_following_ratio=0.0,
    page_count=4,  # fetched HTML pages...
    referer_count=4,  # ...with referers present, so no-assets/cold are measurable
)


def test_combiner_spoofed_browser_from_datacenter() -> None:
    # Browser UA + hosting IP + no browser behaviour, otherwise unknown -> spoofed.
    # The verdict's evidence is now in the tags: browser-ua, but no-assets and cold.
    signals = [Signal(Kind.BROWSER, 0.3, ("ua only",), "browser")]
    result = combine(signals, _FAKE_BROWSER, datacenter=True, unknown_threshold=0.45)
    assert result.primary is Kind.SPOOFED_BROWSER
    assert {"browser-ua", "no-assets", "cold", "datacenter"} <= result.tags


def test_browser_version_parsing_and_age() -> None:
    from datetime import datetime, timezone

    from agent_census import uas

    assert uas.browser_version("... Chrome/106.0.0.0 Safari/537.36") == ("chrome", 106)
    assert uas.browser_version("... Firefox/121.0") == ("firefox", 121)
    # Edge/Opera ride the Chromium major via their Chrome/ token.
    assert uas.browser_version("... Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0") == ("chrome", 120)
    # Safari reports its Version/ major (not the frozen Safari/605 WebKit build).
    assert uas.browser_version(
        "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML) Version/16.0 Safari/605.1.15"
    ) == ("safari", 16)
    # Non-browsers report nothing.
    assert uas.browser_version("curl/8.0") is None

    at = datetime(2026, 6, 1, tzinfo=timezone.utc)
    old = uas.version_age_months("Chrome/106.0.0.0", at)
    assert old is not None and old > 36  # ~3.7 years
    fresh = uas.version_age_months("Chrome/120.0.0.0", datetime(2024, 1, 1, tzinfo=timezone.utc))
    assert fresh is not None and fresh <= 6
    assert uas.version_age_months("Chrome/120.0.0.0", None) is None  # no anchor time


def test_contact_marker_in_ua_reads_as_a_bot_not_a_browser() -> None:
    from agent_census import uas

    # A browser-shaped shell, but it advertises a +contact: that is how a bot
    # names its operator, so it is automation, not a browser.
    shelled = (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
        "SomeFetcher/1.0; +https://some.example/bot)"
    )
    assert uas.declares_bot(shelled)
    assert not uas.looks_like_browser(shelled)
    # An e-mail contact counts too.
    assert uas.declares_bot("Mozilla/5.0 (compatible; FooAgent/2.0; +ops@foo.example)")
    # A genuine browser carries no contact marker and is unaffected.
    real = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17 Safari/605.1.15"
    )
    assert uas.looks_like_browser(real) and not uas.declares_bot(real)


def test_combiner_fake_browser_without_datacenter_stays_unknown() -> None:
    # The same costume from a non-hosting IP is only fingerprinted, not promoted.
    signals = [Signal(Kind.BROWSER, 0.3, ("ua only",), "browser")]
    result = combine(signals, _FAKE_BROWSER, datacenter=False, unknown_threshold=0.45)
    assert result.primary is Kind.UNKNOWN
    assert {"browser-ua", "no-assets", "cold"} <= result.tags
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
    result = combine([Signal(Kind.FEED_READER, 0.5, ("feed UA",), "feed_reader")], feats)
    assert result.primary is Kind.FEED_READER  # not mistaken for a spoofed browser


def test_combiner_real_browser_behaviour_from_datacenter_is_not_spoofed() -> None:
    # Asset co-loading means real browsing; a hosting IP alone doesn't condemn it.
    feats = ClientFeatures(request_count=5, ua_looks_like_browser=True, asset_coload_ratio=0.6)
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, feats, datacenter=True, unknown_threshold=0.45)
    assert result.primary is not Kind.SPOOFED_BROWSER


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
        request_count=5,
        user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)",
        vuln_path_hits=3,
        vuln_path_ratio=0.6,  # 3 of 5 requests are probes -- genuinely probing
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


def test_fingerprint_poles_and_indeterminate_gating() -> None:
    from datetime import datetime, timezone

    # A real browser: the positive poles across dimensions.
    browser = ClientFeatures(
        request_count=20,
        ua_empty=False,
        ua_looks_like_browser=True,
        rate_regularity=0.8,
        asset_coload_ratio=0.7,
        page_count=10,
        referer_following_ratio=0.6,
        referer_count=15,
        status_counts={200: 18, 304: 2},
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36",
        last_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    bt = classify_client(browser).tags
    # The UA-shape tag folds in the version age, so it's current-browser-ua, not
    # a separate browser-ua + current-ua pair.
    assert {"current-browser-ua", "bursty", "loads-assets", "follows-links", "has-cache"} <= bt
    assert "browser-ua" not in bt

    # A cold library scraper: the negative poles -- and navigation is *omitted*
    # (not "cold") because no request carried a Referer, so it can't be judged.
    bot = ClientFeatures(
        request_count=50,
        ua_empty=False,
        ua_looks_like_browser=False,
        rate_regularity=0.05,
        asset_coload_ratio=0.0,
        page_count=40,
        referer_count=0,  # no referers -> navigation indeterminate
        distinct_paths=10,
        status_counts={200: 50},
        user_agent="python-requests/2.31.0",
    )
    tt = classify_client(bot).tags
    assert {"generic-ua", "metronomic", "no-assets"} <= tt
    assert "follows-links" not in tt and "cold" not in tt  # indeterminate -> no tag
    assert "no-cache" not in tt  # caching is one-sided: absence of 304 is unknowable


def test_behavioural_tags_promoted_from_evidence() -> None:
    storm = ClientFeatures(request_count=30, ratio_404=0.9, distinct_404_paths=20)
    assert "404-storm" in classify_client(storm).tags
    exotic = ClientFeatures(request_count=5, exotic_method_count=3)
    assert "exotic-method" in classify_client(exotic).tags
    metro = ClientFeatures(request_count=20, rate_regularity=0.05)
    assert "metronomic" in classify_client(metro).tags
    # A plain client earns none of them.
    plain = ClientFeatures(request_count=20, ratio_404=0.0, rate_regularity=0.8)
    assert not ({"404-storm", "exotic-method", "metronomic"} & classify_client(plain).tags)


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


def test_feed_ua_terms_are_word_anchored() -> None:
    # The short generic terms ("atom", "rss") must not match inside unrelated words.
    from agent_census.classify.feed_reader import ua_is_feed_reader

    assert not ua_is_feed_reader("Mozilla/5.0 Anatomy/1.0")  # 'atom' inside 'Anatomy'
    assert not ua_is_feed_reader("atomic-loader/2")  # 'atom' inside 'atomic'
    assert ua_is_feed_reader("My RSS Poller/1.0")  # 'rss' as a whole word
    assert ua_is_feed_reader("SomeClient (atom)")  # 'atom' as a whole word


def test_named_feed_readers_without_generic_terms_are_recognised() -> None:
    # Readers whose UA carries no rss/atom/feed word -- recognised by product name.
    from agent_census.classify.feed_reader import ua_is_feed_reader

    assert ua_is_feed_reader("Selfoss/2.19 (+https://selfoss.aditu.de)")
    assert ua_is_feed_reader("feedspool/1.0; +https://github.com/lmorchard/feedspool-go")
    assert ua_is_feed_reader("SurfaceFeedPoller/1.0 (+https://thesurface.ai)")
    assert ua_is_feed_reader("Lumen/0.1 (+https://github.com/yuichielectric/Lumen)")
    assert not ua_is_feed_reader("Lumen Technologies router")  # bare 'Lumen' must not match


def test_feed_reader_ua_is_not_tagged_bot_ua() -> None:
    # A feed reader that also self-declares a bot names itself a feed tool, not a
    # generic unrecognised bot, so it must not pick up the bot-ua tag.
    from agent_census.classify.tags import derive_tags

    feats = ClientFeatures(
        request_count=10,
        user_agent="PollerBot/1.0 (RSS reader)",
        ua_declares_bot=True,
    )
    assert "bot-ua" not in derive_tags(feats, None, None)


def test_feed_reader_from_datacenter_is_not_spoofed_browser() -> None:
    # Browser-shaped UA, hosting origin, no browser behaviour -- would be a spoofed
    # browser, except it names a feed tool, so its identity wins over the costume.
    feats = ClientFeatures(
        request_count=10,
        user_agent="Mozilla/5.0 (compatible) QuietReader (RSS reader)",
        ua_looks_like_browser=True,
        ua_declares_bot=True,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
    )
    result = combine([], feats, datacenter=True)
    assert result.primary is not Kind.SPOOFED_BROWSER


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


def test_fetching_robots_dings_a_browser() -> None:
    # All-distinct URLs (no 304 ding), so this isolates the robots.txt nudge.
    base = ClientFeatures(
        request_count=20, distinct_paths=20, asset_coload_ratio=0.8, ua_looks_like_browser=True
    )
    with_robots = replace(base, fetched_robots_txt=True)
    assert (
        BrowserClassifier().evaluate(with_robots)[0].confidence
        < BrowserClassifier().evaluate(base)[0].confidence
    )


def test_cold_refetching_is_not_a_browser() -> None:
    # The reported case: heavy volume, browser-shaped, but re-fetches a small set
    # of URLs cold (no 304s) and checked robots.txt -> not a browser.
    feats = ClientFeatures(
        request_count=3470,
        distinct_paths=200,  # ~3270 revisits, all cold
        asset_coload_ratio=0.67,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        fetched_robots_txt=True,
        status_counts={200: 3470},
    )
    assert classify_client(feats).primary is not Kind.BROWSER


def test_moderate_volume_all_distinct_stays_a_browser() -> None:
    # A normal-sized session of distinct URLs with no 304s says nothing (nothing
    # was revisited), so a genuine browser is left alone below the volume bar.
    feats = ClientFeatures(
        request_count=300,
        distinct_paths=300,
        asset_coload_ratio=0.8,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        status_counts={200: 300},
    )
    assert classify_client(feats).primary is Kind.BROWSER


def test_large_volume_no_304_is_not_a_browser() -> None:
    # Browser-shaped and all-distinct, but a large number of requests without one
    # 304: a real browser would have revalidated or served from cache (fewer
    # requests). Zero revalidation at this scale -> not a browser.
    feats = ClientFeatures(
        request_count=2500,
        distinct_paths=2500,
        asset_coload_ratio=0.7,
        ua_looks_like_browser=True,
        ratio_404=0.0,
        status_counts={200: 2500},
    )
    assert classify_client(feats).primary is not Kind.BROWSER


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


def test_turnitin_classifies_as_data_harvester() -> None:
    feats = ClientFeatures(
        request_count=5,
        ua_empty=False,
        user_agent="TurnitinBot/3.0 (+https://turnitin.com/robot/crawlerinfo.html)",
    )
    result = classify_client(feats)
    assert result.primary is Kind.DATA_HARVESTER
    assert "declares-known-bot" in result.tags


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


def test_native_app_stack_is_app_kind() -> None:
    # An iOS app using CFNetwork, and a Flutter app using dart:io, are first-party
    # app traffic -- not a browser, not a crawler.
    cfnet = ClientFeatures(
        request_count=20, user_agent="HackerNews/1541 CFNetwork/3860.600.12 Darwin/25.5.0"
    )
    assert classify_client(cfnet).primary is Kind.APP
    dart = ClientFeatures(request_count=5, user_agent="Dart/3.11 (dart:io)")
    assert classify_client(dart).primary is Kind.APP


def test_feed_reading_app_stays_feed_reader() -> None:
    # A feed reader that happens to ride CFNetwork is still a feed reader: the more
    # specific identity (and its behaviour) outweighs the generic app stack.
    feats = ClientFeatures(
        request_count=10,
        user_agent="NetNewsWire (RSS) CFNetwork/1410 Darwin/23.0.0",
        feed_requests=10,
        feed_ratio=1.0,
    )
    assert classify_client(feats).primary is Kind.FEED_READER


def test_feed_reader_app_not_feed_dominant_is_not_an_app() -> None:
    # Reeder / Tapestry / "RSS Mobile" ride CFNetwork but name a feed reader. Even
    # when feeds aren't the majority of the window, the named identity beats the
    # generic app stack -- they must not be filed as `app`.
    for ua in (
        "Reeder/5.0 CFNetwork/1410 Darwin/23.0.0",
        "Tapestry/1.0 CFNetwork/1410 Darwin/23.0.0",
        "RSS%20Mobile/2.1 CFNetwork/1410 Darwin/23.0.0",
    ):
        feats = ClientFeatures(
            request_count=10, distinct_paths=8, feed_requests=3, feed_ratio=0.3, user_agent=ua
        )
        assert classify_client(feats).primary is not Kind.APP, ua



def test_datacenter_library_harvester_is_a_scraper() -> None:
    # A generic HTTP library fetching several pages from hosting is a scraper, even
    # at a volume too low for the main scraper signal -- the origin tips it.
    feats = ClientFeatures(request_count=9, distinct_paths=9, user_agent="Go-http-client/2.0")
    assert classify_client(feats, datacenter=True).primary is Kind.SCRAPER
    # The same library from a residential IP is left unknown (could be an app/script).
    assert classify_client(feats, datacenter=False).primary is Kind.UNKNOWN


def test_residential_brief_browser_is_floored_to_browser() -> None:
    # A real, current browser UA from a residential IP whose short visit co-loaded
    # no assets still reads as a probable browser (low confidence), not unknown.
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=3,
        distinct_paths=3,
        ua_looks_like_browser=True,
        ua_empty=False,
        ratio_404=0.0,
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    )
    assert classify_client(feats, datacenter=False).primary is Kind.BROWSER
    # From hosting the same shape is a spoofed browser, not a real one.
    assert classify_client(feats, datacenter=True).primary is Kind.SPOOFED_BROWSER


def test_ancient_residential_browser_is_not_floored() -> None:
    # The floor excludes ancient UAs: a years-stale Chrome is the tell, so it stays
    # out of the browser bucket even from a residential IP.
    from datetime import datetime, timezone

    feats = ClientFeatures(
        request_count=3,
        distinct_paths=3,
        ua_looks_like_browser=True,
        ua_empty=False,
        ratio_404=0.0,
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/99.0.4844.5 Safari/537.36",
    )
    assert classify_client(feats, datacenter=False).primary is not Kind.BROWSER
