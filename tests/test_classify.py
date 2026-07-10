"""Tests for individual classifiers and the combiner."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_census.classify import classify_client
from agent_census.classify.browser import BrowserClassifier
from agent_census.classify.combiner import combine
from agent_census.classify.crawler import CrawlerClassifier
from agent_census.classify.feed_reader import FeedReaderClassifier
from agent_census.classify.scraper import ScraperClassifier
from agent_census.classify.spam_bot import SpamBotClassifier
from agent_census.classify.vuln_scanner import VulnScannerClassifier
from agent_census.model import (
    BotVerification,
    ChannelVerdict,
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
        distinct_404_targets=20,
        vuln_path_hits=8,
        sample_vuln_paths=("/.env", "/wp-login.php"),
        traversal_hits=1,
    )
    signals = VulnScannerClassifier().evaluate(feats)
    assert signals and signals[0].kind is Kind.VULN_SCANNER
    assert signals[0].confidence >= 0.45


def test_forbidden_heavy_corroborates_but_does_not_fire_alone() -> None:
    # The server refusing most of a client's requests (403) is corroboration for
    # vuln_scanner, but a 403 can be a benign hotlink / WAF block, so it must not brand a
    # client a scanner on its own.
    blocked = ClientFeatures(request_count=40, status_counts={403: 30, 200: 10})
    sig = VulnScannerClassifier().evaluate(blocked)
    assert sig and any("403" in e for e in sig[0].evidence)  # it contributes a tell...
    assert sig[0].confidence < 0.45  # ...but not enough to fire on its own
    assert classify_client(blocked).primary is not Kind.VULN_SCANNER


def test_forbidden_heavy_tips_a_client_with_a_hostile_tell() -> None:
    # A single traversal marker (0.15) is under the bar by itself; the server also
    # refusing most of this client's requests (403, 0.30) tips it to vuln_scanner.
    # This is the minimum tipping case and a deliberate knife-edge: 0.30 + 0.15 is
    # 0.44999… in double precision, and clears 0.45 only because the combiner rounds each
    # confidence to round_digits before comparing (see combiner.py, which cites this exact
    # sum). If the forbidden weight, the traversal weight, or round_digits changes, this is
    # the guard that catches the boundary flipping -- do not weaken it to a >= check.
    traversal = ClientFeatures(request_count=40, traversal_hits=1, status_counts={200: 40})
    assert classify_client(traversal).primary is not Kind.VULN_SCANNER
    traversal_blocked = replace(traversal, status_counts={403: 30, 200: 10})
    assert classify_client(traversal_blocked).primary is Kind.VULN_SCANNER


def test_lone_probe_is_a_scanner_not_a_singleton() -> None:
    # A single request, and it's a probe: its whole footprint is hostile, so it
    # clears as a vuln_scanner rather than falling into the singleton bucket.
    feats = ClientFeatures(
        request_count=1, vuln_path_hits=1, sample_vuln_paths=("/.env",), ratio_404=1.0
    )
    assert classify_client(feats).primary is Kind.VULN_SCANNER


def test_signal_confidence_never_goes_negative() -> None:
    # The browser classifier sums and subtracts weights and can net below 0 (a
    # metronomic, non-browser-shaped client). Signal.confidence must stay in [0, 1].
    from agent_census.classify.browser import BrowserClassifier

    feats = ClientFeatures(
        request_count=200,
        rate_regularity=0.0,  # perfectly metronomic -> penalty
        asset_coload_ratio=0.0,
        ua_looks_like_browser=False,
    )
    for signal in BrowserClassifier().evaluate(feats):
        assert 0.0 <= signal.confidence <= 1.0


def test_one_probe_amid_normal_traffic_stays_incidental() -> None:
    # A single probe buried in otherwise normal traffic is not enough on its own.
    feats = ClientFeatures(
        request_count=50, vuln_path_hits=1, sample_vuln_paths=("/.env",), ratio_2xx=0.95
    )
    signals = VulnScannerClassifier().evaluate(feats)
    assert signals and signals[0].confidence < 0.45  # incidental tier, below threshold


def test_spam_bot_submission_endpoint_reads_actual_paths() -> None:
    # The submission-endpoint signal must come from submit_path_hits (measured
    # against the client's real request paths), not the vuln-probe sample. A
    # comment-spam bot that hits no vuln-probe paths must still surface it.
    feats = ClientFeatures(
        request_count=20,
        method_counts={"POST": 20},
        post_ratio=1.0,
        asset_coload_ratio=0.0,
        submit_path_hits=20,
        sample_vuln_paths=(),  # never probed a vuln path
    )
    signals = SpamBotClassifier().evaluate(feats)
    assert signals and signals[0].kind is Kind.SPAM_BOT
    assert any("submission endpoints" in e for e in signals[0].evidence)


def test_tie_break_priority_covers_every_kind() -> None:
    # Every Kind needs an explicit tie-break rank. A missing one silently falls to
    # the worst rank (below UNKNOWN) via _RANK.get's len(_PRIORITY) fallback, so it
    # loses every confidence tie -- which is what happened to DATA_HARVESTER.
    from agent_census.classify.combiner import _PRIORITY

    assert set(_PRIORITY) == set(Kind)
    assert len(_PRIORITY) == len(set(_PRIORITY))  # no duplicate ranks


def test_vuln_scanner_silent_on_clean_client() -> None:
    feats = ClientFeatures(request_count=10, ratio_2xx=1.0)
    assert VulnScannerClassifier().evaluate(feats) == []


def test_browser_fires_on_coloading() -> None:
    feats = ClientFeatures(
        request_count=10,
        asset_coload_ratio=0.8,
        page_count=5,  # enough pages that the co-load share is real evidence
        ua_looks_like_browser=True,
        static_ratio=0.5,
        ratio_404=0.0,
    )
    signals = BrowserClassifier().evaluate(feats)
    assert signals and signals[0].kind is Kind.BROWSER
    # The co-load signal itself fired -- confidence is above the bare UA floor and the
    # evidence names the sub-resource loading, not just a browser-shaped UA.
    assert signals[0].confidence > 0.45
    assert any("sub-resource" in e for e in signals[0].evidence)


def test_single_page_cascade_scores_coload() -> None:
    # A single HTML page whose sub-resources co-load it (100%) now scores the co-load
    # signal (coload_min_pages = 1). Co-load is referer-linked (#109), so one page's
    # cascade is real evidence rather than the coin flip #115 guarded against, and
    # one-and-done page loads are a large, legitimate share of sessions.
    feats = ClientFeatures(
        request_count=10,
        asset_coload_ratio=1.0,
        page_count=1,
        ua_looks_like_browser=True,
        ratio_404=0.0,
    )
    signals = BrowserClassifier().evaluate(feats)
    assert signals and any("sub-resource" in e for e in signals[0].evidence)


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


def test_polls_feeds_tag_is_behavioural() -> None:
    # The across-the-board feed tag fires on the observed behaviour (requested feed
    # resources), whatever the UA claims -- distinct from the UA-based fetches-feeds. So a
    # browser-UA spoofer that also polls feeds carries it alongside its verdict.
    feats = ClientFeatures(
        request_count=100, feed_requests=40, feed_ratio=0.4, ua_looks_like_browser=True
    )
    tags = classify_client(feats).tags
    assert "polls-feeds" in tags
    assert "fetches-feeds" not in tags  # UA does not name a feed tool


def test_self_referer_on_non_browser_ua_is_not_tagged() -> None:
    # A non-browser UA self-referring isn't faking browser navigation -> no tag.
    feats = ClientFeatures(
        request_count=30,
        ua_looks_like_browser=False,
        self_referer_ratio=1.0,
        user_agent="python-requests/2.31.0",
    )
    assert "forged-referer" not in classify_client(feats).tags


def _www_referer_browser(**kw: object) -> ClientFeatures:
    """A browser-shaped client carrying a same-site www Referer on every request
    (served the apex) -- the www->apex-redirector spoof shape."""
    base: dict[str, object] = dict(
        request_count=200,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.5,  # otherwise a solid browser
        feed_requests=0,
        www_referer_hits=200,
        www_referer_ratio=1.0,
    )
    base.update(kw)
    return ClientFeatures(**base)  # type: ignore[arg-type]


def _apex_referer_browser(**kw: object) -> ClientFeatures:
    """The mirror shape: a browser carrying a same-site bare-apex Referer on every
    request (served www) -- the apex->www-redirector spoof shape."""
    base: dict[str, object] = dict(
        request_count=200,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.5,
        feed_requests=0,
        apex_referer_hits=200,
        apex_referer_ratio=1.0,
    )
    base.update(kw)
    return ClientFeatures(**base)  # type: ignore[arg-type]


def test_impossible_referer_makes_a_browser_spoofed() -> None:
    # On a www-redirector site a same-site www Referer is impossible from a real
    # browser: a residential browser -> spoofed_browser, tagged. This is the #96 catch.
    result = classify_client(_www_referer_browser(), redirect_shadow="www")
    assert result.primary is Kind.SPOOFED_BROWSER
    assert "impossible-referer" in result.tags


def test_impossible_apex_referer_makes_a_browser_spoofed() -> None:
    # The symmetric case: an apex->www redirector, where a bare-apex Referer is the
    # impossible one. Same verdict, driven by the apex-side counter and gate.
    result = classify_client(_apex_referer_browser(), redirect_shadow="apex")
    assert result.primary is Kind.SPOOFED_BROWSER
    assert "impossible-referer" in result.tags


def test_impossible_referer_direction_must_match_the_gate() -> None:
    # A www Referer on an apex-redirector site (and vice versa) is NOT impossible --
    # the tell only fires when the Referer names the redirect-only form.
    assert "impossible-referer" not in classify_client(
        _www_referer_browser(), redirect_shadow="apex"
    ).tags
    assert "impossible-referer" not in classify_client(
        _apex_referer_browser(), redirect_shadow="www"
    ).tags


def test_impossible_referer_needs_a_redirect_shadow() -> None:
    # Same client, but the site redirects neither form (e.g. www serves content):
    # the tell can't fire, so it stays a browser.
    result = classify_client(_www_referer_browser(), redirect_shadow=None)
    assert result.primary is Kind.BROWSER
    assert "impossible-referer" not in result.tags


def test_impossible_referer_below_min_ratio_does_not_fire() -> None:
    # A lone www Referer could be a quirky proxy / extension -- require a real share.
    feats = _www_referer_browser(www_referer_hits=3, www_referer_ratio=0.015)
    result = classify_client(feats, redirect_shadow="www")
    assert result.primary is Kind.BROWSER
    assert "impossible-referer" not in result.tags


def test_impossible_referer_ignores_feed_clients() -> None:
    # Feed pollers that hit www are already handled by feed_ratio -- not additive.
    feats = _www_referer_browser(feed_requests=200, feed_ratio=1.0)
    result = classify_client(feats, redirect_shadow="www")
    assert "impossible-referer" not in result.tags


def test_impossible_referer_does_not_override_a_stronger_signal() -> None:
    # A vuln scanner behind a browser UA that also carries www Referers stays a
    # vuln scanner: the conversion only applies when browser is the winning verdict.
    feats = _www_referer_browser(
        vuln_path_hits=50,
        vuln_path_ratio=0.25,
        ratio_404=0.7,
        distinct_404_targets=20,
    )
    assert classify_client(feats, redirect_shadow="www").primary is Kind.VULN_SCANNER


def test_impossible_referer_reaches_spoofed_from_below_threshold() -> None:
    # A residential browser-UA client with no other classifier support still reaches
    # spoofed_browser: the SpoofedBrowserClassifier fires on the dispositive
    # impossible-referer tell rather than letting it fall to UNKNOWN.
    feats = _www_referer_browser(asset_coload_ratio=0.0)
    result = classify_client(feats, redirect_shadow="www")
    assert result.primary is Kind.SPOOFED_BROWSER
    assert "impossible-referer" in result.tags


def test_plain_costume_residential_stays_unspoofed() -> None:
    # Regression: a browser costume with no www tell on a residential IP keeps its
    # datacenter gate -- it must NOT become spoofed_browser off the back of this work.
    feats = ClientFeatures(
        request_count=200,
        ua_looks_like_browser=True,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
    )
    assert classify_client(feats, redirect_shadow="www").primary is not Kind.SPOOFED_BROWSER


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


def test_lacks_cache_is_tagged() -> None:
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
    assert "lacks-cache" in result.tags
    # The REDbot tool-driver shape: a browser UA that holds no cache and follows no
    # links is a costume, so it now reads as spoofed_browser (issue #100) rather than
    # the older, vaguer automation fallback.
    assert result.primary is Kind.SPOOFED_BROWSER


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
    result = classify_client(feats)
    assert result.primary is Kind.AUTOMATION
    # The fallback's evidence is the whole reason for the verdict -- the same
    # sentence for every such client -- so it's flagged boilerplate, not caption
    # material (a report should show nothing rather than that restatement).
    assert result.boilerplate_lead is True


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


def test_recognised_crawler_is_not_downgraded_to_generic_crawler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A recognised crawler that also crawls broadly (high coverage, follows links, no
    # assets) must keep its specific kind -- the generic crawler classifier's
    # behavioural score must not outrank the recognition. AhrefsSiteAudit was landing
    # in `crawler` (1.00) over `seo_marketing` (0.83) before the deferral gate.
    from agent_census import uas

    feats = ClientFeatures(
        request_count=1492,
        distinct_paths=1200,
        coverage=0.8,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.9,
        ratio_2xx=0.95,
        ua_declares_bot=True,
        ua_empty=False,
        user_agent="Mozilla/5.0 (compatible; SomeKnownBot/1.0; +http://example.com/bot)",
    )
    # Unrecognised: the generic crawler and scraper classifiers own it.
    assert classify_client(feats).primary is Kind.CRAWLER
    # Recognised by UA token: both generic classifiers defer.
    monkeypatch.setattr(uas, "names_known_crawler", lambda ua: True)
    assert not CrawlerClassifier().evaluate(feats)
    assert not ScraperClassifier().evaluate(feats)
    monkeypatch.setattr(uas, "names_known_crawler", lambda ua: False)
    # Recognised by origin AS (a spoofed-UA crawler): crawler must defer here too.
    monkeypatch.setattr(uas, "match_asn_any", lambda asn: "Sberbank")
    assert not CrawlerClassifier().evaluate(feats)


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


def test_safari_age_band_has_a_neutral_middle() -> None:
    # Safari's band is current (fresh) / stale (>=2yr) with a deliberate neutral
    # None in between (~one year behind is normal for OS-bundled Safari).
    from agent_census.uas import _safari_age_band

    assert _safari_age_band(-20.0) is None  # implausibly ahead: no credit
    assert _safari_age_band(0.0) == "current"
    assert _safari_age_band(13.0) == "current"  # upper edge of current
    assert _safari_age_band(18.0) is None  # neutral middle -- neither current nor stale
    assert _safari_age_band(24.0) == "stale"  # two annual versions behind
    assert _safari_age_band(60.0) == "stale"  # never escalates past stale


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
        ClientFeatures(
            request_count=5, ua_empty=False, ua_declares_bot=True, user_agent="FooBot/1.0"
        )
    )
    assert "bot-ua" in unknown.tags and "declares-known-bot" not in unknown.tags


def test_user_triggered_proxy_is_tagged_without_changing_kind() -> None:
    # A "-User" proxy fetches on behalf of a present user: it keeps its category's
    # kind (ai_crawler / search_engine) and is marked with the user-triggered tag.
    ai_user = classify_client(
        ClientFeatures(
            request_count=5,
            ua_empty=False,
            ua_declares_bot=True,
            user_agent="Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
        )
    )
    assert ai_user.primary is Kind.AI_CRAWLER
    assert "user-triggered" in ai_user.tags
    search_user = classify_client(
        ClientFeatures(request_count=5, ua_empty=False, user_agent="YandexUserproxy")
    )
    assert search_user.primary is Kind.SEARCH_ENGINE
    assert "user-triggered" in search_user.tags
    # An autonomous crawler in the same category is not user-triggered.
    autonomous = classify_client(
        ClientFeatures(
            request_count=5,
            ua_empty=False,
            ua_declares_bot=True,
            user_agent="Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
        )
    )
    assert autonomous.primary is Kind.AI_CRAWLER
    assert "user-triggered" not in autonomous.tags


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
    assert "stale-browser-ua" in tags_for(
        "Firefox/100.0", datetime(2024, 6, 1, tzinfo=timezone.utc)
    )
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


def test_one_request_with_no_signal_is_unknown_tagged_singleton() -> None:
    # A single-request client with no strong signal and no machine tell is unknown,
    # carrying the `singleton` tag -- "one request" is a volume fact, not a kind.
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(signals, ClientFeatures(request_count=1), unknown_threshold=0.45)
    assert result.primary is Kind.UNKNOWN
    assert "singleton" in result.tags


def test_one_request_from_datacenter_is_automation_tagged_singleton() -> None:
    signals = [Signal(Kind.BROWSER, 0.3, ("weak",), "browser")]
    result = combine(
        signals, ClientFeatures(request_count=1), datacenter=True, unknown_threshold=0.45
    )
    assert result.primary is Kind.AUTOMATION
    assert "singleton" in result.tags


def test_combiner_one_request_keeps_confident_kind() -> None:
    # One request that clearly matches a kind keeps that kind, not singleton.
    signals = [Signal(Kind.VULN_SCANNER, 0.8, ("probe",), "vuln_scanner")]
    result = combine(signals, ClientFeatures(request_count=1), unknown_threshold=0.45)
    assert result.primary is Kind.VULN_SCANNER


def test_vuln_scanner_outranks_a_stronger_spoof_costume() -> None:
    # A datacenter no-cache costume accumulates a higher spoof score (0.90) than its
    # probing scores as a scanner (0.70); without precedence the scan would read as a
    # mere costume. Probing attack paths is the more actionable verdict, so vuln_scanner
    # wins once it clears the bar -- the costume tells still surface via tags.
    signals = [
        Signal(Kind.SPOOFED_BROWSER, 0.90, ("browser costume",), "spoofed_browser"),
        Signal(Kind.VULN_SCANNER, 0.70, ("44 probe paths",), "vuln_scanner"),
    ]
    result = combine(signals, ClientFeatures(request_count=758), unknown_threshold=0.45)
    assert result.primary is Kind.VULN_SCANNER


def test_below_threshold_vuln_does_not_displace_spoofed() -> None:
    # A whiff of probing that doesn't clear the bar isn't a scanner, so it must not steal
    # the primary verdict from a genuine costume -- the precedence only applies when
    # vuln_scanner itself fires.
    signals = [
        Signal(Kind.SPOOFED_BROWSER, 0.90, ("browser costume",), "spoofed_browser"),
        Signal(Kind.VULN_SCANNER, 0.30, ("one odd path",), "vuln_scanner"),
    ]
    result = combine(signals, ClientFeatures(request_count=758), unknown_threshold=0.45)
    assert result.primary is Kind.SPOOFED_BROWSER


def test_one_request_library_is_automation_not_singleton() -> None:
    # A one-shot library client carries a machine tell, so it's characterisable as
    # automation -- it shouldn't fall into the "too little to tell" singleton bucket.
    feats = ClientFeatures(request_count=1, ua_empty=False, user_agent="curl/8.7.1")
    assert classify_client(feats).primary is Kind.AUTOMATION


def test_one_request_self_declared_bot_is_automation() -> None:
    feats = ClientFeatures(
        request_count=1,
        ua_empty=False,
        ua_declares_bot=True,
        user_agent="MysteryBot/1.0 (+http://example.com/bot)",
    )
    assert classify_client(feats).primary is Kind.AUTOMATION


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
    # Browser UA + hosting IP + no browser behaviour -> spoofed_browser, now produced by
    # the SpoofedBrowserClassifier competing in normal aggregation (datacenter is one
    # weighted tell, not a hard gate). Evidence is in the tags: browser-ua, no-assets, cold.
    result = classify_client(_FAKE_BROWSER, datacenter=True)
    assert result.primary is Kind.SPOOFED_BROWSER
    assert {"browser-ua", "no-assets", "cold", "datacenter"} <= result.tags
    # The classifier reports the specific tells that fired, so the lead is real evidence,
    # not the old boilerplate fallback sentence.
    assert result.boilerplate_lead is False


def test_browser_version_parsing_and_age() -> None:
    from datetime import datetime, timezone

    from agent_census import uas

    assert uas.browser_version("... Chrome/106.0.0.0 Safari/537.36") == ("chrome", 106)
    assert uas.browser_version("... Firefox/121.0") == ("firefox", 121)
    # Edge/Opera ride the Chromium major via their Chrome/ token.
    assert uas.browser_version("... Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0") == (
        "chrome",
        120,
    )
    # Safari reports its Version/ major (not the frozen Safari/605 WebKit build).
    assert uas.browser_version(
        "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML) Version/16.0 Safari/605.1.15"
    ) == ("safari", 16)
    # Non-browsers report nothing.
    assert uas.browser_version("curl/8.0") is None

    # A crafted UA with a multi-thousand-digit version must not crash (int() would
    # raise on Python 3.11+ past the 4300-digit limit); the capture is length-bounded.
    huge = "Mozilla/5.0 Chrome/" + "9" * 100_000 + " Safari/537.36"
    parsed = uas.browser_version(huge)
    assert parsed is not None and parsed[0] == "chrome"

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


def test_rss_declares_bot_only_as_a_whole_word() -> None:
    from agent_census import uas

    # 'rss' is a short token, so it must match as a whole word only -- otherwise
    # it fires inside ordinary product names / surnames like 'Larsson'.
    assert not uas.declares_bot("Mozilla/5.0 (X11) Larsson/1.0")
    assert not uas.declares_bot("Carsson/2.0")
    # A genuine RSS-tool token is still recognised.
    assert uas.declares_bot("Some RSS Reader/1.0")
    assert uas.declares_bot("rss-parser/3.1")


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
    # Declares Googlebot and probes vuln paths: keeps its kind, gets a 'probe-paths'
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
    assert "probe-paths" in result.tags
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
    verification = BotVerification(
        VerificationStatus.VERIFIED,
        resolved_host="x.googlebot.com",
        dns=ChannelVerdict.VERIFIED,
    )
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert "dns-verified" in result.tags
    assert result.primary is Kind.SEARCH_ENGINE


def test_unverified_tag_when_network_check_inconclusive() -> None:
    # Had rdns/range info to check, but it came back inconclusive: surfaced as a tag,
    # the kind/verdict otherwise unchanged.
    feats = ClientFeatures(request_count=5, user_agent="Googlebot/2.1")
    verification = BotVerification(
        VerificationStatus.UNVERIFIED, network_checked=True, dns=ChannelVerdict.UNVERIFIED
    )
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert "dns-unverified" in result.tags
    assert "dns-verified" not in result.tags
    assert result.primary is Kind.SEARCH_ENGINE


def test_unverified_tag_on_impersonator_with_network_check() -> None:
    # A definitive rdns/range failure: still the impersonator kind, now also tagged
    # so the verification failure is visible alongside it.
    feats = ClientFeatures(request_count=5, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
    verification = BotVerification(
        VerificationStatus.IMPERSONATOR,
        resolved_host="x.evil.example",
        network_checked=True,
        dns=ChannelVerdict.VIOLATION,
    )
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert result.primary is Kind.IMPERSONATOR  # outcome unchanged
    assert "dns-violation" in result.tags


def test_no_unverified_tag_when_no_network_info() -> None:
    # UNVERIFIED with nothing to check against (no rdns/range info, no ASN) -- not the
    # same as a check that ran and didn't confirm, so it carries no tag.
    feats = ClientFeatures(request_count=5, user_agent="Googlebot/2.1")
    verification = BotVerification(VerificationStatus.UNVERIFIED, network_checked=False)
    signals = [Signal(Kind.SEARCH_ENGINE, 0.8, ("declares Googlebot",), "search_engine")]
    result = combine(signals, feats, verification=verification)
    assert "dns-unverified" not in result.tags
    assert "ip-unverified" not in result.tags


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
    storm = ClientFeatures(request_count=30, ratio_404=0.9, distinct_404_targets=20)
    assert "404-storm" in classify_client(storm).tags
    exotic = ClientFeatures(request_count=5, exotic_method_count=3)
    assert "exotic-method" in classify_client(exotic).tags
    metro = ClientFeatures(request_count=20, rate_regularity=0.05)
    assert "metronomic" in classify_client(metro).tags
    # A plain client earns none of them.
    plain = ClientFeatures(request_count=20, ratio_404=0.0, rate_regularity=0.8)
    assert not ({"404-storm", "exotic-method", "metronomic"} & classify_client(plain).tags)


def test_often_forbidden_tag_flags_a_blocked_client() -> None:
    # The server refusing most of a client's requests (403) is its own verdict that the
    # client is misbehaving -- surfaced as a tag.
    blocked = ClientFeatures(request_count=20, status_counts={403: 19, 200: 1})
    assert "often-forbidden" in classify_client(blocked).tags
    # One incidental 403 (a single protected path) amid normal traffic doesn't trip it.
    incidental = ClientFeatures(request_count=100, status_counts={200: 99, 403: 1})
    assert "often-forbidden" not in classify_client(incidental).tags
    # Nor does a small sample, even if all forbidden -- too little to characterise.
    tiny = ClientFeatures(request_count=2, status_counts={403: 2})
    assert "often-forbidden" not in classify_client(tiny).tags


def test_tag_evidence_covers_every_derived_tag() -> None:
    # Inspect mode shows the measurement behind each tag, so derive_tag_evidence
    # must explain exactly the tags derive_tags emits -- no tag without a reason,
    # no orphan reason. Exercise a feature-rich client that earns many tags at once.
    from agent_census.classify.tags import derive_tag_evidence, derive_tags

    feats = ClientFeatures(
        request_count=40,
        distinct_paths=10,
        status_counts={200: 40},
        rate_regularity=0.05,
        head_ratio=0.5,
        ua_empty=False,
        user_agent="python-requests/2.31.0",
        ua_declares_bot=False,
        ua_count_for_ip=6,
    )
    evidence = derive_tag_evidence(feats, None, None, datacenter=True)
    assert set(evidence) == derive_tags(feats, None, None, datacenter=True)
    # Every reason is a non-empty, concrete string (cites the measurement).
    assert evidence and all(why.strip() for why in evidence.values())
    assert "lacks-cache" in evidence and "304" in evidence["lacks-cache"]


def test_classification_carries_tag_evidence_only_when_signals_kept() -> None:
    # tag_evidence is inspect-only detail held on the same terms as all_signals:
    # populated when keep_signals, dropped on the bulk analyze path.
    feats = ClientFeatures(request_count=20, rate_regularity=0.05)
    kept = combine([], feats, keep_signals=True)
    dropped = combine([], feats, keep_signals=False)
    assert kept.tags == dropped.tags  # the tags themselves are unaffected
    assert dict(kept.tag_evidence).keys() == set(kept.tags)
    assert dropped.tag_evidence == ()


def test_aggregate_suppresses_cadence_tag() -> None:
    # On a multi-client display fold the interleaved arrivals carry no cadence, so
    # the metronomic/bursty/steady tag is suppressed -- but only that. The other
    # fingerprint dimensions (here a generic UA) are per-request and still apply.
    from agent_census.classify.tags import CADENCE_TAGS, derive_tags

    feats = ClientFeatures(
        request_count=20, ua_empty=False, rate_regularity=0.05, user_agent="python-requests/2.31.0"
    )
    assert "metronomic" in derive_tags(feats, None, None)
    aggregated = derive_tags(feats, None, None, aggregate=True)
    assert not (CADENCE_TAGS & aggregated)
    assert "generic-ua" in aggregated  # a non-cadence fingerprint tag is untouched
    assert "metronomic" not in classify_client(feats, aggregate=True).tags


def test_uses_head_tag() -> None:
    signals = [Signal(Kind.MONITOR, 0.6, ("monitors",), "monitor")]
    heading = ClientFeatures(request_count=10, head_ratio=0.5)
    assert "uses-HEAD" in combine(signals, heading).tags
    # Incidental HEAD (at or below the bar) is not tagged.
    incidental = ClientFeatures(request_count=10, head_ratio=0.1)
    assert "uses-HEAD" not in combine(signals, incidental).tags


def test_304_lifts_browser_and_feed_reader_confidence() -> None:
    base = dict(
        request_count=10,
        asset_coload_ratio=0.6,
        page_count=5,
        ua_looks_like_browser=True,
        ratio_404=0.0,
    )
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
    facebook = classify_client(
        ClientFeatures(request_count=2, user_agent="facebookexternalhit/1.1")
    )
    assert facebook.primary is Kind.SOCIAL_PREVIEW


def test_known_bot_match_without_declared_name_carries_no_agent_name() -> None:
    # Googlebot's agents/search_engine.toml entry declares no `name`, so the
    # classification carries no agent identity beyond the UA-based classification.
    result = classify_client(
        ClientFeatures(request_count=4, user_agent="Mozilla/5.0 (compatible; Googlebot/2.1)")
    )
    assert result.agent_name is None
    # But its evidence[0] is still flagged as boilerplate (it's just the identity
    # declaration) regardless of whether `name` is set -- a report caption should
    # skip it either way, not just when there's a declared name to show instead.
    assert result.boilerplate_lead is True


def test_known_bot_match_carries_declared_name_to_classification() -> None:
    # agents/ai_crawler.toml's Colossio entry declares a `name` distinct from its
    # ua_substring -- the classifier should surface the name, not the raw token.
    result = classify_client(
        ClientFeatures(request_count=3, user_agent="colossio-crawler/1.0")
    )
    assert result.primary is Kind.AI_CRAWLER
    assert result.agent_name == "Colossio"


def test_known_bot_asn_match_carries_agent_name_to_classification() -> None:
    from agent_census.classify.ai_crawler import AiCrawlerClassifier

    # agents/ai_crawler.toml's Sberbank entry is asn_primary: recognised by AS
    # number alone (rotating spoofed-browser UAs) -- only the operator label.
    signals = AiCrawlerClassifier().evaluate(
        ClientFeatures(request_count=3, user_agent="Mozilla/5.0", as_number="AS35237")
    )
    assert len(signals) == 1
    assert signals[0].agent_name == "Sberbank"


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
    result = classify_client(cfnet)
    assert result.primary is Kind.APP
    # It's the same evidence for every App client -- naming the platform stack,
    # never a fact specific to this one -- so a report caption should skip it.
    assert result.boilerplate_lead is True
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
