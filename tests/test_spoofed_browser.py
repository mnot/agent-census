"""The browser-spoof score (classify/spoofed_browser.py, issue #100).

Two layers: behavioural tests through the public ``classify_client`` asserting the final
``Kind`` (so they exercise the classifier, the combiner's browser-vote suppression, and
priority together), and unit tests on ``SpoofedBrowserClassifier`` itself via its
context-aware entry point.

The weights are calibrated in data/tuning/spoofed_browser.toml; these tests pin the four
calibration anchors (impossible-referer alone; datacenter+costume; residential
costume+one-strong-tell; residential costume alone stays a browser) plus the exclusions
found on the live digest (known agents, feed-fetchers, probers).
"""

from __future__ import annotations

from agent_census.classify import classify_client
from agent_census.classify.spoofed_browser import SpoofedBrowserClassifier
from agent_census.model import ClassifyContext, ClientFeatures, Kind


def _browser_costume(**kw: object) -> ClientFeatures:
    """A browser-UA client showing none of a browser's behaviour: it fetches HTML pages
    but co-loads none of their sub-resources and follows no on-site links. The base
    costume shape -- on its own too weak to be called spoofed (the false-positive guard),
    but a spoofed_browser the moment a corroborating tell is added."""
    base: dict[str, object] = dict(
        request_count=200,
        ua_looks_like_browser=True,
        ua_empty=False,
        page_count=50,
        asset_coload_ratio=0.0,
        referer_following_ratio=0.0,
        feed_requests=0,
    )
    base.update(kw)
    return ClientFeatures(**base)  # type: ignore[arg-type]


# ---- Calibration anchors (behavioural) ------------------------------------------------


def test_datacenter_costume_is_spoofed() -> None:
    # datacenter (0.30) + costume (0.15 + 0.15) = 0.60. Preserves the pre-#100 catch,
    # with datacenter now a weight rather than a hard gate.
    assert classify_client(_browser_costume(), datacenter=True).primary is Kind.SPOOFED_BROWSER


def test_impossible_referer_residential_is_spoofed() -> None:
    # The dispositive tell reaches spoofed_browser with no datacenter origin (issue #101).
    feats = _browser_costume(www_referer_hits=200, www_referer_ratio=1.0)
    result = classify_client(feats, redirect_shadow="www")
    assert result.primary is Kind.SPOOFED_BROWSER
    assert "impossible-referer" in result.tags


def test_residential_costume_alone_stays_browser() -> None:
    # The false-positive guard: costume tells alone (0.30) do not clear the bar, so a
    # referer-stripping privacy browser is not mislabelled. This is the anchor that keeps
    # datacenter-decoupling safe.
    assert classify_client(_browser_costume()).primary is not Kind.SPOOFED_BROWSER


def test_residential_costume_plus_head_heavy_is_spoofed() -> None:
    # costume (0.30) + HEAD-heavy (0.30) = 0.60, on a residential IP.
    feats = _browser_costume(head_ratio=0.8, method_counts={"HEAD": 160, "GET": 40})
    assert classify_client(feats).primary is Kind.SPOOFED_BROWSER


def test_residential_costume_plus_no_cache_is_spoofed() -> None:
    # costume + holds-no-cache at volume (0.30 + 0.30). Previously landed on AUTOMATION.
    feats = _browser_costume(request_count=600, distinct_paths=1, status_counts={200: 600})
    assert feats.holds_no_cache
    assert classify_client(feats).primary is Kind.SPOOFED_BROWSER


def test_residential_costume_plus_forged_referer_is_spoofed() -> None:
    # costume + fabricated referers (Referer == the requested URL).
    feats = _browser_costume(self_referer_ratio=0.9, referer_count=200)
    assert classify_client(feats).primary is Kind.SPOOFED_BROWSER


def test_genuine_browser_is_never_spoofed() -> None:
    # A real browser co-loads assets, follows links, and revalidates: it trips no spoof
    # tell, so the classifier never fires and it stays a browser, datacenter or not.
    feats = ClientFeatures(
        request_count=200,
        ua_looks_like_browser=True,
        ua_empty=False,
        page_count=50,
        asset_coload_ratio=0.6,
        referer_following_ratio=0.4,
        referer_count=180,
        status_counts={200: 180, 304: 20},
    )
    assert classify_client(feats).primary is Kind.BROWSER
    assert classify_client(feats, datacenter=True).primary is not Kind.SPOOFED_BROWSER


# ---- Exclusions / precedence found on the live digest ---------------------------------


def test_probing_browser_ua_stays_vuln_scanner() -> None:
    # A browser-UA client that probes attack paths is a vuln_scanner, not a spoofed
    # browser: probing is not a spoof-score tell, and vuln_scanner both scores higher and
    # outranks spoofed_browser in the tie-break. (Guards against the spoof score stealing
    # probers.)
    feats = _browser_costume(
        vuln_path_hits=30, vuln_path_ratio=0.15, ratio_404=0.7, distinct_404_paths=20
    )
    assert classify_client(feats).primary is Kind.VULN_SCANNER


def test_feed_dominant_browser_ua_is_not_spoofed() -> None:
    # A feed-*dominant* client wearing a plain browser UA is caught by feed behaviour, not
    # repainted as a costume: the spoof classifier gates on the feed-dominant share.
    feats = _browser_costume(head_ratio=0.8, feed_requests=200, feed_ratio=1.0)
    assert classify_client(feats).primary is not Kind.SPOOFED_BROWSER


def test_minority_feed_spoofer_is_still_caught() -> None:
    # A spoofer that ALSO polls feeds, but only as a minority of its traffic (below the
    # feed-dominant gate), is a costume, not a feed reader -- it must still be spoofed. This
    # is the OneHostPlanet case: forged referers + no cache + hosting, yet ~40% feeds.
    feats = _browser_costume(
        feed_requests=40, feed_ratio=0.4, self_referer_ratio=0.9, referer_count=200
    )
    assert classify_client(feats).primary is Kind.SPOOFED_BROWSER


def test_near_line_feed_poller_that_renders_stays_browser() -> None:
    # The near-line false-positive guard: a real browser with a feed extension, just under
    # the feed-dominant gate (so spoof-eligible), but it co-loads its pages' sub-resources.
    # The co-load guard suppresses its cold tells and it has no active tell, so it scores ~0
    # and stays a browser -- exactly the case the fix must not break.
    feats = ClientFeatures(
        request_count=100,
        feed_requests=49,
        feed_ratio=0.49,
        ua_looks_like_browser=True,
        ua_empty=False,
        page_count=50,
        asset_coload_ratio=0.6,
        referer_following_ratio=0.4,
        referer_count=90,
        status_counts={200: 90, 304: 10},
    )
    assert classify_client(feats).primary is Kind.BROWSER


# ---- Classifier unit tests ------------------------------------------------------------


def _confidence(feats: ClientFeatures, **kw: object) -> float:
    ctx = ClassifyContext(
        datacenter=bool(kw.get("datacenter", False)),
        redirect_shadow=kw.get("redirect_shadow"),  # type: ignore[arg-type]
    )
    signals = SpoofedBrowserClassifier().evaluate_in_context(feats, ctx)
    return max((s.confidence for s in signals), default=0.0)


def test_datacenter_is_a_weight_not_a_gate() -> None:
    # Same features fire residentially (a weight, not an on/off gate) and score strictly
    # higher from a datacenter origin.
    feats = _browser_costume(head_ratio=0.8)
    assert _confidence(feats, datacenter=True) > _confidence(feats) > 0.0


def test_tells_accumulate() -> None:
    # Two corroborating tells outscore one -- the whole point of the accumulation model.
    one = _browser_costume(head_ratio=0.8)
    two = _browser_costume(head_ratio=0.8, self_referer_ratio=0.9, referer_count=200)
    assert _confidence(two) > _confidence(one)


def test_impossible_referer_is_dispositive_alone() -> None:
    # An otherwise solid browser (co-loads, follows links) that carries the impossible
    # Referer still fires on that tell alone.
    feats = ClientFeatures(
        request_count=200,
        ua_looks_like_browser=True,
        ua_empty=False,
        page_count=50,
        asset_coload_ratio=0.5,
        referer_following_ratio=0.4,
        feed_requests=0,
        www_referer_hits=200,
        www_referer_ratio=1.0,
    )
    assert _confidence(feats, redirect_shadow="www") >= 0.45


def test_known_agent_never_fires() -> None:
    feats = _browser_costume(
        user_agent="Feedly/1.0 (+http://www.feedly.com/fetcher.html)",
        ua_looks_like_browser=False,
        feed_requests=0,
        head_ratio=0.8,
    )
    assert _confidence(feats) == 0.0


def test_feed_fetcher_never_fires() -> None:
    feats = _browser_costume(head_ratio=0.8, feed_requests=200, feed_ratio=1.0)
    assert _confidence(feats) == 0.0
