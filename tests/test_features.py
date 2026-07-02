"""Tests for per-client feature extraction."""

from __future__ import annotations

import pytest

from agent_census.features import extract_features

from .factories import entry


def test_empty_input() -> None:
    feats = extract_features([])
    assert feats.request_count == 0


def test_as_identity_captured_from_env_fields() -> None:
    # MaxMind %{MM_ASORG}e / %{MM_ASN}e land in extra; first non-empty wins.
    feats = extract_features(
        [
            entry("/a", extra={"env:MM_ASORG": "Amazon.com, Inc.", "env:MM_ASN": "16509"}),
            entry("/b", offset=1, extra={"env:MM_ASORG": "Amazon.com, Inc."}),
        ]
    )
    assert feats.as_org == "Amazon.com, Inc."
    assert feats.as_number == "16509"


def test_as_identity_absent_without_env_fields() -> None:
    feats = extract_features([entry("/a"), entry("/b", offset=1)])
    assert feats.as_org is None
    assert feats.as_number is None


def test_as_number_kept_when_later_line_lacks_asn() -> None:
    # ASN-only log (no ASORG). A later line whose extra is non-empty but carries
    # no ASN field must not clobber the number already captured.
    feats = extract_features(
        [
            entry("/a", extra={"env:MM_ASN": "16509", "port:p": "443"}),
            entry("/b", offset=1, extra={"port:p": "443"}),
        ]
    )
    assert feats.as_org is None
    assert feats.as_number == "16509"


def test_as_number_filled_from_later_line() -> None:
    # Number absent on the first line but present later: capture it when it appears.
    feats = extract_features(
        [
            entry("/a", extra={"env:MM_ASORG": "Amazon.com, Inc."}),
            entry("/b", offset=1, extra={"env:MM_ASN": "16509"}),
        ]
    )
    assert feats.as_org == "Amazon.com, Inc."
    assert feats.as_number == "16509"


def test_volume_and_bandwidth() -> None:
    feats = extract_features(
        [entry("/a", bytes_sent=100), entry("/b", bytes_sent=300, offset=1)]
    )
    assert feats.request_count == 2
    assert feats.total_bytes == 400
    assert feats.mean_bytes == 200


def test_negative_bytes_are_clamped() -> None:
    # A malformed/adversarial bytes field must not push total_bytes negative.
    feats = extract_features(
        [entry("/a", bytes_sent=100), entry("/b", bytes_sent=-500, offset=1)]
    )
    assert feats.total_bytes == 100


def test_status_ratios_and_404_paths() -> None:
    entries = [
        entry("/x", status=404, offset=0),
        entry("/y", status=404, offset=1),
        entry("/z", status=200, offset=2),
    ]
    feats = extract_features(entries)
    assert feats.ratio_404 > 0.6
    assert feats.distinct_404_paths == 2


def test_asset_coloading_detected() -> None:
    entries = [
        entry("/", status=200, offset=0),
        entry("/style.css", status=200, offset=1),
        entry("/app.js", status=200, offset=2),
    ]
    feats = extract_features(entries)
    assert feats.asset_coload_ratio > 0.0
    assert feats.static_ratio > 0.0


def test_no_coloading_for_scraper_pattern() -> None:
    entries = [entry(f"/article/{i}", status=200, offset=i) for i in range(10)]
    feats = extract_features(entries)
    assert feats.asset_coload_ratio == 0.0
    assert feats.distinct_paths == 10


def test_vuln_and_traversal_signals() -> None:
    entries = [
        entry("/.env", status=404, offset=0),
        entry("/wp-login.php", status=404, offset=0.1),
        entry("/", status=404, query="a=../../etc/passwd", offset=0.2),
    ]
    feats = extract_features(entries)
    assert feats.vuln_path_hits >= 2
    assert feats.traversal_hits >= 1


def test_contextual_path_counts_only_when_absent() -> None:
    # /wp-login.php is a real path on a WordPress site: a 200 means it belongs here
    # (not a probe), a 404 means the client is guessing at WordPress we don't run.
    served = extract_features([entry("/wp-login.php", status=200, offset=0)])
    assert served.vuln_path_hits == 0
    missing = extract_features([entry("/wp-login.php", status=404, offset=0)])
    assert missing.vuln_path_hits == 1


def test_contextual_path_existing_but_gated_not_a_probe() -> None:
    # 401/403 mean the path exists (just access-controlled) -- still site surface.
    for code in (401, 403, 301):
        feats = extract_features([entry("/wp-admin", status=code, offset=0)])
        assert feats.vuln_path_hits == 0, code


def test_always_probe_path_counts_regardless_of_status() -> None:
    # A 200 on /.env is the leaked-secret case -- the most alarming, never benign.
    for code in (200, 403, 404):
        feats = extract_features([entry("/.env", status=code, offset=0)])
        assert feats.vuln_path_hits == 1, code


def test_submit_path_hits_count_only_posts() -> None:
    # A submission endpoint is a spam tell only when *submitted to*. A benign GET
    # to a path that matches a bare substring (/contact, /comments/feed) must not
    # count; a POST to a real submission endpoint must.
    assert extract_features([entry("/contact", offset=0)]).submit_path_hits == 0
    assert extract_features([entry("/comments/feed", offset=0)]).submit_path_hits == 0
    posted = extract_features([entry("/wp-comments-post.php", method="POST", offset=0)])
    assert posted.submit_path_hits == 1


def test_encoding_evasion_signal() -> None:
    # Double-encoded traversal (WAF-bypass) is counted as evasion, not plain
    # traversal: %252e%252e does not contain the single-encoded %2e%2e marker.
    entries = [
        entry("/", status=404, query="file=%252e%252e%252fetc%252fpasswd", offset=0),
    ]
    feats = extract_features(entries)
    assert feats.evasion_hits >= 1
    assert feats.traversal_hits == 0


def test_regular_timing_low_cv() -> None:
    entries = [entry("/", offset=i * 60) for i in range(6)]
    feats = extract_features(entries)
    assert feats.rate_regularity is not None
    assert feats.rate_regularity < 0.01
    assert feats.inter_arrival_median == 60.0


def test_out_of_order_timestamp_keeps_baseline_monotonic() -> None:
    # An earlier-than-previous timestamp (clock skew, interleaved workers) is
    # skipped, and the baseline must not retreat to it -- otherwise the next
    # in-order gap is measured from the wrong point and over-reported.
    from agent_census.features import FeatureAccumulator

    acc = FeatureAccumulator()
    for off in (0, 120, 60, 180):  # 60 arrives late, after 120
        acc.add(entry("/p", offset=off))
    feats = acc.finalize()
    # Deltas: 0->120 and 120->180; the late 60 is dropped, not used as a baseline
    # (which would have measured 120->? as 180-60=120 and hidden the real 60 gap).
    assert feats.inter_arrival_min == 60.0
    assert feats.inter_arrival_mean == pytest.approx(90.0)


def test_high_volume_timing_is_bounded_but_accurate() -> None:
    # Past the exact-delta buffer the accumulator switches to a fixed histogram,
    # so it holds no per-request timing array. Exact stats (mean/min/CV) survive;
    # the binned quantiles land in the right ballpark.
    from agent_census.features import _IAT_BUF_CAP, FeatureAccumulator

    acc = FeatureAccumulator()
    for i in range(_IAT_BUF_CAP * 3):
        acc.add(entry("/p", offset=10 * i))
    feats = acc.finalize()

    assert acc._iat_hist is not None  # pylint: disable=protected-access
    assert acc._iat_buf is None  # pylint: disable=protected-access
    assert feats.inter_arrival_min == 10.0
    assert feats.inter_arrival_mean == pytest.approx(10.0)
    assert feats.rate_regularity == pytest.approx(0.0, abs=1e-9)
    assert feats.inter_arrival_median == pytest.approx(10.0, rel=0.3)
    assert feats.peak_requests_per_minute >= 6  # ~6 requests per 60s minute


def test_self_referential_referer_not_counted_as_following() -> None:
    # Referer == the requested URL (apex or www): fabricated, not link-following.
    entries = [
        entry("/blog/index.atom", referer="https://mnot.net/blog/index.atom", offset=0),
        entry("/blog/index.atom", referer="https://www.mnot.net/blog/index.atom", offset=1),
        entry("/", referer="https://mnot.net/", offset=2),
    ]
    feats = extract_features(entries)
    assert feats.self_referer_ratio == 1.0
    assert feats.referer_following_ratio == 0.0


def test_referer_following_ratio() -> None:
    entries = [
        entry("/", offset=0),
        entry("/about", referer="http://example.com/", offset=1),
        entry("/contact", referer="http://example.com/about", offset=2),
    ]
    feats = extract_features(entries)
    assert feats.referer_following_ratio == 1.0


def test_ua_count_passed_through() -> None:
    feats = extract_features([entry("/")], ua_count_for_ip=7)
    assert feats.ua_count_for_ip == 7


def test_feed_requests_by_filename() -> None:
    entries = [
        entry("/blog/feed/", offset=0),
        entry("/index.rss", offset=1),
        entry("/atom.xml", offset=2),
        entry("/about", offset=3),
    ]
    feats = extract_features(entries)
    assert feats.feed_requests == 3
    assert feats.feed_ratio == 0.75


def test_feed_token_must_be_a_whole_filename_part() -> None:
    # The feed tokens match a whole dot/dash/underscore part, not a bare substring,
    # so ordinary pages that merely contain "feed"/"atom"/"rss" don't read as feeds.
    entries = [
        entry("/anatomy.html", offset=0),  # 'atom' inside 'anatomy'
        entry("/feedback/", offset=1),  # 'feed' inside 'feedback'
        entry("/rss.xml", offset=2),  # a real feed -- 'rss' is a whole part
        entry("/index.xml", offset=3),  # token-less feed recognised as a stopgap
    ]
    feats = extract_features(entries)
    assert feats.feed_requests == 2


def test_feed_requests_by_content_type() -> None:
    from agent_census.model import LogEntry

    e = LogEntry(
        line_no=1,
        remote_host="1.2.3.4",
        path="/subscribe",
        status=200,
        extra={"out:Content-Type": "application/atom+xml; charset=utf-8"},
    )
    feats = extract_features([e])
    assert feats.feed_requests == 1


def test_request_buckets_spread_over_span() -> None:
    # 10 requests in the first minute, 10 in the eleventh: the cadence histogram
    # puts them at opposite ends of its fixed-width axis, nothing in between.
    entries = [entry("/a", offset=float(i)) for i in range(10)]
    entries += [entry("/b", offset=600.0 + i) for i in range(10)]
    feats = extract_features(entries)
    assert len(feats.request_buckets) == 40
    assert feats.request_buckets[0] == 10
    assert feats.request_buckets[-1] == 10
    assert sum(feats.request_buckets) == 20
    assert sum(feats.request_buckets[1:-1]) == 0


def test_request_buckets_even_over_long_span() -> None:
    # One request per minute across a span far longer than the bucket count: the
    # bins are equal-width, so every bucket fills -- including the last. Scaling by
    # the last index instead of the count would starve the final bin to a single
    # minute; this guards that regression.
    entries = [entry("/a", offset=float(i * 60)) for i in range(400)]
    feats = extract_features(entries)
    assert len(feats.request_buckets) == 40
    assert all(feats.request_buckets), "every equal-width bin should be populated"
    assert max(feats.request_buckets) - min(feats.request_buckets) <= 1  # evenly spread
    assert sum(feats.request_buckets) == 400


def test_request_buckets_empty_for_single_minute_burst() -> None:
    # Every request inside one minute: no cadence to show at minute resolution.
    feats = extract_features([entry("/a", offset=float(i)) for i in range(30)])
    assert feats.request_buckets == ()


def test_request_buckets_empty_without_requests() -> None:
    assert extract_features([]).request_buckets == ()


def test_iat_bucket_handles_non_finite_deltas() -> None:
    # int(math.log10(inf)) / int(nan) would raise; the guard must fail safe.
    from agent_census.features import _iat_bucket

    assert _iat_bucket(float("inf")) == 0
    assert _iat_bucket(float("nan")) == 0
    assert _iat_bucket(-1.0) == 0
