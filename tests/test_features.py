"""Tests for per-client feature extraction."""

from __future__ import annotations

from agent_census.features import extract_features

from .factories import entry


def test_empty_input() -> None:
    feats = extract_features([])
    assert feats.request_count == 0


def test_volume_and_bandwidth() -> None:
    feats = extract_features(
        [entry("/a", bytes_sent=100), entry("/b", bytes_sent=300, offset=1)]
    )
    assert feats.request_count == 2
    assert feats.total_bytes == 400
    assert feats.mean_bytes == 200


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


def test_regular_timing_low_cv() -> None:
    entries = [entry("/", offset=i * 60) for i in range(6)]
    feats = extract_features(entries)
    assert feats.rate_regularity is not None
    assert feats.rate_regularity < 0.01
    assert feats.inter_arrival_median == 60.0


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
