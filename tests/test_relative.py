"""Tests for site-relative magnitude tags (classify/relative.py, issue #8)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_census.classify.relative import (
    MetricThreshold,
    ReferenceCalibration,
    RelativeParams,
    is_reference_browser,
    load_relative_tags,
    make_collector,
    parse_relative_tags,
    relative_tags,
    tag_profile,
)
from agent_census.errors import ConfigError
from agent_census.model import (
    Classification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
)


def browser(rate: int = 10, *, count: int = 50) -> ClientFeatures:
    """A high-confidence reference browser, parametric on its peak rate."""
    return ClientFeatures(
        request_count=count,
        ua_looks_like_browser=True,
        page_count=10,
        asset_coload_ratio=0.7,
        status_counts={200: count - 1, 304: 1},
        referer_count=10,
        referer_following_ratio=0.5,
        peak_requests_per_minute=rate,
    )


# --------------------------------------------------------------- reference predicate


def test_reference_browser_via_cache() -> None:
    assert is_reference_browser(browser())


def test_reference_browser_via_link_following() -> None:
    # No 304, but it co-loads assets and follows links -> still a real browser.
    f = replace(browser(), status_counts={200: 50})
    assert is_reference_browser(f)


def test_fake_browser_is_not_reference() -> None:
    # A browser UA that never co-loads assets and never follows a referer: a costume.
    f = replace(browser(), asset_coload_ratio=0.0, referer_following_ratio=0.0)
    assert not is_reference_browser(f)


def test_non_browser_ua_is_not_reference() -> None:
    assert not is_reference_browser(replace(browser(), ua_looks_like_browser=False))


def test_too_few_requests_is_not_reference() -> None:
    assert not is_reference_browser(browser(count=3))


# ------------------------------------------------------------------- calibration


def _calibrate(rates: list[int], params: RelativeParams) -> ReferenceCalibration:
    collector = make_collector()
    for rate in rates:
        collector.observe(browser(rate))
    return collector.calibrate(params)


PARAMS = RelativeParams(
    margin=3.0, min_reference=30, floors={"rate": 60.0, "bytes": 0.0, "breadth": 0.0, "duration": 0.0}
)


def test_thin_pool_falls_back_to_floor() -> None:
    cal = _calibrate([10] * 5, PARAMS)
    th = cal.threshold("browsers", "rate")
    assert th is not None
    assert th.fallback is True
    assert th.relative is None
    assert th.value == 60.0  # the absolute floor
    assert cal.warning() is not None and "5 high-confidence" in cal.warning()


def test_full_pool_uses_relative_threshold() -> None:
    # 40 browsers, rates 5..24; p95 (log scale) x3 clears the floor of 60.
    cal = _calibrate(list(range(5, 25)) * 2, PARAMS)
    th = cal.threshold("browsers", "rate")
    assert th is not None
    assert th.fallback is False
    assert th.relative is not None and th.value == th.relative
    assert th.value > 60.0
    assert cal.warning() is None


def test_relative_threshold_floored_when_browsers_are_quiet() -> None:
    # A site whose real browsers are all slow: relative gate computes a tiny value,
    # but the absolute floor keeps the tag meaningful.
    cal = _calibrate([2] * 40, PARAMS)
    th = cal.threshold("browsers", "rate")
    assert th is not None and th.fallback is False and th.value == 60.0


# --------------------------------------------------------------------- tagging


def test_high_rate_tagged_above_threshold() -> None:
    cal = _calibrate([10] * 5, PARAMS)  # thin -> floor 60
    assert relative_tags(browser(100), Kind.UNKNOWN, load_relative_tags(), cal) == frozenset(
        {"high-rate"}
    )


def test_below_floor_not_tagged() -> None:
    cal = _calibrate([10] * 5, PARAMS)
    assert relative_tags(browser(50), Kind.UNKNOWN, load_relative_tags(), cal) == frozenset()


def test_low_volume_client_not_tagged() -> None:
    # Insufficient data: a near-singleton with a huge instantaneous rate is gated out.
    f = ClientFeatures(request_count=3, peak_requests_per_minute=10_000)
    cal = _calibrate([10] * 5, PARAMS)
    assert relative_tags(f, Kind.UNKNOWN, load_relative_tags(), cal) == frozenset()


def test_metric_not_in_config_not_tagged() -> None:
    # The default config only emits `rate`; a high byte volume earns nothing yet.
    cal = _calibrate([10] * 5, PARAMS)
    f = replace(browser(10), total_bytes=10**12)
    assert "high-bytes" not in relative_tags(f, Kind.BROWSER, load_relative_tags(), cal)


def test_tag_profile_preserves_existing_tags() -> None:
    cal = _calibrate([10] * 5, PARAMS)
    profile = ClientProfile(
        client_id=ClientId(ip="192.0.2.9"),
        entries=(),
        features=browser(100),
        classification=Classification(primary=Kind.UNKNOWN, confidence=0.5, tags=frozenset({"datacenter"})),
    )
    tagged = tag_profile(profile, load_relative_tags(), cal)
    assert tagged.classification.tags == frozenset({"datacenter", "high-rate"})


def test_tag_profile_noop_returns_same_object() -> None:
    cal = _calibrate([10] * 5, PARAMS)
    profile = ClientProfile(
        client_id=ClientId(ip="192.0.2.9"),
        entries=(),
        features=browser(10),  # below floor
        classification=Classification(primary=Kind.UNKNOWN, confidence=0.5),
    )
    assert tag_profile(profile, load_relative_tags(), cal) is profile


# ----------------------------------------------------------------- config loading


def test_bundled_config_loads() -> None:
    cfg = load_relative_tags()
    assert cfg.params.margin == 3.0
    assert cfg.params.min_reference == 30
    assert cfg.params.floors["rate"] == 60.0
    assert cfg.for_kind(Kind.BROWSER).metrics == ("rate",)
    assert cfg.for_kind(Kind.UNKNOWN).reference == "browsers"


def _good() -> dict[str, object]:
    return {
        "params": {
            "margin": 3.0,
            "min_reference": 30,
            "floor_rate": 60,
            "floor_bytes": 1,
            "floor_breadth": 1,
            "floor_duration": 1,
        },
        "default": {"reference": "browsers", "tags": ["rate"]},
    }


def test_parse_accepts_kind_override() -> None:
    data = _good()
    data["kind"] = [{"kind": "unknown", "tags": ["rate", "bytes"]}]
    cfg = parse_relative_tags(data)
    assert cfg.for_kind(Kind.UNKNOWN).metrics == ("rate", "bytes")
    assert cfg.for_kind(Kind.BROWSER).metrics == ("rate",)  # falls back to default


def test_parse_rejects_unknown_metric() -> None:
    data = _good()
    data["default"] = {"tags": ["nope"]}
    with pytest.raises(ConfigError, match="unknown metric"):
        parse_relative_tags(data)


def test_parse_rejects_unknown_reference() -> None:
    data = _good()
    data["default"] = {"reference": "robots", "tags": ["rate"]}
    with pytest.raises(ConfigError, match="reference"):
        parse_relative_tags(data)


def test_parse_rejects_unknown_kind() -> None:
    data = _good()
    data["kind"] = [{"kind": "wombat", "tags": ["rate"]}]
    with pytest.raises(ConfigError, match="unknown kind"):
        parse_relative_tags(data)


def test_parse_rejects_missing_param() -> None:
    data = _good()
    del data["params"]["floor_rate"]  # type: ignore[union-attr]
    with pytest.raises(ConfigError, match="missing"):
        parse_relative_tags(data)


def test_parse_rejects_unexpected_top_level_key() -> None:
    data = _good()
    data["bogus"] = 1
    with pytest.raises(ConfigError, match="unexpected top-level"):
        parse_relative_tags(data)


def test_warning_threshold_object() -> None:
    # A calibration with no thin pools yields no warning.
    cal = ReferenceCalibration(
        pool_sizes={"browsers": 100},
        thresholds={"browsers": {"rate": MetricThreshold("rate", 60.0, 60.0, 60.0, False)}},
        min_reference=30,
    )
    assert cal.warning() is None
