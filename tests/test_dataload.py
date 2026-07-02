"""Tests for the TOML data files and loader."""

from __future__ import annotations

import pytest

from agent_census.dataload import (
    _AGENT_SCHEMA,
    _SHARED_TUNING,
    KNOWN_AGENT_CATEGORIES,
    _bad_format,
    _check_top_level,
    _grouped_lists,
    _require_agent,
    _validate_records,
    load_asn_agents,
    load_egress_networks,
    load_list,
    load_range_sources,
    load_request_signatures,
    load_shared_tuning,
    load_tokens,
    load_tuning,
    load_ua_signatures,
    load_vuln_paths,
)
from agent_census.errors import ConfigError


def test_crawler_spec_fields() -> None:
    spec = dict(load_tokens("ai_crawler"))["GPTBot"]
    assert spec.domains == ("openai.com",)
    assert spec.ranges_urls == ("https://openai.com/gptbot.json",)


def test_ranges_url_loaded() -> None:
    spec = dict(load_tokens("ai_crawler"))["OAI-SearchBot"]
    assert spec.ranges_urls == ("https://openai.com/searchbot.json",)


def test_ranges_url_list_loaded() -> None:
    # A monitor that splits its published ranges across feeds declares a list; it
    # normalises to a tuple of every feed. Pingdom publishes one list per IP family.
    spec = dict(load_tokens("monitor"))["Pingdom"]
    assert spec.ranges_urls == (
        "https://my.pingdom.com/probes/ipv4",
        "https://my.pingdom.com/probes/ipv6",
    )


def test_user_triggered_flag_loaded() -> None:
    ai = dict(load_tokens("ai_crawler"))
    assert ai["ChatGPT-User"].user_triggered is True
    assert ai["Amzn-User"].user_triggered is True
    assert ai["GPTBot"].user_triggered is False  # autonomous crawler, default
    assert dict(load_tokens("search_engine"))["YandexUserproxy"].user_triggered is True


def test_browser_releases_load() -> None:
    from datetime import date

    from agent_census.dataload import load_browser_releases

    families = {rel.name: rel for rel in load_browser_releases()}
    assert "Chrome" in families and "Firefox" in families
    chrome = families["Chrome"]
    assert chrome.anchor_major == 120
    assert chrome.anchor_date == date(2023, 12, 6)
    assert chrome.days_per_major == 30


def test_flat_lists_load() -> None:
    assert "sqlmap" in load_list("scanner_ua")
    assert "NetNewsWire" in load_list("feed_readers")
    assert "uptimerobot" in load_list("monitor_uas")
    assert "wp-login" in load_list("submit_paths")


def test_ua_signatures_load() -> None:
    sig = load_ua_signatures()
    assert "applewebkit" in sig.browser_engines
    assert "scrapy" in sig.automation_substrings
    assert "rss" not in sig.automation_substrings  # anchored, not a bare substring
    assert sig.automation_standalone_words == ("feed", "rss")
    assert sig.automation_suffix_words == ("bot",)
    assert "puppeteer" in sig.headless_engines
    assert "curl" in sig.library_names
    assert "podcast" in sig.feed_terms


def test_request_signatures_load() -> None:
    sig = load_request_signatures()
    assert "css" in sig.static_extensions
    assert "html" in sig.page_extensions
    assert "/etc/passwd" in sig.traversal_markers
    assert "%252e" in sig.evasion_markers
    assert "PROPFIND" in sig.uncommon_methods
    assert "rss" in sig.feed_filename_tokens
    assert "index.xml" in sig.feed_filenames


def test_grouped_lists_rejects_unknown_table() -> None:
    with pytest.raises(ConfigError, match="unexpected top-level key"):
        _grouped_lists("x.toml", {"browser": {}, "bogus": {}}, {"browser": {"layout_engines"}})


def test_grouped_lists_rejects_unknown_key() -> None:
    with pytest.raises(ConfigError, match=r"\[browser\] unexpected key"):
        _grouped_lists("x.toml", {"browser": {"engines": []}}, {"browser": {"layout_engines"}})


def test_grouped_lists_rejects_bad_type() -> None:
    with pytest.raises(ConfigError, match="must be a list of strings"):
        _grouped_lists(
            "x.toml", {"browser": {"layout_engines": [1]}}, {"browser": {"layout_engines"}}
        )


def test_grouped_lists_rejects_non_table_section() -> None:
    with pytest.raises(ConfigError, match=r"\[browser\] must be a table"):
        _grouped_lists(
            "x.toml", {"browser": ["not", "a", "table"]}, {"browser": {"layout_engines"}}
        )


def test_grouped_lists_rejects_empty_list() -> None:
    # An empty list would compile to a match-everything regex downstream.
    with pytest.raises(ConfigError, match="must not be empty"):
        _grouped_lists(
            "x.toml", {"browser": {"layout_engines": []}}, {"browser": {"layout_engines"}}
        )


def test_load_list_rejects_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_census.dataload as dl

    monkeypatch.setattr(dl, "_load", lambda name, subdir="": {"empty_thing": []})
    with pytest.raises(ConfigError, match="must not be empty"):
        dl.load_list("empty_thing")


def test_shared_tuning_load() -> None:
    shared = load_shared_tuning()
    assert shared["unknown_threshold"] == 0.45
    assert shared["browser_coload_min"] == 0.4
    assert shared["storm_404_distinct_paths_min"] == 15


def test_all_tuning_files_validate() -> None:
    # Importing the classifiers loads (and so validates) every per-classifier tuning
    # file at module import; a bad file would raise here. This guards the shared one.
    from agent_census.classify.registry import all_classifiers

    assert all_classifiers()
    assert load_shared_tuning()


def test_load_tuning_widens_int_to_float() -> None:
    # storm_404_distinct_paths_min is written as 15 (int) but returned as a float.
    assert load_shared_tuning()["storm_404_distinct_paths_min"] == 15.0


def test_load_tuning_rejects_missing_key() -> None:
    # Full real schema (so every table is accounted for) plus one knob the file lacks.
    schema = {**_SHARED_TUNING, "extra": "verdict.absent"}
    with pytest.raises(ConfigError, match="missing 'verdict.absent'"):
        load_tuning("shared", schema)


def test_load_tuning_rejects_unexpected_table() -> None:
    # A schema that names only [verdict] leaves the file's other tables unexpected.
    with pytest.raises(ConfigError, match="unexpected top-level key"):
        load_tuning("shared", {"x": "verdict.unknown_threshold"})


def test_vuln_paths_split_into_two_buckets() -> None:
    always, contextual = load_vuln_paths()
    # Secret-file / RCE targets are always probes; CMS surfaces are contextual.
    assert "/.env" in always
    assert "/wp-login.php" in contextual
    # No substring belongs to both buckets.
    assert not set(always) & set(contextual)


def test_load_vuln_paths_rejects_empty_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    # An emptied bucket would compile to a match-everything regex (or silently
    # disable its half of detection), so it must raise rather than load.
    import agent_census.dataload as dl

    dl.load_vuln_paths.cache_clear()
    monkeypatch.setattr(
        dl, "_load", lambda name, subdir="": {"always_probe": ["/.env"], "probe_if_absent": []}
    )
    with pytest.raises(ConfigError, match="'probe_if_absent' must not be empty"):
        dl.load_vuln_paths()
    dl.load_vuln_paths.cache_clear()


def test_asn_recognised_agents_loaded() -> None:
    assert (35237, "Sberbank") in load_asn_agents("ai_crawler")
    # An ASN-only agent (no ua_substring) is skipped by the UA-token loader.
    assert all(ua for ua, _spec in load_tokens("ai_crawler"))


def test_asn_range_feeds_loaded(synthetic_asn_crawler: object) -> None:
    from agent_census.dataload import load_asn_range_feeds

    cr = synthetic_asn_crawler
    feeds = {asn: (url, fmt) for asn, url, fmt in load_asn_range_feeds()}
    assert cr.asn in feeds  # type: ignore[attr-defined]
    assert feeds[cr.asn] == (cr.url, "ripestat")  # type: ignore[attr-defined]


def test_range_source_asns_parse_as_ints() -> None:
    by_name = {s.name: s for s in load_range_sources("datacenter_ranges")}
    assert 16509 in by_name["Amazon"].asns  # EC2
    assert 24940 in by_name["Hetzner"].asns
    assert all(isinstance(asn, int) for s in by_name.values() for asn in s.asns)


def test_all_bundled_data_files_validate() -> None:
    # A guard: every shipped data file passes validation (no unknown keys etc.).
    for name in ("scanner_ua", "feed_readers", "monitor_uas", "submit_paths"):
        assert load_list(name)
    always, contextual = load_vuln_paths()
    assert always and contextual
    for category in KNOWN_AGENT_CATEGORIES:
        load_tokens(category)
        load_asn_agents(category)
    assert load_range_sources("datacenter_ranges")
    assert load_egress_networks()
    assert load_ua_signatures().browser_engines
    assert load_request_signatures().static_extensions


def test_validate_rejects_unknown_key() -> None:
    with pytest.raises(ConfigError, match="unknown key 'doamins'"):
        _validate_records(
            "x.toml", "agent", [{"ua_substring": "X", "doamins": ["a"]}], _AGENT_SCHEMA
        )


def test_validate_rejects_bad_type() -> None:
    # asns must be a list of AS numbers, not strings.
    with pytest.raises(ConfigError, match=r"'asns' must be asn\[\]"):
        _validate_records("x.toml", "agent", [{"name": "X", "asns": ["35237"]}], _AGENT_SCHEMA)


def test_validate_rejects_out_of_range_asn() -> None:
    # An AS number outside the 32-bit range is rejected, not silently accepted.
    with pytest.raises(ConfigError, match=r"'asns' must be asn\[\]"):
        _validate_records("x.toml", "agent", [{"name": "X", "asns": [-1]}], _AGENT_SCHEMA)
    with pytest.raises(ConfigError, match=r"'asns' must be asn\[\]"):
        _validate_records(
            "x.toml", "agent", [{"name": "X", "asns": [4294967296]}], _AGENT_SCHEMA
        )


def test_validate_rejects_missing_required() -> None:
    # No ua_substring and not asn_primary -> nothing to identify the agent by.
    with pytest.raises(ConfigError, match="needs a 'ua_substring'"):
        _validate_records("x.toml", "agent", [{"domains": ["a"]}], _AGENT_SCHEMA, _require_agent)
    # asn_primary without an asns list has no identity either.
    with pytest.raises(ConfigError, match="'asn_primary' needs an 'asns'"):
        _validate_records("x.toml", "agent", [{"asn_primary": True}], _AGENT_SCHEMA, _require_agent)


def test_validate_rejects_non_table_entry() -> None:
    with pytest.raises(ConfigError, match="expected a table"):
        _validate_records("x.toml", "agent", ["just a string"], _AGENT_SCHEMA)


def test_bad_format_flagged() -> None:
    assert "unknown format 'yaml'" in _bad_format({"format": "yaml"})
    assert _bad_format({"format": "ripestat"}) == ""
    assert _bad_format({}) == ""


def test_top_level_rejects_stray_key() -> None:
    # A mistyped array name ([[agents]] instead of [[agent]]) is caught.
    with pytest.raises(ConfigError, match="unexpected top-level key"):
        _check_top_level("x.toml", {"agent": [], "agents": []}, {"agent"})
