"""Tests for the TOML data files and loader."""

from __future__ import annotations

import pytest

from agent_census.dataload import (
    _AGENT_SCHEMA,
    _bad_format,
    _check_top_level,
    _require_agent,
    _validate_records,
    KNOWN_AGENT_CATEGORIES,
    load_asn_agents,
    load_egress_networks,
    load_list,
    load_range_sources,
    load_tokens,
    load_vuln_paths,
)
from agent_census.errors import ConfigError


def test_crawler_spec_fields() -> None:
    spec = dict(load_tokens("ai_crawler"))["GPTBot"]
    assert spec.domains == ("openai.com",)
    assert spec.ranges_url == "https://openai.com/gptbot.json"


def test_ranges_url_loaded() -> None:
    spec = dict(load_tokens("ai_crawler"))["OAI-SearchBot"]
    assert spec.ranges_url == "https://openai.com/searchbot.json"


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


def test_vuln_paths_split_into_two_buckets() -> None:
    always, contextual = load_vuln_paths()
    # Secret-file / RCE targets are always probes; CMS surfaces are contextual.
    assert "/.env" in always
    assert "/wp-login.php" in contextual
    # No substring belongs to both buckets.
    assert not set(always) & set(contextual)


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
    for name in ("scanner_ua", "feed_readers"):
        assert load_list(name)
    assert load_vuln_paths()
    for category in KNOWN_AGENT_CATEGORIES:
        load_tokens(category)
        load_asn_agents(category)
    assert load_range_sources("datacenter_ranges")
    assert load_egress_networks()


def test_validate_rejects_unknown_key() -> None:
    with pytest.raises(ConfigError, match="unknown key 'doamins'"):
        _validate_records(
            "x.toml", "agent", [{"ua_substring": "X", "doamins": ["a"]}], _AGENT_SCHEMA
        )


def test_validate_rejects_bad_type() -> None:
    # asns must be a list of ints, not strings.
    with pytest.raises(ConfigError, match=r"'asns' must be int\[\]"):
        _validate_records("x.toml", "agent", [{"name": "X", "asns": ["35237"]}], _AGENT_SCHEMA)


def test_validate_rejects_missing_required() -> None:
    # No ua_substring and not asn_primary -> nothing to identify the agent by.
    with pytest.raises(ConfigError, match="needs a 'ua_substring'"):
        _validate_records("x.toml", "agent", [{"domains": ["a"]}], _AGENT_SCHEMA, _require_agent)
    # asn_primary without an asns list has no identity either.
    with pytest.raises(ConfigError, match="'asn_primary' needs an 'asns'"):
        _validate_records(
            "x.toml", "agent", [{"asn_primary": True}], _AGENT_SCHEMA, _require_agent
        )


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
