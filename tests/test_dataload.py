"""Tests for the TOML data files and loader."""

from __future__ import annotations

from agent_census.dataload import load_asn_agents, load_list, load_range_sources, load_tokens


def test_crawler_spec_fields() -> None:
    spec = dict(load_tokens("ai_crawler"))["ClaudeBot"]
    assert spec.domains == ("anthropic.com", "claude.ai")
    assert spec.ranges_url == "https://claude.com/crawling/bots.json"


def test_ranges_url_loaded() -> None:
    spec = dict(load_tokens("ai_crawler"))["OAI-SearchBot"]
    assert spec.ranges_url == "https://openai.com/searchbot.json"


def test_flat_lists_load() -> None:
    assert "/.env" in load_list("vuln_paths")
    assert "sqlmap" in load_list("scanner_ua")
    assert "NetNewsWire" in load_list("feed_readers")


def test_asn_recognised_agents_loaded() -> None:
    assert (35237, "Sberbank") in load_asn_agents("ai_crawler")
    # An ASN-only agent (no ua_substring) is skipped by the UA-token loader.
    assert all(ua for ua, _spec in load_tokens("ai_crawler"))


def test_range_source_asns_parse_as_ints() -> None:
    by_name = {s.name: s for s in load_range_sources("datacenter_ranges")}
    assert 16509 in by_name["Amazon AWS"].asns  # EC2
    assert 24940 in by_name["Hetzner"].asns
    assert all(isinstance(asn, int) for s in by_name.values() for asn in s.asns)
