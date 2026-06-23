"""Tests for the TOML data files and loader."""

from __future__ import annotations

from agent_census.dataload import load_list, load_tokens


def test_crawler_spec_fields() -> None:
    spec = dict(load_tokens("ai_crawler"))["ClaudeBot"]
    assert spec.domains == ("anthropic.com", "claude.ai")
    assert spec.ranges == ("160.79.104.0/21",)  # inline-comment source stripped by TOML
    assert spec.ranges_url is None


def test_ranges_url_loaded() -> None:
    spec = dict(load_tokens("ai_crawler"))["OAI-SearchBot"]
    assert spec.ranges_url == "https://openai.com/searchbot.json"


def test_flat_lists_load() -> None:
    assert "/.env" in load_list("vuln_paths")
    assert "sqlmap" in load_list("scanner_ua")
    assert "NetNewsWire" in load_list("feed_readers")
