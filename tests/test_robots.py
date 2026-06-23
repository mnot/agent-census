"""Tests for robots.txt parsing and compliance scoring."""

from __future__ import annotations

from datetime import datetime

from agent_census.features import extract_features
from agent_census.model import RobotsVerdict
from agent_census.robots.compliance import evaluate
from agent_census.robots.parser import RobotsRules
from agent_census.robots.source import RobotsDoc, url_for_host

from .factories import entry

ROBOTS = """
User-agent: *
Disallow: /private/

User-agent: BadBot
Disallow: /
Crawl-delay: 10
""".strip()


def test_rules_basic_allow_deny() -> None:
    rules = RobotsRules(ROBOTS)
    assert rules.has_rules()
    assert rules.can_fetch("Mozilla", "/public")
    assert not rules.can_fetch("Mozilla", "/private/x")
    assert not rules.can_fetch("BadBot", "/anything")


def test_matched_group_and_crawl_delay() -> None:
    rules = RobotsRules(ROBOTS)
    assert rules.matched_group("BadBot") == "BadBot"
    assert rules.matched_group("RandomUA") == "*"
    assert rules.crawl_delay("BadBot") == 10.0


def test_compliance_ignores_when_disallowed_requested() -> None:
    rules = RobotsRules(ROBOTS)
    entries = [entry("/private/secret", offset=i) for i in range(3)]
    feats = extract_features(entries)
    report = evaluate(entries, feats, rules, "Mozilla")
    assert report.verdict is RobotsVerdict.IGNORES
    assert report.disallowed_hits == 3


def test_compliance_respects_when_clean() -> None:
    rules = RobotsRules(ROBOTS)
    entries = [entry("/robots.txt", offset=0)] + [entry(f"/p{i}", offset=i + 1) for i in range(6)]
    feats = extract_features(entries)
    report = evaluate(entries, feats, rules, "Mozilla")
    assert report.verdict is RobotsVerdict.RESPECTS
    assert report.fetched_robots_first is True


def test_compliance_unknown_without_rules() -> None:
    rules = RobotsRules("# empty\n")
    entries = [entry("/x", offset=0)]
    feats = extract_features(entries)
    report = evaluate(entries, feats, rules, None)
    assert report.verdict is RobotsVerdict.UNKNOWN


def test_url_for_host_variants() -> None:
    assert url_for_host("example.com") == "https://example.com/robots.txt"
    assert url_for_host("https://example.com") == "https://example.com/robots.txt"
    assert url_for_host("https://example.com/robots.txt") == "https://example.com/robots.txt"


def test_robots_doc_note_warns_on_fetch() -> None:
    fetched = RobotsDoc("x", "https://e/robots.txt", fetched_at=datetime(2026, 1, 1))
    assert "differ" in fetched.note()
    local = RobotsDoc("x", "/path/robots.txt")
    assert "loaded from" in local.note()
