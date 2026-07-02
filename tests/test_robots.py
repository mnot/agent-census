"""Tests for robots.txt parsing and compliance scoring."""

from __future__ import annotations

from datetime import datetime

from agent_census.features import FeatureAccumulator, extract_features
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


def test_wildcard_and_anchor_rules() -> None:
    # RFC 9309 §2.2.3: '*' matches any run, a trailing '$' anchors the path end.
    # The stdlib matcher ignores both, so these all read as allowed there.
    pdf = RobotsRules("User-agent: *\nDisallow: /private/*.pdf$")
    assert not pdf.can_fetch("*", "/private/report.pdf")  # wildcard + anchor bites
    assert pdf.can_fetch("*", "/private/report.txt")  # different extension is fine
    assert pdf.can_fetch("*", "/private/report.pdf.gz")  # $ anchor: not the end

    mid = RobotsRules("User-agent: *\nDisallow: /*?session=")
    assert not mid.can_fetch("*", "/page?session=1")  # mid-string wildcard

    exact = RobotsRules("User-agent: *\nDisallow: /admin$")
    assert not exact.can_fetch("*", "/admin")  # exactly /admin is blocked
    assert exact.can_fetch("*", "/admin/panel")  # anything longer is not


def test_most_specific_rule_wins_and_allow_breaks_ties() -> None:
    # The longest matching pattern decides; a same-length Allow beats a Disallow.
    rules = RobotsRules("User-agent: *\nDisallow: /a/\nAllow: /a/keep")
    assert rules.can_fetch("*", "/a/keep")  # more specific Allow
    assert not rules.can_fetch("*", "/a/block")  # only the Disallow matches
    tie = RobotsRules("User-agent: *\nDisallow: /p\nAllow: /p")
    assert tie.can_fetch("*", "/p")  # equal length -> Allow wins


def test_matched_group_and_crawl_delay() -> None:
    rules = RobotsRules(ROBOTS)
    assert rules.matched_group("BadBot") == "BadBot"
    assert rules.matched_group("RandomUA") == "*"
    assert rules.crawl_delay("BadBot") == 10.0


def test_matched_group_is_stable_document_order_heuristic() -> None:
    # matched_group is a stable, text-derived display heuristic: document-order
    # first match, independent of the CPython robotparser version. With 'Google'
    # before 'Googlebot', token 'Googlebot' reports 'Google'. This is intentionally
    # NOT reconciled with can_fetch's verdict (which uses longest-match on newer,
    # RFC 9309 interpreters) -- see the note on RobotsRules.matched_group. Do not
    # rewrite this to assert verdict-consistency; that is version-dependent.
    rules = RobotsRules(
        "User-agent: Google\nDisallow: /a\n\nUser-agent: Googlebot\nDisallow: /b\n"
    )
    assert rules.matched_group("Googlebot") == "Google"


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


def test_compliance_robots_txt_not_a_disallowed_hit() -> None:
    # Under Disallow: /, the stdlib reports /robots.txt itself as denied. A crawler
    # that politely fetched only /robots.txt must not be scored as ignoring robots.
    rules = RobotsRules("User-agent: *\nDisallow: /\n")
    entries = [entry("/robots.txt", offset=0)]
    feats = extract_features(entries)
    report = evaluate(entries, feats, rules, "Mozilla")
    assert report.disallowed_hits == 0
    assert report.verdict is RobotsVerdict.RESPECTS


def test_compliance_streaming_robots_txt_not_disallowed() -> None:
    # The streaming accumulator must agree with evaluate(): /robots.txt is exempt.
    rules = RobotsRules("User-agent: *\nDisallow: /\n")
    acc = FeatureAccumulator(disallowed_check=lambda p: not rules.can_fetch("Mozilla", p))
    acc.add(entry("/robots.txt", offset=0))
    assert acc.disallowed_hits == 0


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
