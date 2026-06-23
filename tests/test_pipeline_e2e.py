"""End-to-end pipeline test over the bundled sample log."""

from __future__ import annotations

from pathlib import Path

from agent_census import identity, pipeline
from agent_census.model import Kind
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS
from agent_census.report import render_inspect, render_report, select_profiles
from agent_census.robots.parser import RobotsRules

DATA = Path(__file__).parent / "data"


def _run() -> pipeline.AnalysisResult:
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")
    robots = (DATA / "robots.txt").read_text(encoding="utf-8")
    return pipeline.analyze(
        DATA / "sample_access.log",
        parser,
        strategy,
        robots=RobotsRules(robots),
    )


def _kind_of(result: pipeline.AnalysisResult, ip: str) -> Kind:
    for profile in result.profiles:
        if profile.client_id.ip == ip:
            return profile.classification.primary
    raise AssertionError(f"no client with ip {ip}")


def test_skip_count() -> None:
    result = _run()
    assert result.skips.skipped == 1  # the trailing garbage line
    assert result.skips.parsed == 42


def test_multiple_logfiles_are_pooled() -> None:
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")
    log = DATA / "sample_access.log"
    one = pipeline.analyze(log, parser, strategy)
    both = pipeline.analyze([log, log], parser, strategy)
    # Same clients, but every client's request count is doubled by the repeat.
    assert both.skips.parsed == one.skips.parsed * 2
    assert {p.client_id for p in both.profiles} == {p.client_id for p in one.profiles}
    by_ip = {p.client_id: p.features.request_count for p in one.profiles}
    for profile in both.profiles:
        assert profile.features.request_count == by_ip[profile.client_id] * 2


def test_each_client_classified_as_expected() -> None:
    result = _run()
    assert _kind_of(result, "192.0.2.10") is Kind.BROWSER
    assert _kind_of(result, "203.0.113.66") is Kind.VULN_SCANNER
    assert _kind_of(result, "66.249.66.1") is Kind.SEARCH_ENGINE
    assert _kind_of(result, "20.171.0.5") is Kind.AI_CRAWLER
    assert _kind_of(result, "198.51.100.9") is Kind.MONITOR
    assert _kind_of(result, "45.33.32.156") is Kind.SCRAPER


def test_gptbot_ignores_robots_but_stays_ai_crawler() -> None:
    result = _run()
    for profile in result.profiles:
        if profile.client_id.ip == "20.171.0.5":
            assert profile.classification.primary is Kind.AI_CRAWLER
            assert "ignores-robots" in profile.classification.tags
            assert "impersonator" not in profile.classification.tags


def test_report_renders_markdown() -> None:
    text = render_report(_run(), source="sample")
    assert "# Client Census" in text
    assert "## Summary by kind" in text
    assert "vuln_scanner" in text


def test_inspect_renders_rationale() -> None:
    selected = select_profiles(_run(), client=None, kind="vuln_scanner")
    text = render_inspect(selected)
    assert "Why this classification" in text
    assert "known probe paths" in text
    assert "Request trace" in text


def test_eviction_matches_no_eviction(tmp_path: Path) -> None:
    # A 3-day log where every client is active within a single day; with a 12h
    # gap, day-1/2 clients are evicted before day-3, but the result must be
    # identical to running with no eviction (no client returns after the gap).
    lines = []
    for day in (1, 2, 3):
        for client in range(6):
            for req in range(3):
                lines.append(
                    f"10.0.{day}.{client} - - [0{day}/Oct/2023:12:0{req}:00 +0000] "
                    f'"GET /p{client} HTTP/1.1" 200 100 "-" "agent-{client}"'
                )
    log = tmp_path / "multiday.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")

    def summary(result: pipeline.AnalysisResult) -> dict[object, tuple[int, Kind]]:
        return {
            p.client_id: (p.features.request_count, p.classification.primary)
            for p in result.profiles
        }

    base = pipeline.analyze(log, parser, strategy)
    evicted = pipeline.analyze(log, parser, strategy, quiescent_seconds=12 * 3600)
    assert summary(base) == summary(evicted)
    assert evicted.identity_stats == base.identity_stats
    assert len(evicted.profiles) == 18


def test_collect_entries_only_for_requested_keys() -> None:
    result = _run()
    scanner = next(p for p in result.profiles if p.classification.primary is Kind.VULN_SCANNER)
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")
    collected = pipeline.collect_entries(
        DATA / "sample_access.log", parser, strategy, [scanner]
    )
    assert set(collected) == {scanner.client_id}
    assert len(collected[scanner.client_id]) == scanner.features.request_count
