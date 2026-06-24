"""End-to-end pipeline test over the bundled sample log."""

from __future__ import annotations

from pathlib import Path

import pytest

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
    assert "# Agent Census" in text
    assert "## Summary by kind" in text
    assert "vuln scanner" in text  # category names display without underscores


def test_report_shows_elapsed_note() -> None:
    text = render_report(_run(), source="x", elapsed=7.25)
    assert "_Analysed in 7.2s._" in text
    # omitted when not provided
    assert "Analysed in" not in render_report(_run(), source="x")


def test_category_names_display_without_underscores() -> None:
    result = _run()
    text = render_report(result, source="x")
    assert "## vuln scanner" in text  # spaced label in the section header
    assert "vuln_scanner" not in text  # no slugs in the human-facing report


def test_kind_input_accepts_any_separator() -> None:
    result = _run()
    for spelling in ("vuln scanner", "vuln-scanner", "vuln_scanner"):
        assert select_profiles(result, client=None, kind=spelling), spelling


def test_inspect_renders_rationale() -> None:
    selected = select_profiles(_run(), client=None, kind="vuln_scanner")
    text = render_inspect(selected)
    assert "Why this classification" in text
    assert "known probe paths" in text
    assert "Request trace" in text


def _rotation_result(tmp_path: Path, ua_count: int) -> pipeline.AnalysisResult:
    lines = [
        f'2.2.2.2 - - [10/Oct/2023:12:0{i}:00 +0000] "GET / HTTP/1.1" 200 100 "-" "rot-agent-{i}"'
        for i in range(ua_count)
    ]
    log = tmp_path / "rotation.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    return pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))


def test_inspect_rolls_up_ua_rotating_ip(tmp_path: Path) -> None:
    # An IP with many rotating UAs is summarised, not dumped one full block each.
    result = _rotation_result(tmp_path, ua_count=6)
    selected = select_profiles(result, client="2.2.2.2", kind=None)
    text = render_inspect(selected)
    assert "6 clients on one IP" in text
    assert "user-agent rotation" in text
    assert "**Total**" in text
    assert "Why this classification" not in text  # summarised, not full blocks


def test_inspect_below_rollup_threshold_shows_full_blocks(tmp_path: Path) -> None:
    result = _rotation_result(tmp_path, ua_count=3)
    selected = select_profiles(result, client="2.2.2.2", kind=None)
    text = render_inspect(selected)
    assert "clients on one IP" not in text
    assert "Why this classification" in text  # full per-client detail


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


def test_max_per_kind_caps_detail_but_keeps_summary_exact(tmp_path: Path) -> None:
    # 40 distinct unknown clients; cap detail at 5 per kind. The kept profiles
    # are bounded, but the rollup still counts all 40 with exact request totals.
    lines = [
        f"10.0.0.{i} - - [10/Oct/2023:12:00:00 +0000] "
        f'"GET / HTTP/1.1" 200 {100 + i} "-" "agent-{i}"'
        for i in range(40)
    ]
    log = tmp_path / "many.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")

    result = pipeline.analyze(log, parser, strategy, max_per_kind=5)
    kept = [p for p in result.profiles if p.client_id.ip.startswith("10.0.0.")]
    assert len(kept) == 5  # detail bounded
    rollup = result.rollups[Kind.SINGLETON]
    assert rollup.clients == 40  # but the rollup counts every client
    assert rollup.requests == 40  # and exact request total
    # the kept five are the highest-volume (here, highest byte ids tie on requests)
    text = render_report(result, source="x")
    assert "40 clients" in text  # section header from the rollup
    assert "…and 35 more" in text  # 40 total - 5 shown

    # unlimited keeps every profile
    full = pipeline.analyze(log, parser, strategy, max_per_kind=0)
    assert len([p for p in full.profiles if p.client_id.ip.startswith("10.0.0.")]) == 40


def test_datacenter_fleet_merges_by_subnet_and_ua(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Treat 198.18.x.x (a benchmarking TEST-NET) as datacenter and fold by /24,
    # so the test does not depend on the hand-curated range data. Two IPs in the
    # same /24 with one UA collapse; a third /24 and a different UA stay separate.
    monkeypatch.setattr(pipeline, "is_datacenter_ip", lambda ip: ip.startswith("198.18."))
    monkeypatch.setattr(
        pipeline,
        "datacenter_subnet",
        lambda ip: ".".join(ip.split(".")[:3]) + ".0/24" if ip.startswith("198.18.") else None,
    )
    ua = "python-requests/2.31.0"
    rows = [
        ("198.18.1.5", ua),
        ("198.18.1.9", ua),  # same /24 + UA -> merges with the above
        ("198.18.2.5", ua),  # different /24 -> its own entry
        ("198.18.1.20", "curl/8.0"),  # same /24, different UA -> its own entry
    ]
    lines = [
        f'{ip} - - [10/Oct/2023:12:0{i}:00 +0000] "GET /p HTTP/1.1" 200 100 "-" "{agent}"'
        for i, (ip, agent) in enumerate(rows)
    ]
    log = tmp_path / "dc.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    merged = [
        p
        for p in result.profiles
        if p.client_id.ip == "198.18.1.0/24" and p.client_id.user_agent == ua
    ]
    assert len(merged) == 1
    assert set(merged[0].member_ips) == {"198.18.1.5", "198.18.1.9"}
    assert "datacenter" in merged[0].classification.tags
    ids = {p.client_id.ip for p in result.profiles}
    assert "198.18.2.0/24" in ids  # the other subnet stayed separate
    # three groups: 1.0/24+requests, 2.0/24+requests, 1.0/24+curl
    assert result.identity_stats.client_count == 3


def test_network_rollups_attribute_providers_and_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Attribute 52.x to a provider and leave folding off, so each client lands in
    # its network bucket; a residential client stays in the catch-all.
    monkeypatch.setattr(pipeline, "datacenter_subnet", lambda ip: None)
    monkeypatch.setattr(pipeline, "is_datacenter_ip", lambda ip: ip.startswith("52."))
    monkeypatch.setattr(
        pipeline, "datacenter_provider", lambda ip: "Amazon AWS" if ip.startswith("52.") else None
    )
    rows = [
        ("52.1.1.1", "python-requests/2.31.0"),
        ("52.1.1.2", "curl/8.0"),
        ("9.9.9.9", "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15"),
    ]
    lines = [
        f'{ip} - - [10/Oct/2023:12:0{i}:00 +0000] "GET /p HTTP/1.1" 200 100 "-" "{ua}"'
        for i, (ip, ua) in enumerate(rows)
    ]
    log = tmp_path / "net.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    assert "Amazon AWS" in result.network_rollups
    assert pipeline.RESIDENTIAL_NETWORK in result.network_rollups
    assert result.network_categories["Amazon AWS"] == "datacenter"
    aws_requests = sum(r.requests for r in result.network_rollups["Amazon AWS"].values())
    assert aws_requests == 2  # both 52.x clients

    text = render_report(result, source="x")
    assert "Requests by kind and network" in text
    assert "Amazon AWS" in text


def test_logged_asn_marks_datacenter_without_ip_ranges(tmp_path: Path) -> None:
    # Offline (no fetched ranges), a client whose IP is in no range but whose
    # logged AS number is annotated as a provider is still flagged datacenter.
    fmt = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%{MM_ASN}e"'
    line = (
        '9.9.9.9 - - [10/Oct/2023:12:00:00 +0000] "GET /p HTTP/1.1" 200 100 '
        '"-" "python-requests/2.31.0" "16509"'
    )
    log = tmp_path / "asn.log"
    log.write_text(line + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    assert "Amazon AWS" in result.network_rollups
    assert result.network_categories["Amazon AWS"] == "datacenter"
    profile = next(p for p in result.profiles if p.client_id.ip == "9.9.9.9")
    assert "datacenter" in profile.classification.tags


def test_markdown_network_table_bolds_row_leader() -> None:
    from agent_census.pipeline import (  # local import keeps the module header lean
        RESIDENTIAL_NETWORK,
        AnalysisResult,
        IdentityStats,
        KindRollup,
        SkipStats,
    )

    result = AnalysisResult(
        profiles=(),
        skips=SkipStats(0, 0, 0),
        identity_strategy="ip_ua",
        identity_stats=IdentityStats(0, 0, 0),
        network_rollups={
            "Amazon AWS": {Kind.SCRAPER: KindRollup(clients=1, requests=900)},
            RESIDENTIAL_NETWORK: {Kind.SCRAPER: KindRollup(clients=1, requests=100)},
        },
        network_categories={"Amazon AWS": "datacenter", RESIDENTIAL_NETWORK: "residential"},
    )
    text = render_report(result, source="x")
    assert "Requests by kind and network" in text
    assert "**900**" in text  # AWS leads the scraper row -> bolded
    assert "**100**" not in text  # the trailing network is not the leader


def test_verified_crawler_buckets_under_its_operator_not_residential(tmp_path: Path) -> None:
    # A verified crawler whose IP is in no datacenter range must still land in the
    # hosting group (under its operator domain), never residential.
    from agent_census.model import BotVerification, ClientId, VerificationStatus
    from agent_census.pipeline import RESIDENTIAL_NETWORK

    class _StubVerifier:
        def needs(self, ua: str | None) -> bool:
            return ua is not None and "MyBot" in ua

        def verify_all(
            self, items: object
        ) -> dict[ClientId, BotVerification]:
            return {
                cid: BotVerification(
                    VerificationStatus.VERIFIED,
                    resolved_host="mybot.example",
                    evidence=("ok",),
                )
                for cid, _ua in items  # type: ignore[attr-defined]
            }

    lines = [
        f'9.9.9.{i} - - [10/Oct/2023:12:00:0{i} +0000] "GET /p{i} HTTP/1.1" 200 100 '
        '"-" "MyBot/1.0 (+https://mybot.example)"'
        for i in range(3)
    ]
    log = tmp_path / "bot.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(
        log, parser, identity.get_strategy("ip_ua"), verifier=_StubVerifier()
    )

    assert "mybot.example" in result.network_rollups
    assert result.network_categories["mybot.example"] == "datacenter"  # hosting group
    assert RESIDENTIAL_NETWORK not in result.network_rollups
    profile = next(p for p in result.profiles if p.client_id.ip == "mybot.example")
    assert profile.network == "mybot.example"


def test_respect_counted_in_summary_without_per_client_tag(tmp_path: Path) -> None:
    # Dropping the respects-robots tag must not lose the summary's respect count:
    # it now comes from the compliance verdict, not the tag.
    from agent_census.robots.parser import RobotsRules

    rules = RobotsRules("User-agent: *\nDisallow: /private/\n")
    busy = [  # >= 5 requests, all allowed -> verdict RESPECTS
        f'8.8.8.8 - - [10/Oct/2023:12:00:0{i} +0000] "GET /ok{i} HTTP/1.1" 200 100 "-" "curl/8.0"'
        for i in range(6)
    ]
    idle = [  # < 5 requests, none disallowed -> verdict UNKNOWN (too little to judge)
        '8.8.4.4 - - [10/Oct/2023:12:05:00 +0000] "GET /ok HTTP/1.1" 200 100 "-" "wget/1.21"'
    ]
    log = tmp_path / "respect.log"
    log.write_text("\n".join(busy + idle) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), robots=rules)

    rollups = result.rollups.values()
    assert sum(r.respects_robots for r in rollups) >= 1  # the busy client
    assert sum(r.unknown_robots for r in rollups) >= 1  # the idle client -> "?"
    # With robots present, every client lands in exactly one bucket.
    accounted = sum(r.respects_robots + r.ignores_robots + r.unknown_robots for r in rollups)
    assert accounted == sum(r.clients for r in rollups)
    assert all("respects-robots" not in p.classification.tags for p in result.profiles)


def test_crawler_recognised_by_logged_asn(tmp_path: Path) -> None:
    # A client from AS35237 (Sberbank) with a spoofed browser UA, recognised by
    # its logged AS number: ai_crawler, attributed to "Sberbank", tagged
    # asn-attributed, and not flagged datacenter (it's no longer in that list).
    fmt = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%{MM_ASN}e"'
    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    )
    lines = [
        f'5.188.0.{i} - - [10/Oct/2023:12:00:0{i} +0000] "GET /p{i} HTTP/1.1" 200 100 '
        f'"-" "{ua}" "35237"'
        for i in range(5)
    ]
    log = tmp_path / "sber.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    assert "Sberbank" in result.network_rollups
    crawlers = [p for p in result.profiles if p.classification.primary is Kind.AI_CRAWLER]
    assert crawlers and all(p.network == "Sberbank" for p in crawlers)
    tags = crawlers[0].classification.tags
    assert "asn-attributed" in tags and "datacenter" not in tags


def test_returning_client_coalesces_after_eviction(tmp_path: Path) -> None:
    # One client (one ip+ua) requests on day 1, then again on day 3. A filler
    # client on day 2 advances the clock past the 12h quiescent window, so the
    # day-1 stretch is evicted before day 3 arrives. The returning client must
    # stay a SINGLE coalesced profile -- not fragment into one-per-stretch.
    solo = [
        f"10.0.0.1 - - [0{day}/Oct/2023:12:0{req}:00 +0000] "
        f'"GET /p HTTP/1.1" 200 100 "-" "solo-agent"'
        for day in (1, 3)
        for req in range(3)
    ]
    filler = ['10.0.9.9 - - [02/Oct/2023:12:00:00 +0000] "GET /f HTTP/1.1" 200 100 "-" "filler"']
    lines = solo[:3] + filler + solo[3:]
    log = tmp_path / "returning.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")

    result = pipeline.analyze(log, parser, strategy, quiescent_seconds=12 * 3600)
    assert result.identity_stats.client_count == 2  # solo + filler, counted once each
    solo_profiles = [p for p in result.profiles if p.client_id.ip == "10.0.0.1"]
    assert len(solo_profiles) == 1
    assert solo_profiles[0].features.request_count == 6

    # With the park capped at zero, the day-1 stretch is finalised for real when
    # evicted, so the day-3 return can no longer coalesce -> the solo client
    # fragments into two profiles.
    fragmented = pipeline.analyze(
        log, parser, strategy, quiescent_seconds=12 * 3600, retired_cap=0
    )
    assert len([p for p in fragmented.profiles if p.client_id.ip == "10.0.0.1"]) == 2


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
