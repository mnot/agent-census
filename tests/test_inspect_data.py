"""Tests for the --inspect-dir bundle: capped traces, the JSON view-model, the
data writer, and the report's click-to-inspect wiring."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_census import identity, pipeline
from agent_census.cli import main
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS
from agent_census.report import render_report_html
from agent_census.report.inspect_data import (
    build_group_view,
    build_member_view,
    rendered_groups,
    write_inspect_bundle,
)
from agent_census.report.aggregate import by_kind, group_actors
from agent_census.robots.parser import RobotsRules

DATA = Path(__file__).parent / "data"
LOG = str(DATA / "sample_access.log")
ROBOTS = str(DATA / "robots.txt")
OFFLINE = ("--no-verify-bots", "--no-fetch-ranges")


def _run(inspect_trace: int = 20) -> pipeline.AnalysisResult:
    parser = resolve("apache", {"format": PRESETS["combined"]})
    strategy = identity.get_strategy("ip_ua")
    robots = RobotsRules((DATA / "robots.txt").read_text(encoding="utf-8"))
    return pipeline.analyze(
        DATA / "sample_access.log",
        parser,
        strategy,
        robots=robots,
        inspect_trace=inspect_trace,
        keep_signals=True,
    )


# -- capped trace ----------------------------------------------------------


def test_inspect_trace_zero_keeps_no_entries() -> None:
    result = _run(inspect_trace=0)
    assert all(not p.entries for p in result.profiles)


def test_inspect_trace_is_capped_per_client() -> None:
    result = _run(inspect_trace=3)
    assert result.profiles  # sanity
    assert all(len(p.entries) <= 3 for p in result.profiles)
    assert any(p.entries for p in result.profiles)


def test_trace_total_is_the_true_count_not_the_sample() -> None:
    # A client with more requests than the cap: the view still reports the true
    # total, and shows only the sampled rows.
    result = _run(inspect_trace=2)
    for group in rendered_groups(result.profiles, top=5):
        for member in build_group_view(group, limit=2)["members"]:
            trace = member["trace"]
            assert trace["shown"] <= 2
            assert trace["total"] >= trace["shown"]
            assert trace["total"] == member["requests_n"]


# -- view-model ------------------------------------------------------------


def test_group_view_has_display_ready_fields() -> None:
    result = _run()
    group = rendered_groups(result.profiles, top=5)[0]
    view = build_group_view(group, limit=20)
    assert view["slug"] == group.slug
    member = view["members"][0]
    for key in ("label", "kind_badge", "confidence", "ip", "user_agent", "signals", "features"):
        assert key in member
    # kind badge is a pre-rendered fragment; confidence is a formatted percentage.
    assert member["kind_badge"].startswith("<span")
    assert member["confidence"].endswith("%")


def test_group_view_spreads_one_actor_over_many_ips(tmp_path: Path) -> None:
    # Same User-Agent from two IPs folds into one actor group: the view carries a
    # card per member (what inspect --actor shows), not a single row.
    lines = [
        f'3.3.3.{ip} - - [10/Oct/2023:12:0{ip}:00 +0000] "GET /p HTTP/1.1" 200 100 "-" "sameUA/1"'
        for ip in (1, 2)
    ]
    log = tmp_path / "spread.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), inspect_trace=20)
    (kind_profiles,) = by_kind(result.profiles).values()
    group = group_actors(kind_profiles)[0]
    view = build_group_view(group, limit=20)
    assert view["count"] == 2
    assert len(view["members"]) == 2
    assert {m["ip"] for m in view["members"]} == {"3.3.3.1", "3.3.3.2"}


def test_trace_offsets_reset_per_page_and_assets_nest(tmp_path: Path) -> None:
    # Two page loads. Each asset nests under its page (child), and each offset is
    # measured from the current page: assets from their page, a navigation from the
    # previous page. The absolute start is lifted out to first_time.
    lines = [
        '7.7.7.7 - - [10/Oct/2023:12:00:00 +0000] "GET /page HTTP/1.1" 200 500 "-" "b/1"',
        '7.7.7.7 - - [10/Oct/2023:12:00:01 +0000] "GET /s.css HTTP/1.1" 200 90 '
        '"http://h/page" "b/1"',
        '7.7.7.7 - - [10/Oct/2023:12:00:05 +0000] "GET /page2 HTTP/1.1" 200 500 '
        '"http://h/page" "b/1"',
        '7.7.7.7 - - [10/Oct/2023:12:00:06 +0000] "GET /p2.css HTTP/1.1" 200 90 '
        '"http://h/page2" "b/1"',
    ]
    log = tmp_path / "page.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), inspect_trace=20)
    (profile,) = [p for p in result.profiles if p.client_id.ip == "7.7.7.7"]
    trace = build_member_view(profile, limit=20)["trace"]
    assert trace["first_time"].startswith("2023-10-10")  # absolute start, out of table
    rows = trace["rows"]
    assert [r["child"] for r in rows] == [False, True, False, True]  # page, asset, page, asset
    # /page +0s; /s.css +1s from /page; /page2 +5s from the previous page; /p2.css
    # +1s from /page2 (base reset), NOT +6s from the first request.
    assert [r["time"] for r in rows] == ["+0.0s", "+1.0s", "+5.0s", "+1.0s"]


def test_trace_referer_shortens_same_site_only(tmp_path: Path) -> None:
    lines = [
        '8.8.8.8 - - [10/Oct/2023:12:00:00 +0000] "GET /a HTTP/1.1" 200 500 '
        '"http://redbot.org/home" "b/1"',
        '8.8.8.8 - - [10/Oct/2023:12:00:01 +0000] "GET /b HTTP/1.1" 200 500 '
        '"https://google.com/search" "b/1"',
    ]
    log = tmp_path / "ref.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), inspect_trace=20)
    (profile,) = [p for p in result.profiles if p.client_id.ip == "8.8.8.8"]
    rows = build_member_view(profile, limit=20, site="redbot.org")["trace"]["rows"]
    referers = [r["referer"] for r in rows]
    assert "/home" in referers  # same-site: scheme + authority dropped
    assert "https://google.com/search" in referers  # off-site: full URL kept


def test_writer_infers_site_host_to_shorten_referers(tmp_path: Path) -> None:
    # A combined log carries no host, so result.site is None -- the writer infers
    # the site from the dominant Referer host and shortens same-site referers.
    lines = [
        f'6.6.6.{i} - - [10/Oct/2023:12:00:0{i} +0000] "GET /p{i} HTTP/1.1" 200 90 '
        '"https://redbot.org/home" "b/1"'
        for i in range(1, 5)
    ]
    log = tmp_path / "site.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), inspect_trace=20)
    assert result.site is None  # combined format logs no host
    write_inspect_bundle(result.profiles, tmp_path, limit=20, top=5, site=result.site)
    referers = [
        row["referer"]
        for path in tmp_path.glob("*.json")
        for member in json.loads(path.read_text())["members"]
        for row in member["trace"]["rows"]
    ]
    assert referers  # sanity
    assert all(r == "/home" for r in referers)  # inferred redbot.org -> path only


# -- writer / drift guard --------------------------------------------------


def test_writer_emits_one_file_per_rendered_group(tmp_path: Path) -> None:
    result = _run()
    n = write_inspect_bundle(result.profiles, tmp_path, limit=20, top=5)
    files = list(tmp_path.glob("*.json"))
    assert n == len(files) == len(rendered_groups(result.profiles, top=5))
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))  # valid JSON
        assert data["slug"] == path.stem  # filename is the slug


def test_every_report_link_resolves_to_a_file(tmp_path: Path) -> None:
    # The drift guard: every data-inspect slug the report emits must have a file.
    result = _run()
    write_inspect_bundle(result.profiles, tmp_path, limit=20, top=5)
    html = render_report_html(result, source="x", top=5, inspect=True)
    slugs = set(re.findall(r'data-inspect="([0-9a-f]{16})"', html))
    files = {p.stem for p in tmp_path.glob("*.json")}
    assert slugs
    assert slugs <= files, f"rows link to missing files: {slugs - files}"


# -- CLI -------------------------------------------------------------------


def test_cli_inspect_data_on_by_default(tmp_path: Path) -> None:
    # No flag needed: an HTML report to a file gets the inspect data by default.
    out = tmp_path / "report.html"
    rc = main(["analyze", LOG, "--robots-file", ROBOTS, *OFFLINE, "-o", str(out)])
    assert rc == 0
    index = out.read_text(encoding="utf-8")
    assert index.startswith("<!doctype html>")
    assert re.search(r'data-inspect="[0-9a-f]{16}"', index)
    # Data lands in a report-named directory and the viewer is pointed at it.
    assert '__INSPECT_DIR__="report.inspect/"' in index
    files = list((out.parent / "report.inspect").glob("*.json"))
    assert files
    slugs = {p.stem for p in files}
    for slug in re.findall(r'data-inspect="([0-9a-f]{16})"', index):
        assert slug in slugs


def test_cli_inspect_data_dirs_are_per_report(tmp_path: Path) -> None:
    # Two reports in one folder keep separate data dirs -- no shared inspect/ to
    # collide in.
    for name in ("alpha.html", "beta.html"):
        assert main(["analyze", LOG, *OFFLINE, "-o", str(tmp_path / name)]) == 0
    assert (tmp_path / "alpha.inspect").is_dir()
    assert (tmp_path / "beta.inspect").is_dir()
    assert not (tmp_path / "inspect").exists()


def test_cli_inspect_data_prunes_stale_files_on_rerun(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    data_dir = tmp_path / "report.inspect"
    assert main(["analyze", LOG, *OFFLINE, "-o", str(out)]) == 0
    orphan = data_dir / "deadbeefdeadbeef.json"  # a file no current row links to
    orphan.write_text("{}", encoding="utf-8")
    assert main(["analyze", LOG, *OFFLINE, "-o", str(out)]) == 0  # re-run
    assert not orphan.exists()  # pruned
    index = out.read_text(encoding="utf-8")
    files = {p.stem for p in data_dir.glob("*.json")}
    for slug in re.findall(r'data-inspect="([0-9a-f]{16})"', index):
        assert slug in files  # every current row still resolves


def test_cli_no_inspect_data_opts_out(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    rc = main(["analyze", LOG, *OFFLINE, "-o", str(out), "--no-inspect-data"])
    assert rc == 0
    index = out.read_text(encoding="utf-8")
    assert not re.search(r'data-inspect="[0-9a-f]{16}"', index)  # rows keep copy-id
    assert 'data-copy="' in index
    assert not (out.parent / "report.inspect").exists()  # no files written


def test_cli_inspect_data_skipped_for_markdown(tmp_path: Path) -> None:
    # Markdown has no overlay, so no data is written even though the flag defaults on.
    out = tmp_path / "report.md"
    rc = main(["analyze", LOG, *OFFLINE, "--md", "-o", str(out)])
    assert rc == 0
    assert not (out.parent / "report.inspect").exists()


def test_cli_inspect_command_is_markdown_only(tmp_path: Path) -> None:
    out = tmp_path / "trace.md"
    rc = main(["inspect", LOG, *OFFLINE, "--kind", "browser", "-o", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "<!doctype html>" not in text
    assert text.lstrip().startswith("#")  # Markdown heading
