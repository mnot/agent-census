"""Tests for the HTML renderers."""

from __future__ import annotations

from pathlib import Path

from agent_census import identity, pipeline
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS
from agent_census.report import render_inspect_html, render_report_html, select_profiles
from agent_census.report.html import _esc

DATA = Path(__file__).parent / "data"


def _run() -> pipeline.AnalysisResult:
    parser = resolve("apache", {"format": PRESETS["combined"]})
    return pipeline.analyze(DATA / "sample_access.log", parser, identity.get_strategy("ip_ua"))


def test_report_html_is_a_full_page() -> None:
    html = render_report_html(_run(), source="sample")
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert html.rstrip().endswith("</html>")
    assert "Agent Census" in html
    assert "Summary by kind" in html
    # kind sections are anchored for the summary links
    assert 'id="vuln_scanner"' in html
    assert 'href="#vuln_scanner"' in html


def test_report_html_client_cells_are_copyable() -> None:
    # The 203.0.113.66 scanner row should be click-to-copy with its id.
    html = render_report_html(_run(), source="sample")
    assert 'data-copy="203.0.113.66"' in html
    assert "navigator.clipboard" in html  # copy script present
    assert "inspect --client" in html  # the tip


def test_kind_section_disclosure_and_filter(tmp_path: Path) -> None:
    # 8 one-off clients -> one 'unknown' kind; top 5 shown, 3 behind a disclosure.
    lines = [
        f"10.0.0.{i} - - [10/Oct/2023:12:00:0{i} +0000] "
        f'"GET / HTTP/1.1" 200 10 "-" "agent-{i}"'
        for i in range(8)
    ]
    log = tmp_path / "many.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))
    html = render_report_html(result, source="x", top=5)

    assert "<details>" in html
    assert "Show 3 more" in html
    assert 'class="filter"' in html  # filter input revealed in the disclosure
    assert html.count('class="frow"') == 3  # the 3 extra rows are filterable


def test_report_html_escapes_user_agent() -> None:
    # Inject a script payload via the UA; it must be escaped, not rendered.
    payload = "<script>alert(1)</script>"
    log = f'1.2.3.4 - - [10/Oct/2023:00:00:00 +0000] "GET / HTTP/1.1" 404 1 "-" "{payload}"'
    tmp = DATA / "_xss_tmp.log"
    tmp.write_text(log + "\n", encoding="utf-8")
    try:
        parser = resolve("apache", {"format": PRESETS["combined"]})
        result = pipeline.analyze(tmp, parser, identity.get_strategy("ip_ua"))
        html = render_report_html(result, source="x")
    finally:
        tmp.unlink()
    assert payload not in html  # the injected tag never appears raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # it is escaped


def test_inspect_html_renders_selected() -> None:
    result = _run()
    selected = select_profiles(result, client=None, kind="vuln_scanner")
    html = render_inspect_html(selected)
    assert "Client Inspection" in html
    assert "Why this classification" in html
    assert "Request trace" in html


def test_inspect_html_empty_selection() -> None:
    html = render_inspect_html([])
    assert "No matching clients" in html


def test_inspect_html_rolls_up_ua_rotating_ip(tmp_path: Path) -> None:
    lines = [
        f'2.2.2.2 - - [10/Oct/2023:12:0{i}:00 +0000] "GET / HTTP/1.1" 200 100 "-" "rot-{i}"'
        for i in range(6)
    ]
    log = tmp_path / "rotation.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))
    selected = select_profiles(result, client="2.2.2.2", kind=None)
    html = render_inspect_html(selected)
    assert "6 clients on one IP" in html
    assert "Request trace" not in html  # rolled up, not full per-client cards


def test_tags_have_hover_descriptions() -> None:
    # The 203.0.113.66 zgrab scanner is tagged 'probing'; it should carry a tooltip.
    html = render_report_html(_run(), source="sample")
    assert "<span class=\"tag\"" in html
    assert 'title="Requested known-vulnerable paths' in html


def test_esc_quotes() -> None:
    assert _esc('a"b<c>') == "a&quot;b&lt;c&gt;"
