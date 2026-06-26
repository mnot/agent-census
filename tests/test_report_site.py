"""The analysed site is baked into the report title/header."""

from __future__ import annotations

from pathlib import Path

from agent_census import identity, pipeline
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS
from agent_census.report import render_report, render_report_html


def _analyze(tmp_path: Path, *, vhosts: list[str] | None = None) -> pipeline.AnalysisResult:
    # Three lines served for a.example, one for b.example.
    lines = [
        f'{host}:443 {ip} - - [10/Oct/2023:12:0{i}:00 +0000] "GET / HTTP/1.1" 200 9 "-" "curl/8"'
        for i, (host, ip) in enumerate(
            [("a.example", "1.1.1.1"), ("a.example", "2.2.2.2"), ("a.example", "3.3.3.3"),
             ("b.example", "9.9.9.9")]
        )
    ]
    log = tmp_path / "vhost.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": PRESETS["vhost_combined"]})
    return pipeline.analyze(log, parser, identity.get_strategy("ip_ua"), vhosts=vhosts)


def test_site_is_most_prevalent_host(tmp_path: Path) -> None:
    result = _analyze(tmp_path)
    assert result.site == "a.example"
    assert "<h1>Agent Census — a.example</h1>" in render_report_html(result, source="x")
    assert render_report(result, source="x").startswith("# Agent Census — a.example")


def test_site_is_first_vhost_when_given(tmp_path: Path) -> None:
    # The passed --vhost wins over the most-common host (here the less-common one).
    result = _analyze(tmp_path, vhosts=["b.example"])
    assert result.site == "b.example"
    assert "<title>Agent Census — b.example</title>" in render_report_html(result, source="x")


def test_no_host_means_no_site_suffix(tmp_path: Path) -> None:
    # The combined format carries no host, so the title stays plain.
    log = tmp_path / "plain.log"
    log.write_text(
        '1.1.1.1 - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 9 "-" "curl/8"\n',
        encoding="utf-8",
    )
    parser = resolve("apache", {"format": PRESETS["combined"]})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))
    assert result.site is None
    assert "<h1>Agent Census</h1>" in render_report_html(result, source="x")
