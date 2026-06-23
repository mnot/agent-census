"""Tests for CLI argument handling and dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_census.cli import main

DATA = Path(__file__).parent / "data"
LOG = str(DATA / "sample_access.log")
ROBOTS = str(DATA / "robots.txt")


def test_analyze_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    rc = main(["analyze", LOG, "-o", str(out)])
    assert rc == 0
    assert "# Client Census" in out.read_text(encoding="utf-8")


def test_options_intermixed_with_logfiles(tmp_path: Path) -> None:
    out = tmp_path / "r.md"
    # An option sits BETWEEN the two log files — the shape that used to fail.
    rc = main(
        [
            "analyze",
            LOG,
            "--log-format-preset",
            "combined",
            LOG,
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    # Both copies were pooled.
    assert "84 parsed" in out.read_text(encoding="utf-8")


def test_html_flag(tmp_path: Path) -> None:
    out = tmp_path / "r.html"
    rc = main(["analyze", LOG, "--html", "-o", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_inspect_by_kind(tmp_path: Path) -> None:
    out = tmp_path / "i.md"
    rc = main(["inspect", LOG, "--robots-file", ROBOTS, "--kind", "vuln_scanner", "-o", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "Why this classification" in text
    # the second-pass entry collection populated the request trace
    assert "/.env" in text and "Request trace" in text


def test_config_error_returns_2(tmp_path: Path) -> None:
    # --host without --fetch-robots is a usage error.
    rc = main(["analyze", LOG, "--host", "example.com", "-o", str(tmp_path / "x.md")])
    assert rc == 2


def test_keyboard_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("agent_census.cli.pipeline.analyze", boom)
    assert main(["analyze", LOG]) == 130
    assert "interrupted" in capsys.readouterr().err


def test_no_command_prints_help_returns_0() -> None:
    assert main([]) == 0


def test_help_flag_exits_zero() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-h"])
    assert exc.value.code == 0
