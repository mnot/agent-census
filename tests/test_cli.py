"""Tests for CLI argument handling and dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_census import userconfig
from agent_census.cli import _apply_persisted_settings, _build_parser, main

DATA = Path(__file__).parent / "data"
LOG = str(DATA / "sample_access.log")
ROBOTS = str(DATA / "robots.txt")
# Verification and range fetching are both on by default and make network calls;
# tests splat these to stay offline.
OFFLINE = ("--no-verify-bots", "--no-fetch-ranges")


def test_analyze_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    rc = main(["analyze", LOG, *OFFLINE, "-o", str(out)])
    assert rc == 0
    assert "# Agent Census" in out.read_text(encoding="utf-8")


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
            *OFFLINE,
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    # Both copies were pooled.
    assert "84 parsed" in out.read_text(encoding="utf-8")


def test_html_flag(tmp_path: Path) -> None:
    out = tmp_path / "r.html"
    rc = main(["analyze", LOG, *OFFLINE, "--html", "-o", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_analyze_cloudflare_preset(tmp_path: Path) -> None:
    # --log-format-preset cloudflare selects the JSON parser, not an Apache format.
    log = tmp_path / "cf.log"
    log.write_text(
        '{"ClientIP":"203.0.113.5","ClientRequestMethod":"GET","ClientRequestURI":"/p",'
        '"EdgeResponseStatus":200,"ClientRequestUserAgent":"curl/8","EdgeResponseBytes":10,'
        '"EdgeStartTimestamp":"2026-06-21T01:50:50Z"}\n',
        encoding="utf-8",
    )
    out = tmp_path / "r.md"
    rc = main(["analyze", str(log), "--log-format-preset", "cloudflare", *OFFLINE, "-o", str(out)])
    assert rc == 0
    assert "1 parsed" in out.read_text(encoding="utf-8")


def test_inspect_by_kind(tmp_path: Path) -> None:
    out = tmp_path / "i.md"
    rc = main(
        ["inspect", LOG, *OFFLINE, "--robots-file", ROBOTS, "--kind", "vuln_scanner", "-o", str(out)]
    )
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "Why this classification" in text
    # the second-pass entry collection populated the request trace
    assert "/.env" in text and "Request trace" in text


def test_inspect_by_network_and_kind(tmp_path: Path) -> None:
    # The sample log is all residential (offline, no datacenter ranges), so the
    # vuln_scanner sits in the residential bucket; AWS should match nothing.
    hit = tmp_path / "hit.md"
    rc = main(
        ["inspect", LOG, *OFFLINE, "--kind", "vuln_scanner", "--network", "residential",
         "-o", str(hit)]
    )
    assert rc == 0
    text = hit.read_text(encoding="utf-8")
    assert "Why this classification" in text and "**Network:** Residential" in text

    miss = tmp_path / "miss.md"
    rc = main(["inspect", LOG, *OFFLINE, "--kind", "vuln_scanner", "--network", "aws", "-o", str(miss)])
    assert rc == 0
    assert "No matching clients" in miss.read_text(encoding="utf-8")


def test_config_error_returns_2(tmp_path: Path) -> None:
    # An unreadable robots file is a config error -> exit 2 (network-free).
    rc = main(
        ["analyze", LOG, *OFFLINE, "--robots-file", str(tmp_path / "nope.txt"), "-o",
         str(tmp_path / "x.md")]
    )
    assert rc == 2


def _analyze_args(argv: list[str]):
    _, subcommands = _build_parser()
    return subcommands["analyze"].parse_intermixed_args(argv)


def test_settings_persist_then_restore() -> None:
    first = _analyze_args([LOG, "--identity", "ip_ua_subnet", "--log-format-preset", "combined"])
    _apply_persisted_settings(first)
    assert userconfig.load() == {"identity": "ip_ua_subnet", "log_format_preset": "combined"}

    # A later run that omits them inherits the saved values.
    later = _analyze_args([LOG])
    _apply_persisted_settings(later)
    assert later.identity == "ip_ua_subnet"
    assert later.log_format_preset == "combined"


def test_passing_a_setting_overrides_and_updates() -> None:
    _apply_persisted_settings(_analyze_args([LOG, "--identity", "ip_ua_subnet"]))
    overridden = _analyze_args([LOG, "--identity", "ip"])
    _apply_persisted_settings(overridden)
    assert overridden.identity == "ip"
    assert userconfig.load()["identity"] == "ip"


def test_format_alternatives_supersede_each_other() -> None:
    _apply_persisted_settings(_analyze_args([LOG, "--log-format-preset", "combined"]))
    assert "log_format_preset" in userconfig.load()
    _apply_persisted_settings(_analyze_args([LOG, "--log-format", "%h %t"]))
    cfg = userconfig.load()
    assert cfg.get("log_format") == "%h %t" and "log_format_preset" not in cfg


def test_identity_defaults_to_ip_ua_when_unset() -> None:
    args = _analyze_args([LOG])
    _apply_persisted_settings(args)
    assert args.identity == "ip_ua"  # built-in default, nothing saved


def test_report_shows_filenames_not_full_paths(tmp_path: Path) -> None:
    sub = tmp_path / "private-dir"
    sub.mkdir()
    log = sub / "access.log"
    log.write_text(Path(LOG).read_text(encoding="utf-8"), encoding="utf-8")
    robots = sub / "robots.txt"
    robots.write_text("User-agent: *\nDisallow: /x/\n", encoding="utf-8")
    out = tmp_path / "r.md"
    main(["analyze", str(log), *OFFLINE, "--robots-file", str(robots), "-o", str(out)])
    text = out.read_text(encoding="utf-8")

    assert "private-dir" not in text  # no directory path leaks into the report
    assert "access.log" in text  # the file name is still shown as the source
    assert "loaded from robots.txt" in text  # robots provenance is the name only


def test_keyboard_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("agent_census.cli.pipeline.analyze", boom)
    assert main(["analyze", LOG]) == 130
    assert "interrupted" in capsys.readouterr().err


def test_verify_bots_on_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_census.pipeline import AnalysisResult, IdentityStats, SkipStats

    seen: dict[str, object] = {}

    def fake_analyze(*_args: object, **kwargs: object) -> AnalysisResult:
        seen["verifier"] = kwargs.get("verifier")
        return AnalysisResult((), SkipStats(0, 0, 0, {}), "ip_ua", IdentityStats(0, 0, 0))

    monkeypatch.setattr("agent_census.cli.pipeline.analyze", fake_analyze)

    main(["analyze", LOG, "-o", str(tmp_path / "a.md")])
    assert seen["verifier"] is not None  # default: verification on

    main(["analyze", LOG, "--no-verify-bots", "-o", str(tmp_path / "b.md")])
    assert seen["verifier"] is None  # opted out


def test_fetch_ranges_on_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_census import iprange
    from agent_census.pipeline import AnalysisResult, IdentityStats, SkipStats

    def fake_analyze(*_args: object, **_kwargs: object) -> AnalysisResult:
        return AnalysisResult((), SkipStats(0, 0, 0, {}), "ip_ua", IdentityStats(0, 0, 0))

    monkeypatch.setattr("agent_census.cli.pipeline.analyze", fake_analyze)

    main(["analyze", LOG, "--no-verify-bots", "-o", str(tmp_path / "a.md")])
    assert iprange.remote_enabled() is True  # default: range fetching on


def test_fetch_ranges_opt_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_census import iprange
    from agent_census.pipeline import AnalysisResult, IdentityStats, SkipStats

    def fake_analyze(*_args: object, **_kwargs: object) -> AnalysisResult:
        return AnalysisResult((), SkipStats(0, 0, 0, {}), "ip_ua", IdentityStats(0, 0, 0))

    monkeypatch.setattr("agent_census.cli.pipeline.analyze", fake_analyze)

    main(["analyze", LOG, "--no-verify-bots", "--no-fetch-ranges", "-o", str(tmp_path / "b.md")])
    assert iprange.remote_enabled() is False  # opted out


def test_no_command_prints_help_returns_0() -> None:
    assert main([]) == 0


def test_help_flag_exits_zero() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-h"])
    assert exc.value.code == 0
