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


def test_analyze_defaults_to_html(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    rc = main(["analyze", LOG, *OFFLINE, "-o", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_analyse_is_an_alias_for_analyze(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    rc = main(["analyse", LOG, *OFFLINE, "-o", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


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
            "--md",
            "-o",
            str(out),
        ]
    )
    assert rc == 0
    # Both copies were pooled.
    assert "84 parsed" in out.read_text(encoding="utf-8")


def test_md_flag(tmp_path: Path) -> None:
    out = tmp_path / "r.md"
    rc = main(["analyze", LOG, *OFFLINE, "--md", "-o", str(out)])
    assert rc == 0
    assert "# Agent Census" in out.read_text(encoding="utf-8")


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
    rc = main(
        ["analyze", str(log), "--log-format-preset", "cloudflare", *OFFLINE, "--md", "-o", str(out)]
    )
    assert rc == 0
    assert "1 parsed" in out.read_text(encoding="utf-8")


def test_vhost_flag_filters_and_reports(tmp_path: Path) -> None:
    log = tmp_path / "multisite.log"
    log.write_text(
        'a.example:443 1.1.1.1 - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 9 "-" "curl/8"\n'
        'b.example:443 9.9.9.9 - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 9 "-" "curl/8"\n',
        encoding="utf-8",
    )
    out = tmp_path / "r.md"
    rc = main(
        ["analyze", str(log), "--log-format-preset", "vhost_combined", "--vhost", "a.example",
         *OFFLINE, "--md", "-o", str(out)]
    )
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "1 parsed" in text and "1 excluded (--vhost)" in text

    # Repeated --vhost is a union: both sites kept, nothing excluded.
    both = tmp_path / "both.md"
    rc = main(
        ["analyze", str(log), "--log-format-preset", "vhost_combined",
         "--vhost", "a.example", "--vhost", "b.example", *OFFLINE, "--md", "-o", str(both)]
    )
    assert rc == 0
    assert "2 parsed" in both.read_text(encoding="utf-8")


def test_inspect_by_kind(tmp_path: Path) -> None:
    out = tmp_path / "i.md"
    rc = main(
        ["inspect", LOG, *OFFLINE, "--robots-file", ROBOTS, "--kind", "vuln_scanner",
         "-o", str(out)]
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
    rc = main(
        ["inspect", LOG, *OFFLINE, "--kind", "vuln_scanner", "--network", "aws",
         "-o", str(miss)]
    )
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
    assert userconfig.load().defaults == {"identity": "ip_ua_subnet", "log_format_preset": "combined"}

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
    assert userconfig.load().defaults["identity"] == "ip"


def test_format_alternatives_supersede_each_other() -> None:
    _apply_persisted_settings(_analyze_args([LOG, "--log-format-preset", "combined"]))
    assert "log_format_preset" in userconfig.load().defaults
    _apply_persisted_settings(_analyze_args([LOG, "--log-format", "%h %t"]))
    cfg = userconfig.load().defaults
    assert cfg.get("log_format") == "%h %t" and "log_format_preset" not in cfg


def test_save_writes_owner_only_permissions() -> None:
    # The config can hold a secret API token; the file must never be group/world
    # readable, and must not pass through a looser mode on the way there.
    import stat

    store = userconfig.load()
    store.defaults["cf_api_token"] = "cfat_secret"
    store.save()
    mode = stat.S_IMODE(userconfig.config_path().stat().st_mode)
    assert mode == 0o600


def test_load_tolerates_a_non_object_config() -> None:
    # A hand-edited config that is valid JSON but not an object (here, a list)
    # must fall back to defaults (with a warning), not crash the whole CLI.
    path = userconfig.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('["not", "a", "dict"]', encoding="utf-8")
    store = userconfig.load()
    assert store.defaults == {} and store.sites == {} and store.warning is not None


def test_identity_defaults_to_ip_ua_when_unset() -> None:
    args = _analyze_args([LOG])
    _apply_persisted_settings(args)
    assert args.identity == "ip_ua"  # built-in default, nothing saved


def test_site_settings_persist_under_the_site() -> None:
    # A setting passed with --site is remembered under that site, not the defaults.
    first = _analyze_args([LOG, "--site", "blog", "--identity", "ip_ua_subnet"])
    _apply_persisted_settings(first)
    store = userconfig.load()
    assert store.sites["blog"]["identity"] == "ip_ua_subnet"
    assert store.defaults == {}  # nothing leaked into the global scope

    # A later --site run inherits it; a run without the site does not.
    later = _analyze_args([LOG, "--site", "blog"])
    _apply_persisted_settings(later)
    assert later.identity == "ip_ua_subnet"
    plain = _analyze_args([LOG])
    _apply_persisted_settings(plain)
    assert plain.identity == "ip_ua"  # falls back to the built-in default


def test_site_overrides_defaults_and_cli_overrides_site() -> None:
    _apply_persisted_settings(_analyze_args([LOG, "--identity", "ip"]))  # global default
    _apply_persisted_settings(_analyze_args([LOG, "--site", "blog", "--identity", "ip_ua_subnet"]))

    # A --site run with nothing passed: the site value wins over the global default.
    inherited = _analyze_args([LOG, "--site", "blog"])
    _apply_persisted_settings(inherited)
    assert inherited.identity == "ip_ua_subnet"

    # A value passed this run beats the stored site value.
    overridden = _analyze_args([LOG, "--site", "blog", "--identity", "ip_ua"])
    _apply_persisted_settings(overridden)
    assert overridden.identity == "ip_ua"


def test_site_supersedes_default_across_the_format_alternatives() -> None:
    # The default names one member of the format pair; the site names the other.
    _apply_persisted_settings(_analyze_args([LOG, "--log-format", "%h %t"]))
    _apply_persisted_settings(_analyze_args([LOG, "--site", "blog", "--log-format-preset", "combined"]))
    resolved = _analyze_args([LOG, "--site", "blog"])
    _apply_persisted_settings(resolved)
    # The site's preset wins; the default's log_format is masked, not blended in.
    assert resolved.log_format_preset == "combined"
    assert resolved.log_format is None


def test_site_logfiles_are_saved_and_restored(tmp_path: Path) -> None:
    log = tmp_path / "site.log"
    log.write_text(Path(LOG).read_text(encoding="utf-8"), encoding="utf-8")

    # Passing paths with --site remembers them under the site.
    first = _analyze_args([str(log), "--site", "blog"])
    _apply_persisted_settings(first)
    assert userconfig.load().sites["blog"]["logfiles"] == [str(log)]

    # A later --site run with no paths pulls them from config.
    later = _analyze_args(["--site", "blog"])
    _apply_persisted_settings(later)
    assert later.logfiles == [log]


def test_site_vhost_is_saved_and_restored() -> None:
    # A vhost filter passed with --site is remembered and re-applied by name.
    first = _analyze_args([LOG, "--site", "blog", "--vhost", "a.example", "--vhost", "b.example"])
    _apply_persisted_settings(first)
    assert userconfig.load().sites["blog"]["vhost"] == ["a.example", "b.example"]

    later = _analyze_args(["--site", "blog"])
    _apply_persisted_settings(later)
    assert later.vhost == ["a.example", "b.example"]


def test_vhost_without_a_site_is_not_persisted() -> None:
    # vhost describes which data is a site; with no site there is nowhere sensible
    # to keep it, so it is used for the run but not remembered.
    _apply_persisted_settings(_analyze_args([LOG, "--vhost", "a.example"]))
    assert userconfig.load().defaults == {}


def test_default_is_a_baseline_a_site_overrides() -> None:
    # A preference set without --site is a global baseline; a site inherits it
    # until it sets its own, and other sites keep inheriting the baseline.
    _apply_persisted_settings(_analyze_args([LOG, "--identity", "ip_ua_subnet"]))  # baseline
    _apply_persisted_settings(_analyze_args([LOG, "--site", "blog", "--identity", "ip"]))  # override

    blog = _analyze_args([LOG, "--site", "blog"])
    _apply_persisted_settings(blog)
    assert blog.identity == "ip"  # the site's own value
    other = _analyze_args([LOG, "--site", "wiki"])
    _apply_persisted_settings(other)
    assert other.identity == "ip_ua_subnet"  # still the baseline
    store = userconfig.load()
    assert store.defaults["identity"] == "ip_ua_subnet"  # baseline untouched by the override


def test_site_run_with_no_logfiles_works_end_to_end(tmp_path: Path) -> None:
    log = tmp_path / "site.log"
    log.write_text(Path(LOG).read_text(encoding="utf-8"), encoding="utf-8")
    out = tmp_path / "r.md"
    # Seed the site with its log file...
    assert main(["analyze", str(log), "--site", "blog", *OFFLINE, "--md", "-o", str(out)]) == 0
    # ...then analyse it by name alone.
    out2 = tmp_path / "r2.md"
    assert main(["analyze", "--site", "blog", *OFFLINE, "--md", "-o", str(out2)]) == 0
    assert "parsed" in out2.read_text(encoding="utf-8")


def test_no_logfiles_and_no_site_is_a_config_error(tmp_path: Path) -> None:
    rc = main(["analyze", *OFFLINE, "--md", "-o", str(tmp_path / "x.md")])
    assert rc == 2


def test_unknown_site_with_no_logfiles_is_a_config_error(tmp_path: Path) -> None:
    rc = main(["analyze", "--site", "ghost", *OFFLINE, "--md", "-o", str(tmp_path / "x.md")])
    assert rc == 2


def test_legacy_flat_config_is_read_as_defaults() -> None:
    # A pre-versioning flat file must keep working, read as the defaults block.
    path = userconfig.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"identity": "ip_ua_subnet"}', encoding="utf-8")
    store = userconfig.load()
    assert store.defaults == {"identity": "ip_ua_subnet"} and store.warning is None


def test_unrecognised_config_version_warns_and_is_ignored() -> None:
    path = userconfig.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"version": 99, "defaults": {"identity": "ip"}}', encoding="utf-8")
    store = userconfig.load()
    assert store.defaults == {} and store.warning is not None


def test_config_flag_redirects_the_settings_file(tmp_path: Path) -> None:
    cfg = tmp_path / "custom.json"
    args = _analyze_args([LOG, "--config", str(cfg), "--identity", "ip_ua_subnet"])
    _apply_persisted_settings(args)
    assert cfg.exists()  # written to the override location
    assert userconfig.load(cfg).defaults["identity"] == "ip_ua_subnet"
    assert not userconfig.config_path().exists()  # the default location is untouched


def test_report_shows_filenames_not_full_paths(tmp_path: Path) -> None:
    sub = tmp_path / "private-dir"
    sub.mkdir()
    log = sub / "access.log"
    log.write_text(Path(LOG).read_text(encoding="utf-8"), encoding="utf-8")
    robots = sub / "robots.txt"
    robots.write_text("User-agent: *\nDisallow: /x/\n", encoding="utf-8")
    out = tmp_path / "r.md"
    main(["analyze", str(log), *OFFLINE, "--md", "--robots-file", str(robots), "-o", str(out)])
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
