"""Tests for the calibration digest renderer and CLI command."""

from __future__ import annotations

from pathlib import Path

from agent_census.cli import main
from agent_census.model import (
    ClientFeatures,
    ClientId,
    ClientProfile,
    Classification,
    Kind,
    Signal,
)
from agent_census.pipeline import (
    RESIDENTIAL_NETWORK,
    AnalysisResult,
    IdentityStats,
    SkipStats,
)
from agent_census.report import render_calibration

DATA = Path(__file__).parent / "data"
LOG = str(DATA / "sample_access.log")
OFFLINE = ("--no-verify-bots", "--no-fetch-ranges")


def _profile(
    ip: str,
    ua: str,
    *,
    requests: int,
    kind: Kind,
    tags: frozenset[str] = frozenset(),
    as_number: str | None = None,
    as_org: str | None = None,
    network: str = RESIDENTIAL_NETWORK,
    browser: bool = False,
    page_count: int = 0,
    asset_coload: float = 0.0,
    signals: tuple[Signal, ...] = (),
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent=ua),
        entries=(),
        features=ClientFeatures(
            request_count=requests,
            user_agent=ua,
            ua_looks_like_browser=browser,
            page_count=page_count,
            asset_coload_ratio=asset_coload,
            as_number=as_number,
            as_org=as_org,
        ),
        classification=Classification(
            primary=kind, confidence=0.7, tags=tags, all_signals=signals
        ),
        network=network,
    )


def _result(profiles: tuple[ClientProfile, ...]) -> AnalysisResult:
    return AnalysisResult(
        profiles=profiles,
        skips=SkipStats(len(profiles), len(profiles), 0),
        identity_strategy="ip_ua",
        identity_stats=IdentityStats(len(profiles), 0, 0),
        network_categories={RESIDENTIAL_NETWORK: "residential", "AWS": "datacenter"},
    )


def test_digest_surfaces_every_section() -> None:
    profiles = (
        # unrecognised ASN: has an AS number but fell to residential
        _profile(
            "9.9.9.9",
            "python-scraper/1",
            requests=400,
            kind=Kind.SCRAPER,
            as_number="64500",
            as_org="Example Hoster LLC",
        ),
        # declared known crawler, not verified
        _profile(
            "1.1.1.1",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            requests=30,
            kind=Kind.SEARCH_ENGINE,
            tags=frozenset({"declares-known-bot"}),
        ),
        # declares a bot we don't recognise
        _profile(
            "2.2.2.2",
            "FooScan/1.0",
            requests=12,
            kind=Kind.UNKNOWN,
            tags=frozenset({"bot-ua"}),
        ),
        # spoof flag + impossible browser, from a datacenter
        _profile(
            "3.3.3.3",
            "Mozilla/5.0 ... Version/99 Safari/605.1.15",
            requests=20,
            kind=Kind.SPOOFED_BROWSER,
            tags=frozenset({"impossible-browser-ua"}),
            network="AWS",
            browser=True,
        ),
        # a real current browser that loaded no assets (headless tell)
        _profile(
            "4.4.4.4",
            "Mozilla/5.0 ... Chrome/120 Safari/537.36",
            requests=50,
            kind=Kind.BROWSER,
            tags=frozenset({"current-browser-ua"}),
            browser=True,
            page_count=40,
            asset_coload=0.0,
        ),
        # singleton (one request -> unknown, tagged singleton; the digest's singleton
        # section keys on request_count, not the kind)
        _profile(
            "5.5.5.5",
            "oneshot/1",
            requests=1,
            kind=Kind.UNKNOWN,
            tags=frozenset({"generic-ua", "singleton"}),
        ),
        # unknown cluster
        _profile(
            "6.6.6.6",
            "weird-thing/2",
            requests=7,
            kind=Kind.UNKNOWN,
            tags=frozenset({"generic-ua"}),
        ),
        # conflicting signals
        _profile(
            "7.7.7.7",
            "python-requests/2.31.0",
            requests=15,
            kind=Kind.SCRAPER,
            signals=(
                Signal(Kind.SCRAPER, 0.70, (), "scraper"),
                Signal(Kind.CRAWLER, 0.45, (), "crawler"),
            ),
        ),
    )
    out = render_calibration(_result(profiles), source="x", top=30)

    assert "# Calibration digest — x" in out
    # unrecognised ASN row
    assert "64500" in out and "Example Hoster LLC" in out
    # declared/unverified split
    assert "Recognised, unverified" in out and "Googlebot" in out
    assert "Unrecognised declared bots" in out and "FooScan/1.0" in out
    # spoof + browser quality
    assert "## Anomaly / spoof flags" in out and "impossible-browser-ua" in out
    assert "Browser UA from a datacenter network" in out
    assert "loaded no assets" in out
    # singletons / unknowns / conflicts
    assert "made exactly one request" in out
    assert "## Unknown clusters" in out and "generic-ua · residential" in out
    assert "scraper 0.70, crawler 0.45" in out and "python-requests" in out


def test_no_findings_reads_cleanly() -> None:
    out = render_calibration(_result(()), source="empty", top=10)
    # Each section still renders with an explicit "nothing here" note.
    assert "_No residual ASNs" in out
    assert "_No one-request clients._" in out
    assert "_Nothing fell to UNKNOWN._" in out


def test_truncation_is_announced() -> None:
    profiles = tuple(
        _profile(f"9.9.9.{i}", "scrape/1", requests=100 - i, kind=Kind.SCRAPER, as_number=str(64500 + i))
        for i in range(5)
    )
    out = render_calibration(_result(profiles), source="x", top=2)
    assert "3 more ASNs not shown (top 2 by volume)" in out


def test_cli_calibrate_runs_end_to_end(tmp_path: Path) -> None:
    out = tmp_path / "calibration.md"
    rc = main(["calibrate", LOG, *OFFLINE, "-o", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Calibration digest — sample_access.log")
    # known fixtures: the python-requests client draws scraper vs crawler, the
    # zgrab scanner is tagged probe-paths, Googlebot declares but isn't verified here.
    assert "## Conflicting signals" in text and "python-requests" in text
    assert "probe-paths" in text


def test_band_table_counts_non_age_browser_shapes() -> None:
    # A browser-shaped client (primary BROWSER) whose UA shape resolves to bot-ua
    # must still appear in the band table; otherwise the table's Clients/Requests
    # silently understate the browser-shaped population.
    profiles = (
        _profile(
            "1.1.1.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            requests=40,
            kind=Kind.BROWSER,
            tags=frozenset({"current-browser-ua"}),
            browser=True,
        ),
        _profile(
            "2.2.2.2",
            "curl/8.0 pretending",
            requests=17,
            kind=Kind.BROWSER,
            tags=frozenset({"bot-ua"}),  # browser-shaped but bot-ua, no age band
        ),
    )
    out = render_calibration(_result(profiles), source="x", top=30)
    table = out.split("## Browser identification quality", 1)[1].split("\n## ", 1)[0]
    assert "| bot-ua | 1 | 17 |" in table


def test_regex_gap_section_lists_only_unreadable_versions() -> None:
    # The "regex gaps" list should hold UAs we genuinely can't version -- not a
    # parseable browser that merely lacks an age band (a middling version age).
    profiles = (
        _profile(
            "1.1.1.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            requests=50,
            kind=Kind.BROWSER,
            tags=frozenset({"browser-ua"}),
            browser=True,
        ),
        _profile(
            "2.2.2.2",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            requests=50,
            kind=Kind.BROWSER,
            tags=frozenset({"browser-ua"}),  # band-less but parseable (mid-age)
            browser=True,
        ),
    )
    out = render_calibration(_result(profiles), source="x", top=30)
    gaps = out.split("### Unparsed browser UAs (regex gaps)", 1)[1].split("\n### ", 1)[0]
    assert "Mobile/15E148" in gaps  # no version token -> a real gap
    assert "Chrome/142" not in gaps  # parses fine -> not a gap
