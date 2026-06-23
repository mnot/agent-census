"""Tests for display formatting helpers."""

from __future__ import annotations

from agent_census.report.format import elide_ua, truncate

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)"
REAL_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/16 Safari/605"


def test_elides_compatible_preamble() -> None:
    assert elide_ua(GOOGLEBOT) == "Googlebot/2.1; +http://www.google.com/bot.html"
    assert elide_ua(GPTBOT) == "GPTBot/1.1; +https://openai.com/gptbot"


def test_browser_ua_left_intact() -> None:
    assert elide_ua(REAL_BROWSER, is_browser=True) == REAL_BROWSER


def test_no_marker_left_intact() -> None:
    assert elide_ua("python-requests/2.31.0") == "python-requests/2.31.0"
    assert elide_ua("UptimeRobot/2.0 (https://uptimerobot.com)") == (
        "UptimeRobot/2.0 (https://uptimerobot.com)"
    )


def test_none_passthrough() -> None:
    assert elide_ua(None) is None


def test_truncate_leaves_short_text() -> None:
    assert truncate("short", 80) == "short"


def test_truncate_clips_long_text_with_ellipsis() -> None:
    out = truncate("x" * 100, 80)
    assert len(out) == 80
    assert out.endswith("…")
