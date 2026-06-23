"""Tests for display formatting helpers."""

from __future__ import annotations

from agent_census.model import (
    BotVerification,
    Classification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
    VerificationStatus,
)
from agent_census.report.format import elide_ua, top_evidence, truncate

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


def test_elides_khtml_preamble_for_non_browser() -> None:
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) NetNewsWire/6.1"
    )
    assert elide_ua(ua) == "NetNewsWire/6.1"
    assert elide_ua(ua, is_browser=True) == ua  # a real browser keeps its preamble


def _profile(verification: BotVerification | None) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip="googlebot.com", user_agent="Googlebot"),
        entries=(),
        features=ClientFeatures(),
        classification=Classification(
            primary=Kind.SEARCH_ENGINE, confidence=0.9, evidence=("UA names Googlebot",)
        ),
        verification=verification,
    )


def test_top_evidence_prefers_verification() -> None:
    verified = BotVerification(
        VerificationStatus.VERIFIED, evidence=("3 IP(s) verified as googlebot.com",)
    )
    assert top_evidence(_profile(verified)) == "3 IP(s) verified as googlebot.com"


def test_top_evidence_falls_back_when_not_verified() -> None:
    assert top_evidence(_profile(None)) == "UA names Googlebot"
    inconclusive = BotVerification(VerificationStatus.UNVERIFIED, evidence=("lookup failed",))
    assert top_evidence(_profile(inconclusive)) == "UA names Googlebot"


def test_truncate_leaves_short_text() -> None:
    assert truncate("short", 80) == "short"


def test_truncate_clips_long_text_with_ellipsis() -> None:
    out = truncate("x" * 100, 80)
    assert len(out) == 80
    assert out.endswith("…")
