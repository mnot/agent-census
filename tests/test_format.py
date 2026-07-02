"""Tests for display formatting helpers."""

from __future__ import annotations

from agent_census.model import (
    BotVerification,
    ChannelVerdict,
    Classification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
    VerificationStatus,
)
import pytest

from agent_census.report.format import (
    agent_identity,
    as_label,
    client_label,
    count,
    elide_ua,
    feature_rows,
    human_duration,
    top_evidence,
    truncate,
)

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)"
REAL_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/16 Safari/605"


def test_elides_compatible_preamble() -> None:
    # Plain Mozilla-compatible boilerplate (no engine) -> a "…" elision marker.
    assert elide_ua(GOOGLEBOT) == "… Googlebot/2.1; +http://www.google.com/bot.html"
    # GPTBot's shell carries AppleWebKit/KHTML -> flagged as a browser costume.
    assert elide_ua(GPTBOT) == "[browser] GPTBot/1.1; +https://openai.com/gptbot"


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
    assert elide_ua(ua) == "[browser] NetNewsWire/6.1"  # wore a WebKit shell
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


def test_top_evidence_ignores_verification() -> None:
    # Verification evidence only ever restates the identity + tag already shown
    # elsewhere on the row, so it's never used for the hero caption -- even when
    # VERIFIED, classification evidence wins.
    verified = BotVerification(
        VerificationStatus.VERIFIED, evidence=("3 IP(s) verified as googlebot.com",)
    )
    assert top_evidence(_profile(verified)) == "UA names Googlebot"
    assert top_evidence(_profile(None)) == "UA names Googlebot"
    inconclusive = BotVerification(VerificationStatus.UNVERIFIED, evidence=("lookup failed",))
    assert top_evidence(_profile(inconclusive)) == "UA names Googlebot"


def _known_bot_profile(evidence: tuple[str, ...]) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip="203.0.113.1", user_agent="Mastodon/1.0"),
        entries=(),
        features=ClientFeatures(),
        classification=Classification(
            primary=Kind.SOCIAL_PREVIEW,
            confidence=0.9,
            evidence=evidence,
            agent_name="Mastodon",
        ),
    )


def test_top_evidence_skips_identity_declaration_for_known_bot() -> None:
    # known_bot's own evidence[0] just names the agent, which is already the
    # row's identity header -- skip it for whatever supporting fact follows.
    profile = _known_bot_profile(
        ("User-Agent declares 'Mastodon', a known social-preview / link-unfurl bot", "fetched /robots.txt")
    )
    assert top_evidence(profile) == "fetched /robots.txt"


def test_top_evidence_empty_when_only_identity_declaration() -> None:
    profile = _known_bot_profile(
        ("User-Agent declares 'Mastodon', a known social-preview / link-unfurl bot",)
    )
    assert top_evidence(profile) == "–"


def _agent_profile(
    *,
    agent_name: str | None = None,
    verification: BotVerification | None = None,
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip="203.0.113.1", user_agent="Googlebot/2.1"),
        entries=(),
        features=ClientFeatures(),
        classification=Classification(
            primary=Kind.SEARCH_ENGINE,
            confidence=0.9,
            evidence=("e",),
            agent_name=agent_name,
        ),
        verification=verification,
    )


def test_agent_identity_prefers_declared_name() -> None:
    profile = _agent_profile(
        agent_name="Googlebot",
        verification=BotVerification(
            VerificationStatus.VERIFIED, resolved_host="crawl.googlebot.com", dns=ChannelVerdict.VERIFIED
        ),
    )
    assert agent_identity(profile) == "Googlebot"


def test_agent_identity_falls_back_to_rdns_host() -> None:
    profile = _agent_profile(
        verification=BotVerification(
            VerificationStatus.VERIFIED, resolved_host="crawl.googlebot.com", dns=ChannelVerdict.VERIFIED
        )
    )
    assert agent_identity(profile) == "crawl.googlebot.com"


def test_agent_identity_none_for_an_unrecognised_client() -> None:
    assert agent_identity(_agent_profile()) is None


def test_agent_identity_ignores_ip_range_match_as_a_hostname() -> None:
    # An agent verified by IP range alone (no declared domains, e.g. ClaudeBot)
    # has `resolved_host` set to the matched CIDR by netverify, not a hostname --
    # the `dns` channel stays NOT_CHECKED in that case. Showing the CIDR as the
    # agent's "identity" would be a network, not a name -- and with no declared
    # name and no confirmed hostname, there is nothing left to show at all.
    range_only = BotVerification(
        VerificationStatus.VERIFIED,
        resolved_host="20.171.207.0/24",
        ip=ChannelVerdict.VERIFIED,
        dns=ChannelVerdict.NOT_CHECKED,
    )
    profile = _agent_profile(verification=range_only)
    assert agent_identity(profile) is None


def _dc_profile(tags: set[str], as_org: str | None, as_number: str | None = None) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip="52.1.1.0/24", user_agent="python-requests/2.31.0"),
        entries=(),
        features=ClientFeatures(as_org=as_org, as_number=as_number),
        classification=Classification(
            primary=Kind.SCRAPER, confidence=0.7, evidence=("cold hits",), tags=frozenset(tags)
        ),
        verification=None,
    )


def test_as_label_formats_org_and_number() -> None:
    assert as_label("Amazon.com, Inc.", "16509") == "Amazon.com, Inc. (AS16509)"
    assert as_label("Amazon.com, Inc.", "AS16509") == "Amazon.com, Inc. (AS16509)"
    assert as_label("Amazon.com, Inc.", None) == "Amazon.com, Inc."


def test_client_label_appends_org_only_for_datacenter() -> None:
    labelled = client_label(_dc_profile({"datacenter"}, "Amazon.com, Inc."))
    assert labelled.endswith("· Amazon.com, Inc.")
    # No datacenter tag -> org is not appended even when present.
    plain = client_label(_dc_profile(set(), "Amazon.com, Inc."))
    assert "Amazon.com, Inc." not in plain


def test_feature_rows_include_as_when_present() -> None:
    rows = dict(feature_rows(ClientFeatures(as_org="Amazon.com, Inc.", as_number="16509")))
    assert rows["AS / network"] == "Amazon.com, Inc. (AS16509)"
    assert "AS / network" not in dict(feature_rows(ClientFeatures()))


def test_truncate_leaves_short_text() -> None:
    assert truncate("short", 80) == "short"


def test_truncate_clips_long_text_with_ellipsis() -> None:
    out = truncate("x" * 100, 80)
    assert len(out) == 80
    assert out.endswith("…")


def test_count_pluralises_to_match() -> None:
    assert count(1, "client") == "1 client"
    assert count(0, "client") == "0 clients"
    assert count(2, "client") == "2 clients"
    assert count(1, "member IP") == "1 member IP"
    assert count(3, "member IP") == "3 member IPs"
    assert count(1234, "request") == "1,234 requests"  # thousands separator kept
    assert count(1, "IP", "IPs") == "1 IP"  # explicit plural for an irregular noun


@pytest.mark.parametrize(
    "seconds,text",
    [
        (45, "45s"),
        (90, "1m 30s"),
        (300, "5m"),  # a zero trailing unit is dropped, not shown as "5m 0s"
        (3600, "1h"),
        (3900, "1h 5m"),
        (3 * 86400, "3d"),
        (3 * 86400 + 4 * 3600, "3d 4h"),
        (604800, "1w"),  # a whole week, not "7d 0h"
        (604800 + 3 * 86400, "1w 3d"),
        (14 * 86400, "2w"),
    ],
)
def test_human_duration(seconds: int, text: str) -> None:
    assert human_duration(seconds) == text
