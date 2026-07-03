"""Tests for select_profiles filtering (client / kind / network)."""

from __future__ import annotations

from agent_census.model import (
    Classification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
)
from agent_census.pipeline import AnalysisResult, IdentityStats, SkipStats
from agent_census.report import render_inspect, select_profiles
from agent_census.report.inspect_data import build_member_view


def _profile(
    ip: str, kind: Kind, network: str, tags: frozenset[str] = frozenset()
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent="ua"),
        entries=(),
        features=ClientFeatures(),
        classification=Classification(primary=kind, confidence=0.9, tags=tags, evidence=()),
        network=network,
    )


def _result(*profiles: ClientProfile) -> AnalysisResult:
    return AnalysisResult(
        profiles=profiles,
        skips=SkipStats(0, 0, 0),
        identity_strategy="ip_ua",
        identity_stats=IdentityStats(0, 0, 0),
    )


RESULT = _result(
    _profile("a", Kind.VULN_SCANNER, "Amazon AWS"),
    _profile("b", Kind.VULN_SCANNER, "Residential / unknown"),
    _profile("c", Kind.BROWSER, "Amazon AWS"),
)


def test_filter_by_network_substring() -> None:
    ips = {p.client_id.ip for p in select_profiles(RESULT, client=None, kind=None, network="aws")}
    assert ips == {"a", "c"}  # case-insensitive substring of the network label


def test_network_and_kind_compose_to_one_cell() -> None:
    sel = select_profiles(RESULT, client=None, kind="vuln_scanner", network="aws")
    assert [p.client_id.ip for p in sel] == ["a"]  # the (AWS, vuln_scanner) cell


def test_network_filter_matches_residential() -> None:
    sel = select_profiles(RESULT, client=None, kind=None, network="residential")
    assert [p.client_id.ip for p in sel] == ["b"]


TAGGED = _result(
    _profile("w1", Kind.AI_CRAWLER, "Example", frozenset({"wba-verified", "datacenter"})),
    _profile("w2", Kind.AI_CRAWLER, "Example", frozenset({"wba-expired"})),
    _profile("r1", Kind.CRAWLER, "Example", frozenset({"ignores-robots"})),
    _profile("n1", Kind.BROWSER, "Example", frozenset()),
)


def test_tag_substring_selects_the_whole_family() -> None:
    # A family prefix catches every member: `wba` matches wba-verified and wba-expired.
    sel = select_profiles(TAGGED, client=None, kind=None, tag="wba")
    assert sorted(p.client_id.ip for p in sel) == ["w1", "w2"]


def test_tag_exact_selects_one() -> None:
    sel = select_profiles(TAGGED, client=None, kind=None, tag="wba-verified")
    assert [p.client_id.ip for p in sel] == ["w1"]


def test_tag_is_case_insensitive() -> None:
    sel = select_profiles(TAGGED, client=None, kind=None, tag="ROBOTS")
    assert [p.client_id.ip for p in sel] == ["r1"]


def test_tag_composes_with_kind() -> None:
    # AND semantics: wba-family AND crawler kind. w1/w2 are ai_crawler, so kind=crawler
    # excludes them and nothing carries a wba tag as a plain crawler.
    assert select_profiles(TAGGED, client=None, kind="crawler", tag="wba") == []
    sel = select_profiles(TAGGED, client=None, kind="ai_crawler", tag="wba")
    assert sorted(p.client_id.ip for p in sel) == ["w1", "w2"]


def _actor_profile(
    ip: str, ua: str, kind: Kind = Kind.AI_CRAWLER, requests: int = 10
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent=ua),
        entries=(),
        features=ClientFeatures(request_count=requests, user_agent=ua),
        classification=Classification(primary=kind, confidence=0.9, evidence=()),
        network="Example",
    )


def test_actor_expands_to_every_group_member() -> None:
    # The whole point of --actor: the lead IP copied from a grouped summary row
    # resolves to every member of that group, not just the lead -- so an operator's
    # rotation across many IPs inspects as one.
    ua = "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"
    a, b, c = (_actor_profile(ip, ua) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"))
    other = _actor_profile("9.9.9.9", "other/1")  # a different actor, must not leak in
    result = _result(a, b, c, other)

    sel = select_profiles(result, client=None, kind=None, actor="1.1.1.1")
    assert sorted(p.client_id.ip for p in sel) == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_actor_handle_is_the_group_lead_only() -> None:
    # Only the lead IP is a valid handle (it's the id the report copies); a non-lead
    # member IP matches no group and selects nothing, rather than silently returning
    # a partial set.
    ua = "bot/1"
    lead = _actor_profile("1.1.1.1", ua, requests=50)  # highest volume -> lead
    member = _actor_profile("2.2.2.2", ua, requests=10)
    result = _result(lead, member)
    assert select_profiles(result, client=None, kind=None, actor="2.2.2.2") == []


def _classified() -> ClientProfile:
    """A client whose features earn several tags, classified as inspect would see it."""
    from agent_census.classify import classify_client

    feats = ClientFeatures(
        request_count=40,
        distinct_paths=10,
        status_counts={200: 40},
        rate_regularity=0.05,
        head_ratio=0.5,
        ua_empty=False,
        user_agent="python-requests/2.31.0",
    )
    cls = classify_client(feats, datacenter=True, keep_signals=True)
    return ClientProfile(
        client_id=ClientId(ip="203.0.113.9", user_agent=feats.user_agent),
        entries=(),
        features=feats,
        classification=cls,
        network="Example Hosting",
    )


def test_brief_kind_focus_shows_attack_shape() -> None:
    # --kind vuln_scanner --brief: one compact row, columns tuned to the probe shape.
    md = render_inspect([_classified()], brief=True, kind="vuln_scanner")
    assert "brief view tuned to `--kind vuln_scanner`" in md
    header = next(ln for ln in md.splitlines() if ln.startswith("| User-Agent"))
    assert "Probe paths" in header and "Traversal" in header and "404 %" in header
    # No full per-client block in brief mode.
    assert "### Why this classification" not in md and "### Request trace" not in md


def test_brief_tag_focus_picks_family_columns() -> None:
    # A wba tag focuses the columns on the signature verdict; a robots tag on politeness.
    p = _profile("x", Kind.AI_CRAWLER, "Example", frozenset({"wba-verified"}))
    wba = render_inspect([p], brief=True, tag="wba")
    assert "| WBA |" in wba and "Operator" in wba and "Key id" in wba

    r = _profile("y", Kind.CRAWLER, "Example", frozenset({"ignores-robots"}))
    robots = render_inspect([r], brief=True, tag="robots")
    assert "| robots |" in robots and "Disallowed" in robots


def test_brief_network_focus_leads_with_identity() -> None:
    p = _profile("203.0.113.9", Kind.BROWSER, "Example Hosting")
    md = render_inspect([p], brief=True, network="hosting")
    header = next(ln for ln in md.splitlines() if ln.startswith("| IP"))
    assert "Network" in header and "Bandwidth" in header
    assert "| 203.0.113.9 |" in md.split("\n", 4)[-1]


def test_brief_generic_when_no_specific_selector() -> None:
    md = render_inspect([_classified()], brief=True)
    assert "brief view tuned to `selection`" in md
    header = next(ln for ln in md.splitlines() if ln.startswith("| User-Agent"))
    assert header.strip() == "| User-Agent | Kind | Conf. | Requests | Tags |"


def test_brief_tag_default_shows_matched_tag_evidence() -> None:
    # A tag with no dedicated family gets a "Why `<tag>`" column carrying its evidence.
    p = _classified()  # earns metronomic, generic-ua, ... under a datacenter classification
    md = render_inspect([p], brief=True, tag="metronomic")
    assert any("Why `metronomic`" in ln for ln in md.splitlines())
    assert "inter-arrival CV" in md  # the matched tag's concrete evidence rides the row


def test_inspect_shows_evidence_for_every_tag() -> None:
    # The whole point of inspect: each tag a client carries must be backed by a
    # concrete, visible reason -- in both renderers.
    profile = _classified()
    assert profile.classification.tags  # the fixture earns some tags

    md = render_inspect([profile])
    for tag in profile.classification.tags:
        line = next((ln for ln in md.splitlines() if ln.startswith(f"- `{tag}`")), None)
        assert line is not None, f"{tag} missing from inspect output"
        assert "—" in line and line.split("—", 1)[1].strip(), f"{tag} shown without evidence"

    # The same evidence rides the JSON view-model the report overlay renders.
    view = build_member_view(profile, limit=20)
    chips = {t["chip"]: t["why"] for t in view["tags"]}
    for tag in profile.classification.tags:
        chip = next((c for c in chips if f">{tag}</span>" in c), None)
        assert chip is not None, f"{tag} missing from inspect data"
        assert chips[chip], f"{tag} shown without evidence"
