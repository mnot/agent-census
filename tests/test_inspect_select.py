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


def _profile(ip: str, kind: Kind, network: str) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent="ua"),
        entries=(),
        features=ClientFeatures(),
        classification=Classification(primary=kind, confidence=0.9, evidence=()),
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
