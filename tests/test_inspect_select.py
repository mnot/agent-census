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
from agent_census.report import render_inspect, render_inspect_html, select_profiles


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

    html = render_inspect_html([profile])
    for tag in profile.classification.tags:
        assert f">{tag}</span>" in html  # rendered as a tag chip in the Tags section
