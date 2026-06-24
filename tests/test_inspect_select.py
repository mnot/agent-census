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
from agent_census.report import select_profiles


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
