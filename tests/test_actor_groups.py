"""Tests for render-time actor grouping (clients differing only by IP/ASN)."""

from __future__ import annotations

from agent_census.model import Classification, ClientFeatures, ClientId, ClientProfile, Kind
from agent_census.report.aggregate import group_actors
from agent_census.report.html import _kind_section as html_section
from agent_census.report.markdown import _kind_section as md_section
from agent_census.pipeline import KindRollup


def _profile(
    ip: str,
    ua: str,
    *,
    tags: frozenset[str] = frozenset(),
    requests: int = 10,
    total_bytes: int = 100,
    as_org: str | None = None,
    as_number: str | None = None,
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent=ua),
        entries=(),
        features=ClientFeatures(
            request_count=requests, total_bytes=total_bytes, as_org=as_org, as_number=as_number
        ),
        classification=Classification(
            primary=Kind.SCRAPER, confidence=0.7, evidence=("cold hits",), tags=tags
        ),
    )


def test_group_actors_merges_same_ua_and_tags() -> None:
    profiles = [
        _profile("1.1.1.1", "bot/1", requests=5, as_number="64500"),
        _profile("2.2.2.2", "bot/1", requests=7, as_number="64501"),
        _profile("3.3.3.3", "bot/1", requests=3),  # no ASN
    ]
    groups = group_actors(profiles)
    assert len(groups) == 1
    group = groups[0]
    assert group.collapsed and len(group.members) == 3
    assert group.requests == 15 and group.distinct_ips == 3 and group.distinct_asns == 2
    # members ordered by request volume
    assert [m.client_id.ip for m in group.members] == ["2.2.2.2", "1.1.1.1", "3.3.3.3"]


def test_group_actors_splits_on_differing_tags() -> None:
    # Same UA, but one carries an extra tag -> two groups, not one.
    profiles = [
        _profile("1.1.1.1", "bot/1", tags=frozenset({"datacenter"})),
        _profile("2.2.2.2", "bot/1", tags=frozenset({"datacenter", "has-cache"})),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 2
    assert all(not g.collapsed for g in groups)


def test_group_actors_sorts_groups_by_requests() -> None:
    profiles = [
        _profile("1.1.1.1", "small/1", requests=2),
        _profile("2.2.2.2", "big/1", requests=50),
        _profile("3.3.3.3", "big/1", requests=50),
    ]
    groups = group_actors(profiles)
    assert groups[0].lead.client_id.user_agent == "big/1"  # 100 reqs > 2
    assert groups[0].requests == 100


def _rollup(clients: int, requests: int) -> KindRollup:
    return KindRollup(clients=clients, requests=requests)


def test_markdown_collapses_into_summary_row_with_hint() -> None:
    profiles = [_profile(f"9.9.9.{i}", "bot/1", requests=4) for i in range(4)]
    lines = md_section(Kind.SCRAPER, profiles, _rollup(clients=4, requests=16), top=5)
    text = "\n".join(lines)
    assert "4 IPs" in text  # collapsed footprint, not four rows
    assert "| 16 |" in text  # requests summed across the group
    assert "inspect --kind scraper" in text  # the per-IP/ASN hint
    assert "9.9.9.0" not in text  # individual IPs are not spelled out in Markdown


def test_html_collapsed_group_lists_members_in_a_disclosure() -> None:
    profiles = [
        _profile("9.9.9.1", "bot/1", requests=8, as_org="Acme", as_number="64500"),
        _profile("9.9.9.2", "bot/1", requests=4),
    ]
    html = html_section(Kind.SCRAPER, profiles, _rollup(clients=2, requests=12), top=5)
    assert "tbody class='actor'" in html
    # Footprint sits right after the triangle in the summary row.
    assert "<span class='tri'>▸</span>2 IPs" in html
    assert "9.9.9.1" in html and "9.9.9.2" in html  # both members listed as rows
    assert "class='amem'" in html  # members are real table rows, not a sub-table
    assert "Acme (AS64500)" in html  # member AS shown
    assert ">12<" in html  # summed requests in the summary row
    # Members reuse the existing Requests column with their own counts.
    assert ">8<" in html and ">4<" in html
    assert "<table class='members'>" not in html  # no separate sub-table


def test_html_single_client_is_not_collapsed() -> None:
    html = html_section(Kind.SCRAPER, [_profile("9.9.9.1", "solo/1")], _rollup(1, 10), top=5)
    assert "tbody class='actor'" not in html
    assert 'data-copy="9.9.9.1"' in html  # ordinary copyable client cell
