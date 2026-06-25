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
    assert "<span class='tri'>▶</span>2 IPs" in html
    assert "9.9.9.1" in html and "9.9.9.2" in html  # both members listed as rows
    assert "class='amem'" in html  # members are real table rows, not a sub-table
    assert "Acme (AS64500)" in html  # member AS shown
    assert ">12<" in html  # summed requests in the summary row
    # Members reuse the existing Requests column with their own counts.
    assert ">8<" in html and ">4<" in html
    assert "<table class='members'>" not in html  # no separate sub-table


def test_folded_single_entry_shows_ips_and_sample_ua() -> None:
    # An ASN-folded entry: one profile, UA-less id but a sample UA in features,
    # and its clustered IPs in member_ips. Both must surface in the report.
    prof = ClientProfile(
        client_id=ClientId(ip="Sberbank", user_agent=None),
        entries=(),
        features=ClientFeatures(
            request_count=120,
            total_bytes=5000,
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/91.0 Safari/537.36",
        ),
        classification=Classification(
            primary=Kind.AI_CRAWLER, confidence=0.6, evidence=("ASN",), tags=frozenset({"asn-attributed"})
        ),
        member_ips=("5.188.0.1", "5.188.7.2", "93.158.0.3"),
        network="Sberbank",
    )
    html = html_section(Kind.AI_CRAWLER, [prof], _rollup(clients=1, requests=120), top=5)
    assert "tbody class='actor'" in html  # collapsible, not a bare row
    assert "· 3 IPs" in html  # the cluster size
    assert "5.188.0.1" in html and "93.158.0.3" in html  # the clustered IPs listed
    assert "Chrome/91.0" in html  # a sample UA, despite the UA-less id

    # Markdown surfaces the count and points at inspect for the list.
    md = md_section(Kind.AI_CRAWLER, [prof], _rollup(clients=1, requests=120), top=5)
    text = "\n".join(md)
    assert "Sberbank (3 IPs)" in text and "inspect --kind ai_crawler" in text


def test_typical_conduct_hoisted_to_header_and_dropped_from_rows() -> None:
    from agent_census.report.aggregate import typical_conduct

    profs = [
        _profile(f"9.9.9.{i}", "scan/1", tags=frozenset({"probing", "bursty"}), requests=5)
        for i in range(4)
    ]
    # Only the conduct tag is "typical"; bursty is a fingerprint dimension.
    assert typical_conduct(profs) == frozenset({"probing"})

    md = md_section(Kind.VULN_SCANNER, profs, _rollup(clients=4, requests=20), top=5)
    text = "\n".join(md)
    assert "_Typically: probing._" in text
    # probing is hoisted: rows show the fingerprint (bursty) but not the baseline.
    rows = [ln for ln in md if "scan/1" in ln]
    assert rows and all("bursty" in ln and "probing" not in ln for ln in rows)

    html = html_section(Kind.VULN_SCANNER, profs, _rollup(clients=4, requests=20), top=5)
    assert "Typically:" in html


def test_html_single_client_is_not_collapsed() -> None:
    html = html_section(Kind.SCRAPER, [_profile("9.9.9.1", "solo/1")], _rollup(1, 10), top=5)
    assert "tbody class='actor'" not in html
    assert 'data-copy="9.9.9.1"' in html  # ordinary copyable client cell
