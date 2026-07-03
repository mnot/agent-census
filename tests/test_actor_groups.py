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
    # Same UA, but one carries an extra identity/conduct tag -> two groups, not one.
    profiles = [
        _profile("1.1.1.1", "bot/1", tags=frozenset({"datacenter"})),
        _profile("2.2.2.2", "bot/1", tags=frozenset({"datacenter", "probe-paths"})),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 2
    assert all(not g.collapsed for g in groups)


def test_group_actors_merges_across_observational_tags() -> None:
    # Same UA, differing only by an incidental per-batch observation (checked-robots,
    # which has no opposing pole) -> one collapsed group, tag still shown: any member
    # earning it is enough.
    profiles = [
        _profile("1.1.1.1", "bot/1", tags=frozenset({"datacenter"})),
        _profile("2.2.2.2", "bot/1", tags=frozenset({"datacenter", "checked-robots"})),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 1
    group = groups[0]
    assert group.collapsed and len(group.members) == 2
    assert group.observational_tags == frozenset({"checked-robots"})


def test_group_actors_merges_across_relative_and_fingerprint_observational_tags() -> None:
    # Same UA, WBA/IP-verified, declares-known-bot -- but the members differ in
    # traffic-mix facts that shouldn't split an already-identified crawler: cadence
    # (bursty), asset co-load (no-assets), and a magnitude tag defined outside
    # tags.py (long-session, from classify/relative.py). All fold into one row.
    profiles = [
        _profile(
            "1.1.1.1",
            "bot/1",
            tags=frozenset({"wba-verified", "ip-verified", "declares-known-bot"}),
        ),
        _profile(
            "2.2.2.2",
            "bot/1",
            tags=frozenset(
                {"wba-verified", "ip-verified", "declares-known-bot", "bursty", "no-assets"}
            ),
        ),
        _profile(
            "3.3.3.3",
            "bot/1",
            tags=frozenset(
                {"wba-verified", "ip-verified", "declares-known-bot", "long-session"}
            ),
        ),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 1
    group = groups[0]
    assert group.collapsed and len(group.members) == 3
    assert group.observational_tags == frozenset({"bursty", "no-assets", "long-session"})


def test_group_actors_merges_and_shows_both_poles_when_members_disagree() -> None:
    # has-cache and lacks-cache are opposite poles of one fact, enforced mutually
    # exclusive per profile -- still merges (both are excluded from the fold key),
    # and both show on the row: seeing both poles together can only mean the
    # members disagree, which is a true, informative fact about the group ("some
    # members cache, some don't"), not a contradiction to hide.
    profiles = [
        _profile("1.1.1.1", "bot/1", tags=frozenset({"datacenter", "has-cache"})),
        _profile("2.2.2.2", "bot/1", tags=frozenset({"datacenter", "lacks-cache"})),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 1
    group = groups[0]
    assert group.collapsed
    assert group.observational_tags == frozenset({"has-cache", "lacks-cache"})


def test_group_actors_never_shows_singleton_on_a_folded_row() -> None:
    # Both members individually made exactly one request, but the merged actor's
    # total is 2 -- "singleton" would misrepresent the group even though every
    # member carries it, so unlike the other observational tags it's excluded from
    # display outright rather than unioned.
    profiles = [
        _profile("1.1.1.1", "bot/1", requests=1, tags=frozenset({"datacenter", "singleton"})),
        _profile("2.2.2.2", "bot/1", requests=1, tags=frozenset({"datacenter", "singleton"})),
    ]
    groups = group_actors(profiles)
    assert len(groups) == 1
    group = groups[0]
    assert group.requests == 2
    assert "singleton" not in group.observational_tags


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
    # The disclosure is a real button (focusable, Enter/Space-operable, with an
    # accessible label); the footprint sits right after it, wrapped in the isolated
    # copy-id span (data-copy on the span, so clicking the id copies but clicking the
    # rest of the row toggles).
    assert 'class="tri" aria-expanded="false"' in html
    assert "▶</button><span class='idcopy' data-copy=\"9.9.9.1\"" in html
    assert ">2 IPs" in html  # footprint inside the copy span
    assert "9.9.9.1" in html and "9.9.9.2" in html  # both members listed as rows
    assert "class='amem'" in html  # members are real table rows, not a sub-table
    assert "Acme (AS64500)" in html  # member AS shown
    assert ">12<" in html  # summed requests in the summary row
    # Members reuse the existing Requests column with their own counts.
    assert ">8<" in html and ">4<" in html
    assert "<table class='members'>" not in html  # no separate sub-table


def test_html_collapsed_summary_copies_lead_id_for_inspect_actor() -> None:
    # The grouped summary row is a toggle, so its copy-id is an isolated inline
    # target (data-copy on a span, not the whole cell): it copies the lead IP for
    # `inspect --actor`, which expands to every member. Clicking elsewhere on the
    # row still toggles the disclosure.
    profiles = [
        _profile("9.9.9.1", "bot/1", requests=8),
        _profile("9.9.9.2", "bot/1", requests=4),
    ]
    html = html_section(Kind.SCRAPER, profiles, _rollup(clients=2, requests=12), top=5)
    assert "class='idcopy' data-copy=\"9.9.9.1\"" in html  # lead IP is the copy target
    assert "inspect --actor" in html
    # Members inside the disclosure keep their own per-IP copy-id for `--client`.
    assert 'data-copy="9.9.9.2"' in html and "inspect --client" in html


def test_html_folded_member_ips_are_not_click_to_copy() -> None:
    # A fold merges its IPs into one profile, so an individual clustered IP resolves
    # to nothing under inspect -- its row must not offer a misleading copy-id. The
    # summary carries the copyable id (the lead prefix, for `inspect --actor`).
    prof = ClientProfile(
        client_id=ClientId(ip="Sberbank", user_agent=None),
        entries=(),
        features=ClientFeatures(request_count=120, total_bytes=5000, user_agent="Chrome/91.0"),
        classification=Classification(
            primary=Kind.AI_CRAWLER, confidence=0.6, evidence=("ASN",),
            tags=frozenset({"asn-attributed"}),
        ),
        member_ips=("5.188.0.1", "5.188.7.2"),
        network="Sberbank",
    )
    html = html_section(Kind.AI_CRAWLER, [prof], _rollup(clients=1, requests=120), top=5)
    assert "5.188.0.1" in html  # the clustered IP is still listed
    assert 'data-copy="5.188.0.1"' not in html  # but not as a copy target
    assert "class='idcopy' data-copy=\"Sberbank\"" in html  # the summary is the copy id
    assert "inspect --actor" in html


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


def test_collapsed_group_names_single_shared_asn() -> None:
    # Every member with an ASN shares the same one -> name it instead of "1 ASNs".
    profiles = [
        _profile("9.9.9.1", "bot/1", requests=6, as_org="Acme", as_number="64500"),
        _profile("9.9.9.2", "bot/1", requests=4, as_org="Acme", as_number="64500"),
    ]
    md = "\n".join(md_section(Kind.SCRAPER, profiles, _rollup(2, 10), top=5))
    assert "2 IPs · Acme (AS64500)" in md
    assert "1 ASNs" not in md  # the bare count is replaced by the AS name

    html = html_section(Kind.SCRAPER, profiles, _rollup(2, 10), top=5)
    assert "2 IPs" in html and "Acme (AS64500)" in html
    assert "1 ASNs" not in html


def test_collapsed_group_with_several_asns_keeps_the_count() -> None:
    profiles = [
        _profile("9.9.9.1", "bot/1", requests=6, as_org="Acme", as_number="64500"),
        _profile("9.9.9.2", "bot/1", requests=4, as_org="Other", as_number="64501"),
    ]
    md = "\n".join(md_section(Kind.SCRAPER, profiles, _rollup(2, 10), top=5))
    assert "2 IPs · 2 ASNs" in md  # no single AS to name -> the count stays
    assert "AS64500" not in md


def test_conduct_tags_shown_on_every_row_not_hoisted() -> None:
    # A conduct tag shared by all of a kind's clients (probe-paths on scanners) is
    # shown on each row, not summarised in a section header -- an omitted tag that
    # still fires is more confusing than the repetition.
    profs = [
        _profile(f"9.9.9.{i}", "scan/1", tags=frozenset({"probe-paths", "bursty"}), requests=5)
        for i in range(4)
    ]

    md = md_section(Kind.VULN_SCANNER, profs, _rollup(clients=4, requests=20), top=5)
    text = "\n".join(md)
    assert "Typically:" not in text
    rows = [ln for ln in md if "scan/1" in ln]
    assert rows and all("bursty" in ln and "probe-paths" in ln for ln in rows)

    html = html_section(Kind.VULN_SCANNER, profs, _rollup(clients=4, requests=20), top=5)
    assert "Typically:" not in html
    assert "probe-paths" in html


def test_html_single_client_is_not_collapsed() -> None:
    html = html_section(Kind.SCRAPER, [_profile("9.9.9.1", "solo/1")], _rollup(1, 10), top=5)
    assert "tbody class='actor'" not in html
    assert 'data-copy="9.9.9.1"' in html  # ordinary copyable client cell
