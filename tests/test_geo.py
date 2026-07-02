"""Tests for report-time country-flag annotation (report/geo.py)."""

from __future__ import annotations

from agent_census.maxmind import CountryResolver
from agent_census.model import Classification, ClientFeatures, ClientId, ClientProfile, Kind
from agent_census.pipeline import KindRollup
from agent_census.report.geo import (
    _FLAG_TOP,
    MULTI_ORIGIN,
    _flag_emoji,
    country_flags,
)
from agent_census.report.html import _kind_section as html_section
from agent_census.report.markdown import _kind_section as md_section

# ISO code -> English name, and the rendered (emoji, name) flag each produces.
_NAMES = {"DE": "Germany", "FR": "France", "JP": "Japan", "NL": "Netherlands", "US": "USA"}
_DE = ("\U0001F1E9\U0001F1EA", "Germany")
_FR = ("\U0001F1EB\U0001F1F7", "France")
_JP = ("\U0001F1EF\U0001F1F5", "Japan")


class _FakeReader:
    """Dict-backed stand-in for a maxminddb reader."""

    def __init__(self, table: dict[str, object]) -> None:
        self.table = table

    def get(self, ip: str) -> object:
        return self.table.get(ip)

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _resolver(ip_to_iso: dict[str, str], suppressed: tuple[str, ...] = ()) -> CountryResolver:
    table: dict[str, object] = {}
    for ip, iso in ip_to_iso.items():
        record: dict[str, object] = {"country": {"iso_code": iso, "names": {"en": _NAMES[iso]}}}
        if ip in suppressed:
            record["traits"] = {"is_anycast": True}
        table[ip] = record
    return CountryResolver(_FakeReader(table))  # type: ignore[arg-type]


def _profile(
    ip: str,
    *,
    ua: str = "bot/1",
    kind: Kind = Kind.SCRAPER,
    tags: frozenset[str] = frozenset(),
    requests: int = 10,
    member_ips: tuple[str, ...] = (),
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent=ua),
        entries=(),
        features=ClientFeatures(request_count=requests),
        classification=Classification(primary=kind, confidence=0.7, evidence=("e",), tags=tags),
        member_ips=member_ips,
    )


def test_flag_emoji_from_iso_code() -> None:
    assert _flag_emoji("DE") == _DE[0]
    assert _flag_emoji("us") == "\U0001F1FA\U0001F1F8"  # case-insensitive
    assert _flag_emoji("USA") == ""  # not two letters
    assert _flag_emoji("D1") == ""  # not all letters


def test_eligible_scraper_gets_a_flag() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": "DE"}))
    assert flags.for_actor(prof.client_id) == _DE


def test_human_kinds_are_excluded() -> None:
    profiles = [
        _profile("1.1.1.1", kind=Kind.BROWSER),
        _profile("2.2.2.2", kind=Kind.FEED_READER),
        _profile("3.3.3.3", kind=Kind.APP),
    ]
    res = _resolver({ip: "DE" for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")})
    assert country_flags(profiles, res).actors == {}


def test_identified_agents_are_excluded() -> None:
    res = _resolver({"1.1.1.1": "US"})
    for tag in ("dns-verified", "ip-verified", "wba-verified", "asn-associated", "asn-attributed"):
        profiles = [_profile("1.1.1.1", kind=Kind.AI_CRAWLER, tags=frozenset({tag}))]
        assert country_flags(profiles, res).actors == {}, tag


def test_datacenter_tag_does_not_exclude() -> None:
    # 'datacenter' is about origin, not agent identity -> still flagged.
    prof = _profile("1.1.1.1", tags=frozenset({"datacenter"}))
    flags = country_flags([prof], _resolver({"1.1.1.1": "NL"}))
    assert flags.for_actor(prof.client_id) is not None


def test_unresolved_ip_gets_no_flag() -> None:
    prof = _profile("1.1.1.1")
    assert country_flags([prof], _resolver({})).actors == {}


def test_anycast_ip_is_suppressed() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": "DE"}, suppressed=("1.1.1.1",)))
    assert flags.actors == {}


def test_traffic_weighted_majority_wins() -> None:
    # One collapsed actor (same UA+tags), 80% of traffic from DE -> DE flag, not the lead IP's.
    members = [
        _profile("1.1.1.1", requests=80),
        _profile("2.2.2.2", requests=20),
    ]
    flags = country_flags(members, _resolver({"1.1.1.1": "DE", "2.2.2.2": "FR"}))
    lead = max(members, key=lambda p: p.features.request_count).client_id
    assert flags.for_actor(lead) == _DE


def test_below_majority_is_multi_origin() -> None:
    # 60/40 split -> no country clears 70% -> the neutral multi-origin marker.
    members = [
        _profile("1.1.1.1", requests=60),
        _profile("2.2.2.2", requests=40),
    ]
    flags = country_flags(members, _resolver({"1.1.1.1": "DE", "2.2.2.2": "FR"}))
    assert flags.for_actor(members[0].client_id) == MULTI_ORIGIN


def test_exactly_seventy_percent_clears_the_cut() -> None:
    members = [
        _profile("1.1.1.1", requests=70),
        _profile("2.2.2.2", requests=30),
    ]
    flags = country_flags(members, _resolver({"1.1.1.1": "DE", "2.2.2.2": "FR"}))
    assert flags.for_actor(members[0].client_id) == _DE


def test_member_ips_fold_uses_per_ip_count_majority() -> None:
    # A folded member with no per-IP counts: 2 of 3 resolved IPs are JP -> JP.
    prof = _profile("cluster-key", member_ips=("9.9.9.9", "8.8.8.8", "7.7.7.7"))
    res = _resolver({"9.9.9.9": "JP", "8.8.8.8": "JP", "7.7.7.7": "FR"})
    flags = country_flags([prof], res)
    assert flags.for_actor(prof.client_id) == _JP
    assert flags.for_ip("9.9.9.9") == _JP and flags.for_ip("7.7.7.7") == _FR


def test_member_ips_fold_with_no_majority_gets_no_flag() -> None:
    # A 1/1 split among resolved IPs is no strict majority -> the actor isn't flagged.
    prof = _profile("cluster-key", member_ips=("9.9.9.9", "7.7.7.7"))
    flags = country_flags([prof], _resolver({"9.9.9.9": "JP", "7.7.7.7": "FR"}))
    assert flags.actors == {}
    # ...but the individual IP rows are still flagged for the HTML cluster expansion.
    assert flags.for_ip("9.9.9.9") == _JP and flags.for_ip("7.7.7.7") == _FR


def test_per_member_flags_recorded_for_collapsed_actor() -> None:
    members = [_profile("1.1.1.1", requests=80), _profile("2.2.2.2", requests=20)]
    flags = country_flags(members, _resolver({"1.1.1.1": "DE", "2.2.2.2": "FR"}))
    assert flags.for_member(members[0].client_id) == _DE
    assert flags.for_member(members[1].client_id) == _FR


def test_top_n_per_kind_cap_counts_actors() -> None:
    # Distinct UAs -> distinct actors; only the busiest _FLAG_TOP are flagged.
    profiles = [
        _profile(f"10.0.0.{i}", ua=f"bot/{i}", requests=i) for i in range(1, _FLAG_TOP + 6)
    ]
    res = _resolver({f"10.0.0.{i}": "DE" for i in range(1, _FLAG_TOP + 6)})
    flags = country_flags(profiles, res)
    assert len(flags.actors) == _FLAG_TOP
    assert ClientId(ip="10.0.0.1", user_agent="bot/1") not in flags.actors  # lowest dropped
    assert ClientId(ip=f"10.0.0.{_FLAG_TOP + 5}", user_agent=f"bot/{_FLAG_TOP + 5}") in flags.actors


def test_cap_is_per_kind_not_global() -> None:
    scrapers = [
        _profile(f"10.0.0.{i}", ua=f"s/{i}", kind=Kind.SCRAPER, requests=i)
        for i in range(1, _FLAG_TOP + 3)
    ]
    harvesters = [
        _profile(f"10.1.0.{i}", ua=f"h/{i}", kind=Kind.DATA_HARVESTER, requests=i)
        for i in range(1, _FLAG_TOP + 3)
    ]
    ips = {p.client_id.ip: "DE" for p in scrapers + harvesters}
    flags = country_flags(scrapers + harvesters, _resolver(ips))
    assert len(flags.actors) == 2 * _FLAG_TOP


def test_markdown_section_renders_the_flag() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": "DE"}))
    lines = md_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5, flags=flags)
    assert any(_DE[0] in line for line in lines)


def test_html_section_renders_flag_with_country_tooltip() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": "DE"}))
    html = html_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5, flags=flags)
    assert _DE[0] in html
    assert 'title="Germany"' in html


def test_html_collapsed_actor_shows_per_member_flags() -> None:
    members = [_profile("1.1.1.1", requests=60), _profile("2.2.2.2", requests=40)]
    flags = country_flags(members, _resolver({"1.1.1.1": "DE", "2.2.2.2": "FR"}))
    html = html_section(Kind.SCRAPER, members, KindRollup(clients=2, requests=100), top=5, flags=flags)
    assert MULTI_ORIGIN[0] in html  # summary row is multi-origin (60/40)
    assert 'title="Germany"' in html and 'title="France"' in html  # per-member rows


def test_html_section_without_flags_has_no_flag_span() -> None:
    prof = _profile("1.1.1.1")
    html = html_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5)
    assert 'class="flag"' not in html
