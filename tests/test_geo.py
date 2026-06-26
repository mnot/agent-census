"""Tests for report-time country-flag annotation (report/geo.py)."""

from __future__ import annotations

from agent_census.maxmind import CountryResolver
from agent_census.model import Classification, ClientFeatures, ClientId, ClientProfile, Kind
from agent_census.pipeline import KindRollup
from agent_census.report.geo import _FLAG_TOP, _flag_emoji, country_flags
from agent_census.report.html import _kind_section as html_section
from agent_census.report.markdown import _kind_section as md_section


class _FakeReader:
    """Dict-backed stand-in for a maxminddb reader."""

    def __init__(self, table: dict[str, object]) -> None:
        self.table = table

    def get(self, ip: str) -> object:
        return self.table.get(ip)

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _resolver(ip_to_country: dict[str, tuple[str, str]]) -> CountryResolver:
    table = {ip: {"country": {"iso_code": code, "names": {"en": name}}}
             for ip, (code, name) in ip_to_country.items()}
    return CountryResolver(_FakeReader(table))  # type: ignore[arg-type]


def _profile(
    ip: str,
    *,
    kind: Kind = Kind.SCRAPER,
    tags: frozenset[str] = frozenset(),
    requests: int = 10,
    member_ips: tuple[str, ...] = (),
) -> ClientProfile:
    return ClientProfile(
        client_id=ClientId(ip=ip, user_agent="bot/1"),
        entries=(),
        features=ClientFeatures(request_count=requests),
        classification=Classification(
            primary=kind, confidence=0.7, evidence=("e",), tags=tags
        ),
        member_ips=member_ips,
    )


def test_flag_emoji_from_iso_code() -> None:
    assert _flag_emoji("DE") == "\U0001F1E9\U0001F1EA"
    assert _flag_emoji("us") == "\U0001F1FA\U0001F1F8"  # case-insensitive
    assert _flag_emoji("USA") == ""  # not two letters
    assert _flag_emoji("D1") == ""  # not all letters


def test_eligible_scraper_gets_a_flag() -> None:
    flags = country_flags([_profile("1.1.1.1")], _resolver({"1.1.1.1": ("DE", "Germany")}))
    assert flags[ClientId(ip="1.1.1.1", user_agent="bot/1")] == ("\U0001F1E9\U0001F1EA", "Germany")


def test_human_kinds_are_excluded() -> None:
    profiles = [
        _profile("1.1.1.1", kind=Kind.BROWSER),
        _profile("2.2.2.2", kind=Kind.FEED_READER),
        _profile("3.3.3.3", kind=Kind.APP),
    ]
    res = _resolver({ip: ("DE", "Germany") for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")})
    assert country_flags(profiles, res) == {}


def test_identified_agents_are_excluded() -> None:
    res = _resolver({ip: ("US", "United States") for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")})
    for tag in ("verified", "asn-associated", "asn-attributed"):
        profiles = [_profile("1.1.1.1", kind=Kind.AI_CRAWLER, tags=frozenset({tag}))]
        assert country_flags(profiles, res) == {}, tag


def test_datacenter_tag_does_not_exclude() -> None:
    # 'datacenter' is about origin, not agent identity -> still flagged.
    flags = country_flags(
        [_profile("1.1.1.1", tags=frozenset({"datacenter"}))],
        _resolver({"1.1.1.1": ("NL", "Netherlands")}),
    )
    assert flags  # not excluded


def test_unresolved_ip_gets_no_flag() -> None:
    assert country_flags([_profile("1.1.1.1")], _resolver({})) == {}


def test_representative_ip_uses_first_member() -> None:
    # A folded entry: geolocate its first member IP, not the synthetic identity key.
    prof = _profile("cluster-key", member_ips=("9.9.9.9", "8.8.8.8"))
    flags = country_flags([prof], _resolver({"9.9.9.9": ("JP", "Japan")}))
    assert flags[prof.client_id] == ("\U0001F1EF\U0001F1F5", "Japan")


def test_top_n_per_kind_cap() -> None:
    # More than _FLAG_TOP eligible clients in one kind: only the busiest get flagged.
    profiles = [_profile(f"10.0.0.{i}", requests=i) for i in range(1, _FLAG_TOP + 6)]
    res = _resolver({f"10.0.0.{i}": ("DE", "Germany") for i in range(1, _FLAG_TOP + 6)})
    flags = country_flags(profiles, res)
    assert len(flags) == _FLAG_TOP
    # The lowest-volume clients (1..5) are dropped; the busiest are kept.
    assert ClientId(ip="10.0.0.1", user_agent="bot/1") not in flags
    assert ClientId(ip=f"10.0.0.{_FLAG_TOP + 5}", user_agent="bot/1") in flags


def test_cap_is_per_kind_not_global() -> None:
    # Two kinds, each over the cap -> each kind keeps up to _FLAG_TOP independently.
    scrapers = [_profile(f"10.0.0.{i}", kind=Kind.SCRAPER, requests=i)
                for i in range(1, _FLAG_TOP + 3)]
    harvesters = [_profile(f"10.1.0.{i}", kind=Kind.DATA_HARVESTER, requests=i)
                  for i in range(1, _FLAG_TOP + 3)]
    ips = {p.client_id.ip: ("DE", "Germany") for p in scrapers + harvesters}
    flags = country_flags(scrapers + harvesters, _resolver(ips))
    assert len(flags) == 2 * _FLAG_TOP


def test_markdown_section_renders_the_flag() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": ("DE", "Germany")}))
    lines = md_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5, flags=flags)
    assert any("\U0001F1E9\U0001F1EA" in line for line in lines)


def test_html_section_renders_flag_with_country_tooltip() -> None:
    prof = _profile("1.1.1.1")
    flags = country_flags([prof], _resolver({"1.1.1.1": ("DE", "Germany")}))
    html = html_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5, flags=flags)
    assert "\U0001F1E9\U0001F1EA" in html
    assert 'title="Germany"' in html


def test_html_section_without_flags_has_no_flag_span() -> None:
    prof = _profile("1.1.1.1")
    html = html_section(Kind.SCRAPER, [prof], KindRollup(clients=1, requests=10), top=5)
    assert 'class="flag"' not in html
