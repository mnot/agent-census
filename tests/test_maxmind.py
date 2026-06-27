"""MaxMind ASN resolution: the reader wrapper, the pipeline precedence, the skew warning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_census import cli, identity, pipeline
from agent_census.cli import _maxmind_paths, _warn_maxmind_skew
from agent_census.errors import ConfigError
from agent_census.maxmind import (
    AsnResolver,
    CountryHit,
    CountryResolver,
    DiscoveredDbs,
    discover_mm_dir,
)
from agent_census.parsing import resolve
from agent_census.parsing.apache import PRESETS

_COMBINED = PRESETS["combined"]  # no AS field
_WITH_ASN = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%{MM_ASN}e"'
_IP = "203.0.113.7"


class _FakeReader:
    """Stand-in for a maxminddb reader: a dict lookup, no real database needed."""

    def __init__(self, table: dict[str, object], raise_on: str | None = None) -> None:
        self.table = table
        self.raise_on = raise_on

    def get(self, ip: str) -> object:
        if ip == self.raise_on:
            raise ValueError("not a valid IP address")
        return self.table.get(ip)

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _resolver(table: dict[str, object], **kw: object) -> AsnResolver:
    return AsnResolver(_FakeReader(table, **kw))  # type: ignore[arg-type]


def test_lookup_extracts_asn_and_org() -> None:
    r = _resolver({_IP: {"autonomous_system_number": 64500, "autonomous_system_organization": "Ex"}})
    assert r.lookup(_IP) == (64500, "Ex")


def test_lookup_handles_miss_partial_and_bad_ip() -> None:
    assert _resolver({}).lookup(_IP) == (None, None)  # not in DB -> get() returns None
    # A record with only one of the two fields, or a non-int ASN, degrades gracefully.
    assert _resolver({_IP: {"autonomous_system_number": 7}}).lookup(_IP) == (7, None)
    assert _resolver({_IP: {"autonomous_system_organization": "Ex"}}).lookup(_IP) == (None, "Ex")
    # An invalid address makes the reader raise; we swallow it.
    assert _resolver({}, raise_on=_IP).lookup(_IP) == (None, None)


def _country(table: dict[str, object], **kw: object) -> CountryResolver:
    return CountryResolver(_FakeReader(table, **kw))  # type: ignore[arg-type]


def test_country_lookup_extracts_code_and_name() -> None:
    r = _country({_IP: {"country": {"iso_code": "DE", "names": {"en": "Germany"}}}})
    assert r.lookup(_IP) == CountryHit("DE", "Germany")


def test_country_lookup_handles_miss_partial_and_bad_ip() -> None:
    assert _country({}).lookup(_IP) == CountryHit()  # not in DB
    # Code present but no English name -> name degrades to None.
    assert _country({_IP: {"country": {"iso_code": "FR"}}}).lookup(_IP) == CountryHit("FR", None)
    # A record without a country block at all.
    assert _country({_IP: {"continent": {"code": "EU"}}}).lookup(_IP) == CountryHit()
    # An invalid address makes the reader raise; we swallow it.
    assert _country({}, raise_on=_IP).lookup(_IP) == CountryHit()


def test_country_lookup_suppresses_anycast_and_proxy_traits() -> None:
    base = {"country": {"iso_code": "US", "names": {"en": "United States"}}}
    for trait in ("is_anycast", "is_anonymous_proxy", "is_satellite_provider"):
        hit = _country({_IP: {**base, "traits": {trait: True}}}).lookup(_IP)
        assert hit == CountryHit("US", "United States", suppressed=True), trait
    # Traits present but all false -> not suppressed.
    hit = _country({_IP: {**base, "traits": {"is_anycast": False}}}).lookup(_IP)
    assert hit.suppressed is False


def _one_line(tmp_path: Path, line: str, fmt: str, resolver: AsnResolver | None) -> object:
    log = tmp_path / "a.log"
    log.write_text(line + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(
        log, parser, identity.get_strategy("ip_ua"), verifier=None, asn_resolver=resolver
    )
    (profile,) = result.profiles
    return profile.features


def _line(ip: str, asn: str | None = None) -> str:
    base = f'{ip} - - [10/Oct/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 9 "-" "curl/8"'
    return base if asn is None else f'{base} "{asn}"'


def test_db_fills_missing_asn(tmp_path: Path) -> None:
    r = _resolver({_IP: {"autonomous_system_number": 64500, "autonomous_system_organization": "Ex"}})
    feats = _one_line(tmp_path, _line(_IP), _COMBINED, r)
    assert feats.as_number == "64500"
    assert feats.as_org == "Ex"


def test_db_wins_over_logged_asn(tmp_path: Path) -> None:
    # The log says AS99999; the DB says AS64500 -> the DB wins (it can be fresher).
    r = _resolver({_IP: {"autonomous_system_number": 64500, "autonomous_system_organization": "Ex"}})
    feats = _one_line(tmp_path, _line(_IP, "99999"), _WITH_ASN, r)
    assert feats.as_number == "64500"


def test_logged_asn_kept_when_db_has_no_answer(tmp_path: Path) -> None:
    # DB doesn't know this IP -> fall back to the logged AS.
    feats = _one_line(tmp_path, _line(_IP, "99999"), _WITH_ASN, _resolver({}))
    assert feats.as_number == "99999"


def _skew_result(when: datetime) -> object:
    feats = SimpleNamespace(first_seen=when, last_seen=when)
    return SimpleNamespace(profiles=[SimpleNamespace(features=feats)])


def test_skew_warning_fires_when_db_is_far_off(capsys: pytest.CaptureFixture[str]) -> None:
    log_time = datetime(2023, 1, 1, tzinfo=timezone.utc)
    built_late = log_time + timedelta(days=300)
    r = _resolver({}, )
    r.build_epoch = int(built_late.timestamp())
    _warn_maxmind_skew(r, _skew_result(log_time), "AS attributions")  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "MaxMind database was built" in err and "after" in err


def test_no_skew_warning_within_window(capsys: pytest.CaptureFixture[str]) -> None:
    log_time = datetime(2023, 1, 1, tzinfo=timezone.utc)
    r = _resolver({})
    r.build_epoch = int((log_time + timedelta(days=30)).timestamp())
    _warn_maxmind_skew(r, _skew_result(log_time), "AS attributions")  # type: ignore[arg-type]
    assert capsys.readouterr().err == ""


def _mkdir_with(tmp_path: Path, names: tuple[str, ...]) -> Path:
    """A directory holding empty placeholder .mmdb files (type comes from the injected map)."""
    d = tmp_path / "dbs"
    d.mkdir(parents=True)
    for name in names:
        (d / name).touch()
    return d


def _type_map(mapping: dict[str, str]):
    return lambda path: mapping.get(path.name)


def test_discover_routes_asn_and_country_by_metadata(tmp_path: Path) -> None:
    # Filenames are deliberately non-canonical; routing is by metadata type, not name.
    d = _mkdir_with(tmp_path, ("a.mmdb", "b.mmdb"))
    types = {"a.mmdb": "GeoLite2-ASN", "b.mmdb": "GeoIP2-Country"}
    found = discover_mm_dir(d, type_of=_type_map(types))
    assert found.asn == d / "a.mmdb"
    assert found.country == d / "b.mmdb"


def test_discover_prefers_country_over_city(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("city.mmdb", "country.mmdb"))
    types = {"city.mmdb": "GeoIP2-City", "country.mmdb": "GeoLite2-Country"}
    found = discover_mm_dir(d, type_of=_type_map(types))
    assert found.country == d / "country.mmdb"  # Country wins over City


def test_discover_city_alone_fills_country_role(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("only.mmdb",))
    found = discover_mm_dir(d, type_of=_type_map({"only.mmdb": "GeoIP2-City"}))
    assert found.country == d / "only.mmdb" and found.asn is None


def test_discover_isp_fills_asn_and_enterprise_fills_both(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("isp.mmdb",))
    assert discover_mm_dir(d, type_of=_type_map({"isp.mmdb": "GeoIP2-ISP"})).asn == d / "isp.mmdb"
    e = _mkdir_with(tmp_path / "x", ("ent.mmdb",))
    found = discover_mm_dir(e, type_of=_type_map({"ent.mmdb": "GeoIP2-Enterprise"}))
    assert found.asn == e / "ent.mmdb" and found.country == e / "ent.mmdb"


def test_discover_dedicated_asn_beats_isp(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("isp.mmdb", "asn.mmdb"))
    types = {"isp.mmdb": "GeoIP2-ISP", "asn.mmdb": "GeoLite2-ASN"}
    assert discover_mm_dir(d, type_of=_type_map(types)).asn == d / "asn.mmdb"


def test_discover_empty_dir_finds_nothing(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("readme.txt",))  # no .mmdb
    found = discover_mm_dir(d, type_of=_type_map({}))
    assert found.asn is None and found.country is None


def test_discover_unreadable_files_are_skipped(tmp_path: Path) -> None:
    d = _mkdir_with(tmp_path, ("good.mmdb", "broken.mmdb"))
    types = {"good.mmdb": "GeoLite2-Country"}  # broken.mmdb -> None (unreadable)
    found = discover_mm_dir(d, type_of=_type_map(types))
    assert found.country == d / "good.mmdb" and found.asn is None


def test_discover_rejects_non_directory(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(ConfigError):
        discover_mm_dir(missing)


def _mm_args(**kw: object) -> SimpleNamespace:
    base = {"mm_asn_db": None, "mm_country_db": None, "mm_db_dir": None}
    base.update(kw)
    return SimpleNamespace(**base)


def test_maxmind_paths_explicit_overrides_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli, "discover_mm_dir", lambda d: DiscoveredDbs(asn=Path("dir-asn"), country=Path("dir-cc"))
    )
    asn, country = _maxmind_paths(_mm_args(mm_asn_db=Path("flag-asn"), mm_db_dir=Path("/x")))
    assert asn == Path("flag-asn")  # explicit flag wins for its role
    assert country == Path("dir-cc")  # the directory fills the role left unset


def test_maxmind_paths_warns_when_dir_yields_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "discover_mm_dir", lambda d: DiscoveredDbs())
    assert _maxmind_paths(_mm_args(mm_db_dir=Path("/empty"))) == (None, None)
    assert "no ASN or country .mmdb" in capsys.readouterr().err
