"""MaxMind ASN resolution: the reader wrapper, the pipeline precedence, the skew warning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_census import identity, pipeline
from agent_census.cli import _warn_maxmind_skew
from agent_census.maxmind import AsnResolver
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
    _warn_maxmind_skew(r, _skew_result(log_time))  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "MaxMind database was built" in err and "after" in err


def test_no_skew_warning_within_window(capsys: pytest.CaptureFixture[str]) -> None:
    log_time = datetime(2023, 1, 1, tzinfo=timezone.utc)
    r = _resolver({})
    r.build_epoch = int((log_time + timedelta(days=30)).timestamp())
    _warn_maxmind_skew(r, _skew_result(log_time))  # type: ignore[arg-type]
    assert capsys.readouterr().err == ""
