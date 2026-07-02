"""Tests for the ``agent-census wba-check`` subcommand (no network: ``_fetch`` is
monkeypatched at the module boundary, same pattern as ``test_wba.py``'s verifier
tests)."""

from __future__ import annotations

import json

import pytest

from agent_census import wba_check
from agent_census.wba import jwk_thumbprint

# A real key pair's worth of fixture data, reused from test_wba.py's baked Ahrefs
# directory so the thumbprints are known-good.
AHREFS_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "0g1xFRWdVlSOm1h92tZ4VFl7FWGtvRnTZ0PwuBdJuDU",
    "kid": "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g",
}
AHREFS_THUMBPRINT = "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g"
assert jwk_thumbprint(AHREFS_JWK) == AHREFS_THUMBPRINT  # sanity-check the fixture itself


def _fake_fetch(
    status: int | None,
    content_type: str | None,
    body: bytes | None,
    error: str | None = None,
):
    def fetch(_url: str):
        return status, content_type, body, error

    return fetch


def _directory(*keys: dict) -> bytes:
    return json.dumps({"keys": list(keys)}).encode("utf-8")


# --- _origin ----------------------------------------------------------------


def test_origin_defaults_to_https_for_a_bare_host() -> None:
    origin, checks = wba_check._origin("example.com")
    assert origin == "https://example.com"
    assert checks == []


def test_origin_accepts_a_url_ignoring_path() -> None:
    origin, checks = wba_check._origin("https://example.com/some/path")
    assert origin == "https://example.com"
    assert checks == []


def test_origin_flags_non_https_scheme() -> None:
    origin, checks = wba_check._origin("http://example.com")
    assert origin == "http://example.com"  # still returned, so the fetch can proceed
    assert len(checks) == 1
    assert checks[0].level == "error"
    assert "https" in checks[0].message


def test_origin_rejects_unparseable_input() -> None:
    origin, checks = wba_check._origin("not a host!!")
    assert origin is None
    assert len(checks) == 1
    assert checks[0].level == "error"


# --- _check_key ---------------------------------------------------------------


def test_check_key_accepts_a_valid_ed25519_key() -> None:
    checks, thumbprint = wba_check._check_key(0, AHREFS_JWK)
    assert thumbprint == AHREFS_THUMBPRINT
    assert [c.level for c in checks] == ["ok"]


def test_check_key_flags_kid_thumbprint_mismatch() -> None:
    bad = {**AHREFS_JWK, "kid": "not-the-thumbprint"}
    checks, thumbprint = wba_check._check_key(0, bad)
    # Still usable (we key on the recomputed thumbprint), but flagged as an error.
    assert thumbprint == AHREFS_THUMBPRINT
    assert any(c.level == "error" and "does not match" in c.message for c in checks)


def test_check_key_accepts_absent_kid() -> None:
    no_kid = {k: v for k, v in AHREFS_JWK.items() if k != "kid"}
    checks, thumbprint = wba_check._check_key(0, no_kid)
    assert thumbprint == AHREFS_THUMBPRINT
    assert [c.level for c in checks] == ["ok"]


def test_check_key_warns_on_non_ed25519_key() -> None:
    checks, thumbprint = wba_check._check_key(0, {"kty": "RSA"})
    assert thumbprint is None
    assert checks[0].level == "warn"


def test_check_key_errors_on_malformed_key() -> None:
    checks, thumbprint = wba_check._check_key(0, {"kty": "OKP", "crv": "Ed25519"})  # no 'x'
    assert thumbprint is None
    assert checks[0].level == "error"


def test_check_key_errors_on_non_object() -> None:
    checks, thumbprint = wba_check._check_key(0, "not a dict")
    assert thumbprint is None
    assert checks[0].level == "error"


# --- check_host: the full flow, _fetch monkeypatched -------------------------


def test_check_host_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _directory(AHREFS_JWK)
    monkeypatch.setattr(
        wba_check,
        "_fetch",
        _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, body),
    )
    checks, origin, keyids = wba_check.check_host("ahrefs.com")
    assert origin == "https://ahrefs.com"
    assert keyids == [AHREFS_THUMBPRINT]
    assert not any(c.level == "error" for c in checks)


def test_check_host_flags_wrong_content_type(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _directory(AHREFS_JWK)
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(200, "application/json", body))
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == [AHREFS_THUMBPRINT]  # still usable
    assert any(c.level == "warn" and "Content-Type" in c.message for c in checks)


def test_check_host_reports_fetch_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(None, None, None, "connection refused"))
    checks, origin, keyids = wba_check.check_host("example.com")
    assert origin == "https://example.com"
    assert keyids == []
    assert checks[-1].level == "error"
    assert "connection refused" in checks[-1].message


def test_check_host_reports_http_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(404, None, None, "HTTP 404"))
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == []
    assert any(c.level == "error" and "404" in c.message for c in checks)


def test_check_host_rejects_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        wba_check,
        "_fetch",
        _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, b"not json"),
    )
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == []
    assert any(c.level == "error" and "JSON" in c.message for c in checks)


def test_check_host_rejects_missing_keys_array(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"not_keys": []}).encode("utf-8")
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, body))
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == []
    assert any(c.level == "error" and "keys" in c.message for c in checks)


def test_check_host_rejects_empty_keys_array(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _directory()
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, body))
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == []
    assert any(c.level == "error" and "empty" in c.message for c in checks)


def test_check_host_flags_duplicate_thumbprints(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _directory(AHREFS_JWK, AHREFS_JWK)
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, body))
    checks, _origin, keyids = wba_check.check_host("example.com")
    assert keyids == [AHREFS_THUMBPRINT]  # only counted once
    assert any(c.level == "warn" and "duplicate" in c.message for c in checks)


def test_check_host_short_circuits_on_unparseable_host() -> None:
    checks, origin, keyids = wba_check.check_host("not a host!!")
    assert origin == ""
    assert keyids == []
    assert checks[0].level == "error"


# --- run(): exit code + rendered output ---------------------------------------


def test_run_returns_zero_and_renders_toml_snippet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _directory(AHREFS_JWK)
    monkeypatch.setattr(
        wba_check,
        "_fetch",
        _fake_fetch(200, wba_check._EXPECTED_CONTENT_TYPE, body),
    )
    assert wba_check.run("ahrefs.com") == 0
    out = capsys.readouterr().out
    assert "[[operator]]" in out
    assert 'agent_urls = ["https://ahrefs.com"]' in out
    assert AHREFS_THUMBPRINT in out


def test_run_returns_nonzero_on_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(wba_check, "_fetch", _fake_fetch(404, None, None, "HTTP 404"))
    assert wba_check.run("example.com") == 1
    out = capsys.readouterr().out
    assert "[error]" in out
    assert "[[operator]]" not in out  # nothing usable to paste
