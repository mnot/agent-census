"""Tests for Web Bot Auth: header parsing/attribution and signature verification."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_census import identity, pipeline, wba
from agent_census.classify.tags import impersonation
from agent_census.model import (
    BotVerification,
    ClientFeatures,
    Kind,
    VerificationStatus,
    WbaResult,
    WbaStatus,
)
from agent_census.parsing import resolve

# The real Ahrefs request Mark logged on the issue (redbot.org), header values as
# they land in LogEntry.extra after the Apache LogFormat quotes are stripped.
AHREFS_SIGNATURE_INPUT = (
    'sig=("@authority" "signature-agent");created=1782543550;'
    'keyid="e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g";alg="ed25519";'
    'expires=1782543610;nonce="WK5RCGd7OHq9M7sF1kJNAlg-'
    '3p1OGWeEuzvmwuPAN-EqSV0emP-BhGURLM4tpU3uxCws1EkyG3A20jtEeSUlhw";'
    'tag="web-bot-auth"'
)
AHREFS_SIGNATURE = "sig=:iKHbu3AZMwkrIWcUdMup9RqVsKVRDvgujcjlbFbl7eEGRXyEn+ajH1305AAv6g58Tm4pOdhjfXTWi7/dkfZIDA==:"
AHREFS_SIGNATURE_AGENT = '"https://ahrefs.com"'
# Ahrefs's published Ed25519 public key (JWK `x`) whose RFC 7638 thumbprint is the
# keyid above, fetched once from ahrefs.com's directory and baked so the interop
# test is offline and deterministic.
AHREFS_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "0g1xFRWdVlSOm1h92tZ4VFl7FWGtvRnTZ0PwuBdJuDU",
    "kid": "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g",
}
AHREFS_KEYID = "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g"
# Ahrefs's real JWK directory response (two keys), as fetched once from
# ahrefs.com/.well-known/http-message-signatures-directory.
AHREFS_DIRECTORY = (
    '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"0g1xFRWdVlSOm1h92tZ4VFl7FWGtvRnTZ0PwuBdJuDU",'
    '"kid":"e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g","use":"sig"},'
    '{"kty":"OKP","crv":"Ed25519","x":"v02owuOay4qEWYA4r-BZzdwy7ySHU8o1FESfuY4ICro",'
    '"kid":"0227KWFT1389RBnlR8TLhbMaA_Of2MbNPhmlNICS7eI","use":"sig"}]}'
)
# The signature base this request must reduce to (RFC 9421 §2.5). Locks
# canonicalisation -- the part most likely to drift.
AHREFS_GOLDEN_BASE = (
    '"@authority": redbot.org\n'
    '"signature-agent": "https://ahrefs.com"\n'
    '"@signature-params": ("@authority" "signature-agent");created=1782543550;'
    'keyid="e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g";alg="ed25519";'
    'expires=1782543610;nonce="WK5RCGd7OHq9M7sF1kJNAlg-'
    '3p1OGWeEuzvmwuPAN-EqSV0emP-BhGURLM4tpU3uxCws1EkyG3A20jtEeSUlhw";'
    'tag="web-bot-auth"'
)


def _ahrefs_claim(timestamp: float | None) -> wba.WbaClaim:
    extra = {
        wba.SIGNATURE_INPUT_HEADER: AHREFS_SIGNATURE_INPUT,
        wba.SIGNATURE_HEADER: AHREFS_SIGNATURE,
        wba.SIGNATURE_AGENT_HEADER: AHREFS_SIGNATURE_AGENT,
    }
    claim = wba.build_claim(
        extra, host="redbot.org", method="GET", path="/?uri=x", timestamp=timestamp
    )
    assert claim is not None
    return claim


def test_parse_signature_input_ahrefs() -> None:
    parsed = wba.parse_signature_input(AHREFS_SIGNATURE_INPUT)
    assert set(parsed) == {"sig"}
    params = parsed["sig"]
    assert params.components == ("@authority", "signature-agent")
    assert params.keyid == "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g"
    assert params.alg == "ed25519"
    assert params.created == 1782543550
    assert params.expires == 1782543610
    assert params.tag == "web-bot-auth"
    assert params.nonce and params.nonce.startswith("WK5RCGd7")


def test_signature_input_param_types() -> None:
    # http-sf decodes params to native types: created/expires are ints, not strings.
    params = wba.parse_signature_input(AHREFS_SIGNATURE_INPUT)["sig"]
    assert isinstance(params.created, int)
    assert isinstance(params.expires, int)
    # An unquoted token-valued param (alg=ed25519) is read as its text too.
    toks = wba.parse_signature_input('s=("@path");created=1;alg=ed25519;tag="web-bot-auth"')["s"]
    assert toks.alg == "ed25519"


def test_parse_signature_bytes() -> None:
    sig = wba.parse_signature(AHREFS_SIGNATURE)
    assert set(sig) == {"sig"}
    # An Ed25519 signature is 64 bytes; http-sf decodes the byte sequence for us.
    assert isinstance(sig["sig"], bytes)
    assert len(sig["sig"]) == 64


def test_parse_signature_agent_forms() -> None:
    # Bare string (the live form, valid through directory -03).
    assert wba.parse_signature_agent('"https://ahrefs.com"') == "https://ahrefs.com"
    # Dictionary member (the -04 form).
    assert wba.parse_signature_agent('sig="https://ahrefs.com"') == "https://ahrefs.com"
    # Unescaped bare URL (invalid, but seen): accepted leniently.
    assert wba.parse_signature_agent("https://ahrefs.com") == "https://ahrefs.com"
    # Absent / empty.
    assert wba.parse_signature_agent(None) is None
    assert wba.parse_signature_agent("") is None


def test_select_web_bot_auth_among_labels() -> None:
    # A Signature-Input carrying another application label alongside ours.
    mixed = (
        'reqsig=("@method" "@path");created=1;keyid="other";tag="some-app", '
        + AHREFS_SIGNATURE_INPUT
    )
    selected = wba.select_web_bot_auth(wba.parse_signature_input(mixed))
    assert selected is not None
    label, params = selected
    assert label == "sig"
    assert params.tag == "web-bot-auth"


def test_select_web_bot_auth_absent() -> None:
    other = 'reqsig=("@method");created=1;keyid="x";tag="some-app"'
    assert wba.select_web_bot_auth(wba.parse_signature_input(other)) is None


def test_build_claim_ahrefs() -> None:
    extra = {
        wba.SIGNATURE_INPUT_HEADER: AHREFS_SIGNATURE_INPUT,
        wba.SIGNATURE_HEADER: AHREFS_SIGNATURE,
        wba.SIGNATURE_AGENT_HEADER: AHREFS_SIGNATURE_AGENT,
    }
    claim = wba.build_claim(
        extra, host="redbot.org", method="get", path="/?uri=x", timestamp=1782543551.0
    )
    assert claim is not None
    assert claim.label == "sig"
    assert claim.authority == "redbot.org"
    assert claim.method == "GET"
    assert claim.scheme == "https"
    assert claim.agent_url == "https://ahrefs.com"
    assert claim.params.keyid == "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g"


def test_build_claim_none_without_signature() -> None:
    assert wba.build_claim({}, host="x", method="GET", path="/", timestamp=None) is None
    # Signature-Input present but no web-bot-auth label -> not our claim.
    extra = {wba.SIGNATURE_INPUT_HEADER: 'a=("@path");created=1;tag="other"'}
    assert wba.build_claim(extra, host="x", method="GET", path="/", timestamp=None) is None


def _log_quote(value: str) -> str:
    """An Apache LogFormat ``"..."`` field with inner quotes backslash-escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def test_pipeline_tags_wba_and_names_operator(tmp_path: Path) -> None:
    # Mark's real Ahrefs request, rendered through an Apache log line that carries
    # the three Web Bot Auth headers, then run end-to-end. A documentation-range IP
    # (TEST-NET-3) keeps the client out of any egress/datacenter fold so the per-
    # request signature is attributed to it rather than suppressed as an aggregate.
    fmt = (
        '%h %t "%r" %>s %b "%{User-Agent}i" %{Host}i '
        '"%{Signature-Input}i" "%{Signature}i" "%{Signature-Agent}i"'
    )
    line = " ".join(
        [
            "203.0.113.10",
            "[27/Jun/2026:06:59:11 +0000]",
            '"GET /?uri=x HTTP/2.0"',
            "200",
            "461",
            _log_quote("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
            "redbot.org",
            _log_quote(AHREFS_SIGNATURE_INPUT),
            _log_quote(AHREFS_SIGNATURE),
            _log_quote(AHREFS_SIGNATURE_AGENT),
        ]
    )
    log = tmp_path / "wba.log"
    log.write_text(line + "\n", encoding="utf-8")

    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))

    signed = [p for p in result.profiles if p.wba is not None]
    assert len(signed) == 1
    profile = signed[0]
    assert profile.wba is not None
    assert profile.wba.status is WbaStatus.PRESENT  # phase 1: present, not yet verified
    assert profile.wba.operator == "Ahrefs"
    assert profile.wba.keyid == "e3vpiy0B6M1Wdxnizw3dqRSgpqS6SXM2qiQ6HtUwZ5g"
    assert "wba" in profile.classification.tags
    assert "wba-verified" not in profile.classification.tags  # no crypto in phase 1


def test_malformed_headers_are_not_claims() -> None:
    # Garbage never raises; it parses to "no claim".
    assert wba.parse_signature_input("this is not a dictionary @#$") == {}
    assert wba.parse_signature_input("") == {}
    assert wba.parse_signature(":unterminated") == {}


# --- verification (phase 2) -----------------------------------------------------


def test_jwk_thumbprint_matches_keyid() -> None:
    # The RFC 7638 thumbprint of Ahrefs's published key recomputes to its keyid.
    assert wba.jwk_thumbprint(AHREFS_JWK) == AHREFS_KEYID
    assert wba.jwk_thumbprint({"kty": "RSA"}) is None  # not an Ed25519 OKP key


def test_golden_signature_base() -> None:
    # Canonicalisation lock: the real request must reduce to exactly this base.
    base, problem = wba.build_signature_base(_ahrefs_claim(1782543551.0))
    assert problem == ""
    assert base == AHREFS_GOLDEN_BASE


def test_verify_real_ahrefs_signature_valid_and_fresh() -> None:
    key = wba.public_key_from_jwk(AHREFS_JWK)
    assert key is not None
    status, _ = wba.verify_claim(_ahrefs_claim(1782543551.0), key)  # within the window
    assert status is WbaStatus.VERIFIED


def test_verify_real_ahrefs_signature_expired() -> None:
    key = wba.public_key_from_jwk(AHREFS_JWK)
    assert key is not None
    # A valid signature whose `expires` (1782543610) is before the request time.
    status, _ = wba.verify_claim(_ahrefs_claim(1782543611.0), key)
    assert status is WbaStatus.EXPIRED


def test_verify_tampered_request_is_forged() -> None:
    key = wba.public_key_from_jwk(AHREFS_JWK)
    assert key is not None
    # Same real signature, but a different @authority -> base no longer matches.
    tampered = replace(_ahrefs_claim(1782543551.0), authority="evil.example")
    status, _ = wba.verify_claim(tampered, key)
    assert status is WbaStatus.FORGED


def _synthetic_signed_claim(
    priv: Ed25519PrivateKey,
    *,
    components: tuple[str, ...] = ("@authority",),
    authority: str | None = "example.com",
    timestamp: float | None = 1500.0,
) -> wba.WbaClaim:
    """A claim whose signature is freshly produced over its own rebuilt base."""
    inner = " ".join(f'"{c}"' for c in components)
    sig_input = f'sig=({inner});created=1000;keyid="k";alg="ed25519";expires=2000;tag="web-bot-auth"'
    params = wba.parse_signature_input(sig_input)["sig"]
    claim = wba.WbaClaim(
        signature_input=sig_input,
        signature="",
        signature_agent='"https://example.com"',
        label="sig",
        params=params,
        agent_url="https://example.com",
        authority=authority,
        method="GET",
        path="/",
        scheme="https",
        timestamp=timestamp,
    )
    base, problem = wba.build_signature_base(claim)
    assert base is not None, problem
    sig_hdr = "sig=:" + base64.b64encode(priv.sign(base.encode("utf-8"))).decode("ascii") + ":"
    return replace(claim, signature=sig_hdr)


def test_synthetic_signature_round_trip() -> None:
    priv = Ed25519PrivateKey.generate()
    claim = _synthetic_signed_claim(priv)
    status, _ = wba.verify_claim(claim, priv.public_key())
    assert status is WbaStatus.VERIFIED


def test_synthetic_signature_wrong_key_is_forged() -> None:
    claim = _synthetic_signed_claim(Ed25519PrivateKey.generate())
    status, _ = wba.verify_claim(claim, Ed25519PrivateKey.generate().public_key())
    assert status is WbaStatus.FORGED


def _unsignable_claim(components: tuple[str, ...]) -> wba.WbaClaim:
    """A claim whose base can't be rebuilt (a covered component we can't supply)."""
    inner = " ".join(f'"{c}"' for c in components)
    sig_input = f'sig=({inner});created=1000;keyid="k";alg="ed25519";tag="web-bot-auth"'
    return wba.WbaClaim(
        signature_input=sig_input,
        signature="sig=:AAAA:",  # never reached: the base check fails first
        signature_agent='"https://example.com"',
        label="sig",
        params=wba.parse_signature_input(sig_input)["sig"],
        agent_url="https://example.com",
        authority="example.com",
        method="GET",
        path="/",
        scheme="https",
        timestamp=1500.0,
    )


def test_signed_body_is_unverifiable_not_forged() -> None:
    # content-digest covered -> the body was signed, which the log can't carry.
    key = Ed25519PrivateKey.generate().public_key()
    status, reason = wba.verify_claim(_unsignable_claim(("@authority", "content-digest")), key)
    assert status is WbaStatus.UNVERIFIABLE
    assert "content-digest" in reason


def test_unlogged_covered_field_is_unverifiable() -> None:
    key = Ed25519PrivateKey.generate().public_key()
    status, reason = wba.verify_claim(_unsignable_claim(("@authority", "x-custom-header")), key)
    assert status is WbaStatus.UNVERIFIABLE
    assert "x-custom-header" in reason


# --- the verifier: key fetch, permanent store, offline behaviour ----------------


def test_verifier_fetches_thumbprint_checks_and_persists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(wba, "remote_enabled", lambda: True)
    fetched: list[str] = []

    def fake_get(url: str) -> str:
        fetched.append(url)
        return AHREFS_DIRECTORY

    monkeypatch.setattr(wba, "_http_get", fake_get)
    verifier = wba.WbaVerifier(allow_fetch=True)
    result = verifier.verify(_ahrefs_claim(1782543551.0))
    assert result.status is WbaStatus.VERIFIED
    assert result.operator == "Ahrefs"
    assert fetched == ["https://ahrefs.com/.well-known/http-message-signatures-directory"]
    verifier.save()

    # The store is permanent: a fresh, offline verifier still verifies from it.
    def boom(url: str) -> str:
        raise AssertionError("must not fetch when the key is already cached")

    monkeypatch.setattr(wba, "_http_get", boom)
    offline = wba.WbaVerifier(allow_fetch=False)
    assert offline.verify(_ahrefs_claim(1782543551.0)).status is WbaStatus.VERIFIED


def test_http_get_refuses_non_http_schemes(monkeypatch: pytest.MonkeyPatch) -> None:
    # A crafted Signature-Agent could name a file:// / ftp:// / etc. URL; the fetch
    # boundary must reject it before urlopen, or it becomes an SSRF/local-read.
    def boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("urlopen must not be called for a non-http(s) scheme")

    monkeypatch.setattr(wba.urllib.request, "urlopen", boom)
    for url in (
        "file:///etc/passwd",
        "ftp://internal/secret",
        "data:text/plain,keys",
        "gopher://169.254.169.254/",
    ):
        assert wba._http_get(url) is None


def test_verifier_offline_without_key_is_unverifiable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    verifier = wba.WbaVerifier(allow_fetch=False)  # empty store, never fetches
    result = verifier.verify(_ahrefs_claim(1782543551.0))
    assert result.status is WbaStatus.UNVERIFIABLE
    assert "could not obtain" in (result.reason or "")


def test_verifier_thumbprint_mismatch_does_not_poison(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A directory serving a different key can't satisfy the requested keyid: keys are
    # stored under their recomputed thumbprint, so the keyid simply isn't found ->
    # unverifiable, never a wrong-key "forged".
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(wba, "remote_enabled", lambda: True)
    wrong = (
        '{"keys":[{"kty":"OKP","crv":"Ed25519",'
        '"x":"v02owuOay4qEWYA4r-BZzdwy7ySHU8o1FESfuY4ICro"}]}'  # Ahrefs's *other* key
    )
    monkeypatch.setattr(wba, "_http_get", lambda url: wrong)
    result = wba.WbaVerifier(allow_fetch=True).verify(_ahrefs_claim(1782543551.0))
    assert result.status is WbaStatus.UNVERIFIABLE


def test_pipeline_verifies_wba_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(wba, "remote_enabled", lambda: True)
    monkeypatch.setattr(wba, "_http_get", lambda url: AHREFS_DIRECTORY)
    fmt = (
        '%h %t "%r" %>s %b "%{User-Agent}i" %{Host}i '
        '"%{Signature-Input}i" "%{Signature}i" "%{Signature-Agent}i"'
    )
    line = " ".join(
        [
            "203.0.113.10",
            "[27/Jun/2026:06:59:10 +0000]",
            '"GET /?uri=x HTTP/2.0"',
            "200",
            "461",
            _log_quote("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
            "redbot.org",
            _log_quote(AHREFS_SIGNATURE_INPUT),
            _log_quote(AHREFS_SIGNATURE),
            _log_quote(AHREFS_SIGNATURE_AGENT),
        ]
    )
    log = tmp_path / "wba.log"
    log.write_text(line + "\n", encoding="utf-8")
    parser = resolve("apache", {"format": fmt})
    result = pipeline.analyze(
        log,
        parser,
        identity.get_strategy("ip_ua"),
        wba_verifier=wba.WbaVerifier(allow_fetch=True),
    )
    signed = [p for p in result.profiles if p.wba is not None]
    assert len(signed) == 1
    profile = signed[0]
    assert profile.wba is not None and profile.wba.status is WbaStatus.VERIFIED
    assert "wba-verified" in profile.classification.tags
    assert profile.classification.primary is not Kind.IMPERSONATOR  # valid sig confirms identity


# --- impersonation precedence (Web Bot Auth outranks the network channel) --------


def _feat(ua: str | None) -> ClientFeatures:
    return ClientFeatures(user_agent=ua)


def test_forged_signature_is_impersonation() -> None:
    forged = WbaResult(WbaStatus.FORGED, evidence=("signature failed",))
    faking, why = impersonation(None, forged, _feat("AhrefsBot"))
    assert faking and why == ("signature failed",)


def test_forged_signature_gets_a_violation_tag() -> None:
    # A forged signature is the impersonator kind, but also gets its own tag --
    # naming *which* channel caught it, since dns/ip/wba can disagree independently.
    from agent_census.classify.tags import derive_tags

    forged = WbaResult(WbaStatus.FORGED, evidence=("signature failed",))
    tags = derive_tags(_feat("AhrefsBot"), None, None, forged)
    assert "wba-violation" in tags


def test_unverifiable_signature_gets_wba_unverified_tag() -> None:
    from agent_census.classify.tags import derive_tags

    unverifiable = WbaResult(WbaStatus.UNVERIFIABLE, reason="key unobtainable")
    tags = derive_tags(_feat("AhrefsBot"), None, None, unverifiable)
    assert "wba-unverified" in tags
    assert "wba-unverifiable" not in tags


def test_valid_signature_clears_a_network_impersonator() -> None:
    # rDNS/range said impersonator, but a valid signature is cryptographic proof.
    net = BotVerification(VerificationStatus.IMPERSONATOR, evidence=("rDNS disagrees",))
    verified = WbaResult(WbaStatus.VERIFIED, operator="Ahrefs")
    faking, _ = impersonation(net, verified, _feat("AhrefsBot"))
    assert not faking


def test_valid_signature_from_wrong_operator_is_impersonation() -> None:
    # UA claims Ahrefs, but the request is validly signed by a different operator.
    verified = WbaResult(WbaStatus.VERIFIED, operator="SomeoneElse")
    faking, why = impersonation(None, verified, _feat("AhrefsBot"))
    assert faking
    assert "Ahrefs" in why[0] and "SomeoneElse" in why[0]


def test_unverifiable_defers_to_network_channel() -> None:
    net = BotVerification(VerificationStatus.IMPERSONATOR, evidence=("rDNS disagrees",))
    unverifiable = WbaResult(WbaStatus.UNVERIFIABLE, reason="no key")
    faking, why = impersonation(net, unverifiable, _feat("AhrefsBot"))
    assert faking and why == ("rDNS disagrees",)


# --- phase 3: domain fallback, mixed identity, nonce replay/reuse ----------------


def test_operator_domain_fallback_for_unregistered_signer() -> None:
    # Same shape of headers, but neither the keyid nor the Signature-Agent is one
    # we have curated -- detect_result is header-parsing only (no crypto), so
    # swapping the keyid string is enough to exercise the "unregistered" path.
    # (Ahrefs's own keyid is curated as of the "ahrefs keyids" data change, so
    # reusing AHREFS_SIGNATURE_INPUT verbatim would resolve via keyid match.)
    unregistered_input = AHREFS_SIGNATURE_INPUT.replace(
        AHREFS_KEYID, "0000000000000000000000000000000000000000x"
    )
    extra = {
        wba.SIGNATURE_INPUT_HEADER: unregistered_input,
        wba.SIGNATURE_HEADER: AHREFS_SIGNATURE,
        wba.SIGNATURE_AGENT_HEADER: '"https://unknown-crawler.example"',
    }
    claim = wba.build_claim(extra, host="redbot.org", method="GET", path="/", timestamp=None)
    assert claim is not None
    result = wba.detect_result(claim)
    assert result.operator is None  # not curated -> no registered identity
    assert result.signer_domain == "unknown-crawler.example"
    assert wba.display_operator(result) == "unknown-crawler.example"


def _seed_key(verifier: wba.WbaVerifier, keyid: str, priv: Ed25519PrivateKey) -> None:
    raw = priv.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    verifier._keys[keyid] = {"kty": "OKP", "crv": "Ed25519", "x": x}  # noqa: SLF001


def test_verify_sample_flags_mixed_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    priv = Ed25519PrivateKey.generate()
    verifier = wba.WbaVerifier(allow_fetch=False)
    _seed_key(verifier, "k", priv)  # the synthetic claims name keyid "k"
    good = _synthetic_signed_claim(priv)
    tampered = replace(good, authority="evil.example")  # base changes -> signature fails
    result = verifier.verify_sample([good, tampered])
    assert result.status is WbaStatus.VERIFIED  # representative drives the headline
    assert result.mixed is True
    # Uniform sample is not flagged mixed.
    assert verifier.verify_sample([good, good]).mixed is False


def _wba_log_line(ip: str) -> str:
    return " ".join(
        [
            ip,
            "[27/Jun/2026:06:59:10 +0000]",
            '"GET / HTTP/2.0"',
            "200",
            "461",
            _log_quote("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
            "redbot.org",
            _log_quote(AHREFS_SIGNATURE_INPUT),
            _log_quote(AHREFS_SIGNATURE),
            _log_quote(AHREFS_SIGNATURE_AGENT),
        ]
    )


_WBA_FMT = (
    '%h %t "%r" %>s %b "%{User-Agent}i" %{Host}i '
    '"%{Signature-Input}i" "%{Signature}i" "%{Signature-Agent}i"'
)


def test_pipeline_flags_cross_origin_replay(tmp_path: Path) -> None:
    # The same signature (same nonce) from two different IPs -> replay, both flagged.
    log = tmp_path / "replay.log"
    log.write_text(_wba_log_line("203.0.113.10") + "\n" + _wba_log_line("198.51.100.10") + "\n")
    parser = resolve("apache", {"format": _WBA_FMT})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))
    wba_profiles = [p for p in result.profiles if p.wba is not None]
    assert len(wba_profiles) == 2
    assert all("wba-replay" in p.classification.tags for p in wba_profiles)


def test_pipeline_flags_same_origin_nonce_reuse(tmp_path: Path) -> None:
    # The same signature twice from one IP -> a signer reusing a nonce, not a replay.
    log = tmp_path / "reuse.log"
    log.write_text(_wba_log_line("203.0.113.10") + "\n" + _wba_log_line("203.0.113.10") + "\n")
    parser = resolve("apache", {"format": _WBA_FMT})
    result = pipeline.analyze(log, parser, identity.get_strategy("ip_ua"))
    wba_profiles = [p for p in result.profiles if p.wba is not None]
    assert len(wba_profiles) == 1
    tags = wba_profiles[0].classification.tags
    assert "wba-nonce-reuse" in tags
    assert "wba-replay" not in tags
