"""Tests for Web Bot Auth: header parsing/attribution and signature verification."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_census import identity, pipeline, wba
from agent_census.model import WbaStatus
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
