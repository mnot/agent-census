"""Tests for Web Bot Auth header parsing (phase 1: parse + attribute, no crypto)."""

from __future__ import annotations

from pathlib import Path

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
