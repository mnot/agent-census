"""Tests for the Cloudflare Logpush (NDJSON) parser."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_census import wba
from agent_census.features import FeatureAccumulator, extract_features
from agent_census.parsing import resolve
from agent_census.model import WbaStatus
from agent_census.parsing.base import ParseOutcome


def _parse(record: dict[str, Any] | str) -> ParseOutcome:
    line = record if isinstance(record, str) else json.dumps(record)
    return list(resolve("cloudflare", {}).parse_lines([line]))[0]


def test_maps_the_core_fields() -> None:
    out = _parse(
        {
            "ClientIP": "203.0.113.5",
            "ClientRequestMethod": "GET",
            "ClientRequestURI": "/blog/post?x=1",
            "ClientRequestHost": "mnot.net",
            "EdgeResponseStatus": 200,
            "ClientRequestUserAgent": "Googlebot",
            "ClientRequestReferer": "https://mnot.net/",
            "EdgeResponseBytes": 4521,
            "ClientRequestProtocol": "HTTP/2",
            "EdgeStartTimestamp": "2026-06-21T01:50:50Z",
            "ClientASN": 15169,
        }
    )
    entry = out.entry
    assert entry is not None
    assert entry.remote_host == "203.0.113.5"
    assert entry.method == "GET" and entry.path == "/blog/post" and entry.query == "x=1"
    assert entry.status == 200 and entry.bytes_sent == 4521
    assert entry.user_agent == "Googlebot" and entry.referer == "https://mnot.net/"
    assert entry.host_header == "mnot.net" and entry.protocol == "HTTP/2"
    assert entry.timestamp is not None and entry.timestamp.year == 2026
    assert entry.extra.get("ClientASN") == "15169"


def test_client_asn_feeds_as_number() -> None:
    out = _parse({"ClientIP": "5.188.0.9", "ClientRequestURI": "/", "ClientASN": 35237})
    feats = extract_features([out.entry])  # type: ignore[list-item]
    assert feats.as_number == "35237"


def test_unix_nanosecond_timestamp() -> None:
    out = _parse({"ClientIP": "1.2.3.4", "ClientRequestURI": "/", "EdgeStartTimestamp": 1718935850000000000})
    assert out.entry is not None and out.entry.timestamp is not None
    assert out.entry.timestamp.year == 2024


def test_path_without_uri_field() -> None:
    out = _parse({"ClientIP": "1.2.3.4", "ClientRequestPath": "/only/path"})
    assert out.entry is not None and out.entry.path == "/only/path" and out.entry.query is None


def test_bad_json_is_skipped_not_raised() -> None:
    out = list(resolve("cloudflare", {}).parse_lines(["not json {"]))[0]
    assert out.entry is None and out.skip_reason and "JSON" in out.skip_reason


def test_non_object_json_is_skipped() -> None:
    out = list(resolve("cloudflare", {}).parse_lines(["[1, 2, 3]"]))[0]
    assert out.entry is None and out.skip_reason and "object" in out.skip_reason


def test_deeply_nested_json_is_skipped_not_raised() -> None:
    # A hostile line of deeply nested JSON raises RecursionError (a RuntimeError,
    # not a ValueError) from json.loads; it must be skipped, not abort the run.
    depth = 200_000
    line = "[" * depth + "]" * depth
    out = list(resolve("cloudflare", {}).parse_lines([line]))[0]
    assert out.entry is None and out.skip_reason and "deeply" in out.skip_reason


def test_missing_fields_default_safely() -> None:
    out = _parse({"EdgeStartTimestamp": "2026-06-21T01:50:50Z"})  # no IP, no request
    entry = out.entry
    assert entry is not None
    assert entry.remote_host == "-" and entry.method is None and entry.path == ""


_SIG_INPUT = 'sig=("@authority" "signature-agent");created=1782543550;keyid="k";tag="web-bot-auth"'
_SIG = "sig=:aGVsbG8=:"
_SIG_AGENT = '"https://ahrefs.com"'


def test_request_headers_feed_web_bot_auth() -> None:
    out = _parse(
        {
            "ClientIP": "203.0.113.5",
            "ClientRequestMethod": "GET",
            "ClientRequestURI": "/",
            "ClientRequestHost": "redbot.org",
            "EdgeStartTimestamp": "2026-06-27T07:19:10Z",
            # Logpush lower-cases names; matching must not depend on it.
            "RequestHeaders": {
                "signature-input": _SIG_INPUT,
                "Signature": _SIG,
                "SIGNATURE-AGENT": _SIG_AGENT,
                "accept": "*/*",
            },
        }
    )
    entry = out.entry
    assert entry is not None
    assert entry.extra[wba.SIGNATURE_INPUT_HEADER] == _SIG_INPUT
    assert entry.extra[wba.SIGNATURE_HEADER] == _SIG
    assert entry.extra[wba.SIGNATURE_AGENT_HEADER] == _SIG_AGENT
    assert "accept" not in entry.extra  # only the headers wba reads are kept
    claim = wba.build_claim(
        entry.extra,
        host=entry.host_header,
        method=entry.method,
        path=entry.path,
        timestamp=None,
    )
    assert claim is not None
    assert claim.agent_url == "https://ahrefs.com" and claim.authority == "redbot.org"


def test_request_header_field_lines_are_joined() -> None:
    out = _parse(
        {"ClientIP": "1.2.3.4", "RequestHeaders": {"signature-input": ["a=1", "b=2"]}}
    )
    assert out.entry is not None
    assert out.entry.extra[wba.SIGNATURE_INPUT_HEADER] == "a=1, b=2"


def test_missing_or_malformed_request_headers_add_nothing() -> None:
    for headers in (None, "x", [], {"signature": 5}, {"signature": ""}, {"accept": "*/*"}):
        record: dict[str, Any] = {"ClientIP": "1.2.3.4", "ClientASN": 15169}
        if headers is not None:
            record["RequestHeaders"] = headers
        out = _parse(record)
        assert out.entry is not None and out.entry.extra == {"ClientASN": "15169"}


def test_lone_surrogates_are_replaced_not_left_to_crash_later() -> None:
    # JSON "\ud800" decodes to a lone surrogate, which can't be UTF-8 encoded.
    out = _parse(
        '{"ClientIP": "1.2.3.4", "ClientRequestURI": "/a\\ud800?q=\\udfff",'
        ' "ClientRequestUserAgent": "bot\\ud800",'
        ' "RequestHeaders": {"signature-input": "x\\ud800", "signature-agent": ["a\\udc00"]}}'
    )
    entry = out.entry
    assert entry is not None
    texts = [entry.path, entry.query, entry.user_agent, *entry.extra.values()]
    for text in texts:
        assert isinstance(text, str)
        text.encode("utf-8")  # must not raise
    assert entry.path == "/a�" and entry.user_agent == "bot�"


def test_empty_header_values_are_dropped_alike() -> None:
    for value in ("", [""], []):
        out = _parse({"ClientIP": "1.2.3.4", "RequestHeaders": {"signature-input": value}})
        assert out.entry is not None and wba.SIGNATURE_INPUT_HEADER not in out.entry.extra


def test_scheme_is_read_and_validated() -> None:
    for raw, expected in (("http", "http"), ("HTTPS", "https"), ("ws", None), (5, None)):
        out = _parse({"ClientIP": "1.2.3.4", "ClientRequestScheme": raw})
        assert out.entry is not None and out.entry.scheme == expected
    assert _parse({"ClientIP": "1.2.3.4"}).entry.scheme is None  # type: ignore[union-attr]


def _signed_record(
    priv: Ed25519PrivateKey, *, scheme: str | None, host: str = "Example.COM:8443"
) -> dict[str, Any]:
    """A Cloudflare record whose signature covers @authority, @path and @scheme."""
    sig_input = (
        'sig=("@authority" "@path" "@scheme");created=1000;keyid="k";alg="ed25519";'
        'expires=2000;tag="web-bot-auth"'
    )
    record: dict[str, Any] = {
        "ClientIP": "203.0.113.5",
        "ClientRequestMethod": "GET",
        "ClientRequestURI": "/a%20b?x=1",
        "ClientRequestHost": host,
        "EdgeStartTimestamp": 1500,
        "RequestHeaders": {"signature-input": sig_input, "signature": "sig=:AA==:"},
    }
    if scheme is not None:
        record["ClientRequestScheme"] = scheme
    claim = _claim_from(record)
    base, problem = wba.build_signature_base(claim)
    assert base is not None, problem
    signature = base64.b64encode(priv.sign(base.encode("utf-8"))).decode("ascii")
    record["RequestHeaders"]["signature"] = f"sig=:{signature}:"
    return record


def _claim_from(record: dict[str, Any]) -> wba.WbaClaim:
    entry = _parse(record).entry
    assert entry is not None and entry.timestamp is not None
    acc = FeatureAccumulator()
    acc.add(entry)
    assert acc.wba_claims, "no claim built from the record"
    return acc.wba_claims[0]


def test_signed_cloudflare_record_verifies_through_features() -> None:
    priv = Ed25519PrivateKey.generate()
    # Plain-HTTP request, signed over @scheme; host carries a port and upper case.
    claim = _claim_from(_signed_record(priv, scheme="http"))
    assert claim.scheme == "http" and claim.authority == "example.com:8443"
    status, _ = wba.verify_claim(claim, priv.public_key())
    assert status is WbaStatus.VERIFIED


def test_unlogged_scheme_assumes_https() -> None:
    priv = Ed25519PrivateKey.generate()
    claim = _claim_from(_signed_record(priv, scheme="https"))
    status, _ = wba.verify_claim(claim, priv.public_key())
    assert status is WbaStatus.VERIFIED
    # Same signed bytes with the scheme dropped from the log still read as https.
    record = _signed_record(priv, scheme="https")
    del record["ClientRequestScheme"]
    assert _claim_from(record).scheme == "https"
