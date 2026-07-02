"""Tests for the Cloudflare Logpush (NDJSON) parser."""

from __future__ import annotations

import json
from typing import Any

from agent_census.features import extract_features
from agent_census.parsing import resolve
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
