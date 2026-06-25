"""Tests for the Apache log-format parser — the project's correctness foundation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_census.errors import FormatSpecError
from agent_census.parsing.apache import PRESETS, ApacheParser


def _one(fmt: str, line: str):
    outcomes = list(ApacheParser(fmt).parse_lines(iter([line])))
    assert len(outcomes) == 1
    return outcomes[0]


def test_combined_format_full_line() -> None:
    line = (
        '192.0.2.10 - alice [10/Oct/2000:13:55:36 -0700] '
        '"GET /index.html?q=1 HTTP/1.1" 200 2326 '
        '"http://example.com/" "Mozilla/5.0 (X11) Firefox/120.0"'
    )
    outcome = _one(PRESETS["combined"], line)
    entry = outcome.entry
    assert entry is not None
    assert entry.remote_host == "192.0.2.10"
    assert entry.remote_logname is None
    assert entry.remote_user == "alice"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.query == "q=1"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.bytes_sent == 2326
    assert entry.referer == "http://example.com/"
    assert entry.user_agent == "Mozilla/5.0 (X11) Firefox/120.0"


def test_timestamp_parsed_with_offset() -> None:
    entry = _one(PRESETS["combined"], _combined("[10/Oct/2000:13:55:36 -0700]")).entry
    assert entry is not None
    expected = datetime(2000, 10, 10, 13, 55, 36, tzinfo=timezone(timedelta(hours=-7)))
    assert entry.timestamp == expected


def test_dash_fields_become_none() -> None:
    line = '203.0.113.5 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 - "-" "-"'
    entry = _one(PRESETS["combined"], line).entry
    assert entry is not None
    assert entry.remote_user is None
    assert entry.referer is None
    assert entry.user_agent is None
    # %b of "-" means no body -> 0, not None
    assert entry.bytes_sent == 0


def test_user_agent_with_embedded_quotes_and_spaces() -> None:
    ua = 'Mozilla/5.0 (compatible; \\"Weird\\"/1.0; +http://x)'
    line = f'198.51.100.7 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 12 "-" "{ua}"'
    entry = _one(PRESETS["combined"], line).entry
    assert entry is not None
    assert entry.user_agent == 'Mozilla/5.0 (compatible; "Weird"/1.0; +http://x)'


def test_bytes_capital_b_and_duration_microseconds() -> None:
    fmt = '%h %t "%r" %>s %B %D'
    line = '10.0.0.1 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 4096 1500'
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.bytes_sent == 4096
    assert entry.response_usec == 1500


def test_duration_seconds_directive_normalized() -> None:
    fmt = '%h %t "%r" %>s %b %T'
    line = '10.0.0.1 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 10 2'
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.response_usec == 2_000_000


def test_request_line_without_query() -> None:
    entry = _one(PRESETS["common"], _common('"GET /about HTTP/1.0"')).entry
    assert entry is not None
    assert entry.path == "/about"
    assert entry.query is None


def test_malformed_request_line_kept_not_skipped() -> None:
    # A binary/garbage request target should NOT drop the line — it is scanner evidence.
    line = '45.9.0.1 - - [10/Oct/2000:13:55:36 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'
    outcome = _one(PRESETS["combined"], line)
    assert outcome.entry is not None
    assert outcome.entry.method is None
    assert outcome.entry.status == 400
    assert outcome.entry.raw_request != ""


def test_line_not_matching_format_is_skipped() -> None:
    outcome = _one(PRESETS["combined"], "this is not a log line at all")
    assert outcome.entry is None
    assert outcome.skip_reason is not None
    assert outcome.line_no == 1


def test_x_forwarded_for_chain_parsed() -> None:
    fmt = '%h %t "%r" %>s %b "%{X-Forwarded-For}i"'
    line = '10.0.0.1 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "203.0.113.1, 70.41.3.18"'
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.forwarded_for == ("203.0.113.1", "70.41.3.18")


def test_separate_method_path_query_directives() -> None:
    fmt = "%h %t %m %U%q %H %>s %b"
    line = "10.0.0.1 [10/Oct/2000:13:55:36 +0000] GET /search?x=1&y=2 HTTP/1.1 200 5"
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.method == "GET"
    assert entry.path == "/search"
    assert entry.query == "x=1&y=2"
    assert entry.protocol == "HTTP/1.1"


def test_ssl_variable_directive() -> None:
    fmt = '%h %t "%r" %>s %b "%{SSL_PROTOCOL}x" "%{SSL_CIPHER}x"'
    line = (
        '10.0.0.1 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 1 '
        '"TLSv1.3" "TLS_AES_256_GCM_SHA384"'
    )
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.extra["ssl:SSL_PROTOCOL"] == "TLSv1.3"
    assert entry.extra["ssl:SSL_CIPHER"] == "TLS_AES_256_GCM_SHA384"


def test_env_directive_captures_as_org_with_spaces() -> None:
    # MaxMind AS org via %{MM_ASORG}e; quoted so the comma/space org is whole.
    fmt = '%h %t "%r" %>s %b "%{MM_ASORG}e" "%{MM_ASN}e"'
    line = (
        '10.0.0.1 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 1 '
        '"Amazon.com, Inc." "16509"'
    )
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.extra["env:MM_ASORG"] == "Amazon.com, Inc."
    assert entry.extra["env:MM_ASN"] == "16509"


def test_port_and_pid_directives() -> None:
    fmt = "%h %t %{canonical}p %{pid}P %>s"
    line = "10.0.0.1 [10/Oct/2000:13:55:36 +0000] 443 1234 200"
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.extra["port:canonical"] == "443"
    assert entry.extra["pid:pid"] == "1234"


def test_custom_time_with_space_does_not_skip_line() -> None:
    # A custom strftime time containing a space (%{%Y-%m-%d %H:%M:%S}t) must still
    # match: a blanket \S+ stops at the space and would skip every line.
    fmt = '%h "%{%Y-%m-%d %H:%M:%S}t" "%r" %>s'
    line = '10.0.0.1 "2023-10-10 12:00:00" "GET / HTTP/1.1" 200'
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.extra["time:%Y-%m-%d %H:%M:%S"] == "2023-10-10 12:00:00"


def test_custom_time_with_space_unquoted_matches() -> None:
    fmt = "%h %{%Y-%m-%d %H:%M:%S}t %>s"
    line = "10.0.0.1 2023-10-10 12:00:00 200"
    entry = _one(fmt, line).entry
    assert entry is not None
    assert entry.extra["time:%Y-%m-%d %H:%M:%S"] == "2023-10-10 12:00:00"


def test_unsupported_directive_fails_loudly() -> None:
    with pytest.raises(FormatSpecError):
        ApacheParser("%h %z")


def test_dangling_percent_fails() -> None:
    with pytest.raises(FormatSpecError):
        ApacheParser("%h %")


def test_blank_lines_are_ignored() -> None:
    outcomes = list(ApacheParser(PRESETS["common"]).parse_lines(iter(["", "   \n"])))
    assert outcomes == []


def _combined(time_field: str) -> str:
    return (
        f'192.0.2.10 - - {time_field} "GET / HTTP/1.1" 200 1 "-" "-"'
    )


def _common(request_field: str) -> str:
    return f'192.0.2.10 - - [10/Oct/2000:13:55:36 +0000] {request_field} 200 1'


def test_trailing_fields_are_optional() -> None:
    # A field appended to the format may be absent on older lines: the line still
    # parses and the missing field is just left unset.
    fmt = PRESETS["combined"] + ' "%{Content-Type}o"'
    base = (
        '192.0.2.10 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 10 '
        '"-" "curl/8"'
    )
    without = _one(fmt, base)
    assert without.entry is not None
    assert without.entry.status == 200 and without.entry.user_agent == "curl/8"
    assert "out:Content-Type" not in without.entry.extra  # absent, not errored

    with_ct = _one(fmt, base + ' "text/html"')
    assert with_ct.entry is not None
    assert with_ct.entry.extra.get("out:Content-Type") == "text/html"


def test_two_trailing_fields_can_be_absent() -> None:
    fmt = PRESETS["combined"] + ' "%{Content-Type}o" "%{X-Cache}o"'
    base = (
        '192.0.2.10 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 10 '
        '"-" "curl/8"'
    )
    assert _one(fmt, base).entry is not None  # both trailing fields omitted
    assert _one(fmt, base + ' "text/html"').entry is not None  # one omitted


def test_missing_middle_field_still_skips() -> None:
    # Only the *tail* is forgiving: a line missing an interior field (here %b, the
    # byte count) doesn't line up and is skipped, not silently mis-parsed.
    line = '192.0.2.10 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 "-" "curl/8"'
    assert _one(PRESETS["combined"], line).entry is None
