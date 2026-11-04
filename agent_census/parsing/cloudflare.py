"""Parser for Cloudflare Logpush "HTTP requests" logs: newline-delimited JSON.

Each line is one JSON object using Cloudflare's field names (``ClientIP``,
``ClientRequestMethod``, ``EdgeResponseStatus`` ...). We map the fields we use
onto :class:`~agent_census.model.LogEntry`. ``ClientASN`` is carried through in
``extra`` so ASN-based detection works straight from the log -- no MaxMind, no
range fetch. ``EdgeStartTimestamp`` is accepted as RFC3339 or a unix integer
(seconds / millis / micros / nanos), since Logpush can emit either. The Web Bot
Auth headers (``Signature-Input``, ``Signature``, ``Signature-Agent``) are read from
the ``RequestHeaders`` custom field when the job logs them.

Unlike Apache, the schema is fixed, so this parser takes no options.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone

from ..model import LogEntry
from ..wba import SIGNATURE_AGENT_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER
from .base import LogParser, ParseOutcome
from .registry import register

_SUBMICRO = re.compile(r"(\.\d{6})\d+")  # fromisoformat rejects >6 fractional digits
_SURROGATES = re.compile("[\ud800-\udfff]")


def _clean(text: str) -> str:
    """Replace lone surrogates (JSON ``\\ud800`` escapes decode to them).

    They're valid ``str`` but can't be UTF-8 encoded, so left in they abort the run
    in whatever later hashes or encodes the value.
    """
    return _SURROGATES.sub("�", text)


def _str(value: object) -> str | None:
    return _clean(value) if isinstance(value, str) else None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_timestamp(value: object) -> datetime | None:
    """RFC3339 string or unix integer (seconds .. nanoseconds) -> aware datetime."""
    if isinstance(value, str) and value:
        text = _SUBMICRO.sub(r"\1", value.strip().replace("Z", "+00:00"))
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    seconds = _int(value)
    if seconds is None or seconds <= 0:
        return None
    if seconds > 1e17:  # nanoseconds
        seconds = int(seconds / 1e9)
    elif seconds > 1e14:  # microseconds
        seconds = int(seconds / 1e6)
    elif seconds > 1e11:  # milliseconds
        seconds = int(seconds / 1e3)
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _scheme(value: object) -> str | None:
    """``http`` or ``https`` (case-insensitive); anything else is treated as unlogged."""
    scheme = value.lower() if isinstance(value, str) else None
    return scheme if scheme in ("http", "https") else None


def _header_value(value: object) -> str | None:
    """A logged header value: a string, or a list of field lines joined per RFC 9110."""
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        value = ", ".join(value)
    return _clean(value) or None if isinstance(value, str) else None


def _web_bot_auth_headers(record: Mapping[str, object]) -> dict[str, str]:
    """The Web Bot Auth request headers from the ``RequestHeaders`` custom field.

    Logpush emits the request headers a job is configured to log as an object keyed
    by header name; names are matched case-insensitively and stored under the
    canonical names ``wba`` reads from ``LogEntry.extra``.
    """
    headers = record.get("RequestHeaders")
    if not isinstance(headers, dict):
        return {}
    wanted = {
        name.lower(): name
        for name in (SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER, SIGNATURE_AGENT_HEADER)
    }
    found: dict[str, str] = {}
    for key, raw in headers.items():
        canonical = wanted.get(key.lower()) if isinstance(key, str) else None
        value = _header_value(raw)
        if canonical is not None and value is not None:
            found[canonical] = value
    return found


def _to_entry(record: Mapping[str, object], line_no: int) -> LogEntry:
    uri = _str(record.get("ClientRequestURI"))
    if uri is not None:
        path, sep, query = uri.partition("?")
    else:
        path, sep, query = _str(record.get("ClientRequestPath")) or "", "", ""
    extra: dict[str, str] = {}
    asn = _int(record.get("ClientASN"))
    if asn:  # the key contains "asn", so features read it as the AS number
        extra["ClientASN"] = str(asn)
    extra.update(_web_bot_auth_headers(record))
    return LogEntry(
        line_no=line_no,
        remote_host=_str(record.get("ClientIP")) or "-",
        timestamp=_parse_timestamp(record.get("EdgeStartTimestamp")),
        method=_str(record.get("ClientRequestMethod")),
        path=path,
        query=query if sep else None,
        protocol=_str(record.get("ClientRequestProtocol")),
        status=_int(record.get("EdgeResponseStatus")),
        bytes_sent=_int(record.get("EdgeResponseBytes")),
        referer=_str(record.get("ClientRequestReferer")),
        user_agent=_str(record.get("ClientRequestUserAgent")),
        host_header=_str(record.get("ClientRequestHost")),
        scheme=_scheme(record.get("ClientRequestScheme")),
        extra=extra,
    )


class CloudflareParser(LogParser):
    """Cloudflare Logpush HTTP-requests logs: one JSON object per line."""

    name = "cloudflare"

    def parse_lines(self, lines: Iterator[str]) -> Iterator[ParseOutcome]:
        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except ValueError:
                yield ParseOutcome(
                    skip_reason="line is not valid JSON", line_no=line_no, raw_line=stripped
                )
                continue
            except RecursionError:
                # Deeply nested JSON exceeds the interpreter's recursion limit.
                # RecursionError is a RuntimeError, not a ValueError, so it would
                # otherwise escape and abort the whole run on one hostile line.
                yield ParseOutcome(
                    skip_reason="JSON line is nested too deeply",
                    line_no=line_no,
                    raw_line=stripped,
                )
                continue
            if not isinstance(record, dict):
                yield ParseOutcome(
                    skip_reason="JSON line is not an object", line_no=line_no, raw_line=stripped
                )
                continue
            yield ParseOutcome(entry=_to_entry(record, line_no), line_no=line_no)


def _factory(_opts: Mapping[str, str]) -> CloudflareParser:
    return CloudflareParser()


register("cloudflare", _factory)
