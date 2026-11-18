"""Parser for Cloudflare Logpush "HTTP requests" logs: newline-delimited JSON.

Each line is one JSON object using Cloudflare's field names (``ClientIP``,
``ClientRequestMethod``, ``EdgeResponseStatus`` ...). We map the fields we use
onto :class:`~agent_census.model.LogEntry`. ``ClientASN`` is carried through in
``extra`` so ASN-based detection works straight from the log -- no MaxMind, no
range fetch. ``EdgeStartTimestamp`` is accepted as RFC3339 or a unix integer
(seconds / millis / micros / nanos), since Logpush can emit either.

Unlike Apache, the schema is fixed, so this parser takes no options.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone

from ..model import LogEntry
from .base import LogParser, ParseOutcome
from .registry import register

_SUBMICRO = re.compile(r"(\.\d{6})\d+")  # fromisoformat rejects >6 fractional digits


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


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


def _to_entry(record: Mapping[str, object], line_no: int) -> LogEntry:
    uri = record.get("ClientRequestURI")
    if isinstance(uri, str):
        path, sep, query = uri.partition("?")
    else:
        path, sep, query = _str(record.get("ClientRequestPath")) or "", "", ""
    extra: dict[str, str] = {}
    asn = _int(record.get("ClientASN"))
    if asn:  # the key contains "asn", so features read it as the AS number
        extra["ClientASN"] = str(asn)
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
