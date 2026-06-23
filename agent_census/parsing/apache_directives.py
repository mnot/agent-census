"""Apache ``LogFormat`` directive table and the per-line value builder.

Each supported ``%``-directive maps to a regex fragment (what Apache writes for
it) and a setter that stores the captured value on a mutable ``_Builder``. The
compiler in :mod:`agent_census.parsing.apache` stitches these fragments into one
regex and replays the setters after a match. Quoting in the format is handled by
the compiler treating the literal ``"`` as literals; quoted directives use a
fragment that tolerates Apache's ``\\"`` escaping.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..errors import FormatSpecError
from ..model import LogEntry

# Regex fragments. Fields are space-delimited in the format, so ``\S+`` stops at
# the next literal. Quoted values may contain Apache's ``\"`` / ``\\`` escapes.
_UNQUOTED = r"\S+"
_QUOTED = r'(?:[^"\\]|\\.)*'
_BRACKET = r"\[[^\]]*\]"
_URLPATH = r"[^?\s]*"
_QUERY = r"(?:\?\S*)?"

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip

_UNESCAPE = re.compile(r"\\(.)")
_UNESCAPE_MAP = {'"': '"', "\\": "\\", "t": "\t", "n": "\n", "r": "\r"}


@dataclass(slots=True)
class _Builder:
    """Mutable accumulator filled by directive setters, then frozen into an entry.

    The field list deliberately mirrors :class:`~agent_census.model.LogEntry`;
    that overlap is the point, so the similarity check is silenced here.
    """

    # pylint: disable=duplicate-code
    remote_host: str | None = None
    remote_logname: str | None = None
    remote_user: str | None = None
    forwarded_for: tuple[str, ...] = ()
    timestamp: datetime | None = None
    response_usec: int | None = None
    method: str | None = None
    path: str = ""
    query: str | None = None
    protocol: str | None = None
    raw_request: str = ""
    status: int | None = None
    bytes_sent: int | None = None
    referer: str | None = None
    user_agent: str | None = None
    host_header: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def build(self, raw_line: str, line_no: int) -> LogEntry:
        return LogEntry(
            raw_line=raw_line,
            line_no=line_no,
            remote_host=self.remote_host if self.remote_host is not None else "-",
            remote_logname=self.remote_logname,
            remote_user=self.remote_user,
            forwarded_for=self.forwarded_for,
            timestamp=self.timestamp,
            response_usec=self.response_usec,
            method=self.method,
            path=self.path,
            query=self.query,
            protocol=self.protocol,
            raw_request=self.raw_request,
            status=self.status,
            bytes_sent=self.bytes_sent,
            referer=self.referer,
            user_agent=self.user_agent,
            host_header=self.host_header,
            extra=self.extra,
        )


Setter = Callable[[_Builder, str], None]


@dataclass(frozen=True, slots=True)
class Directive:
    """A regex fragment plus the setter that records its captured value."""

    pattern: str
    setter: Setter


def _unescape(value: str) -> str:
    return _UNESCAPE.sub(lambda m: _UNESCAPE_MAP.get(m.group(1), m.group(0)), value)


def parse_clf_time(value: str) -> datetime | None:
    """Parse Apache's CLF timestamp ``[10/Oct/2000:13:55:36 -0700]``.

    Uses a fixed month map rather than ``strptime`` so it is locale-immune and
    fast in the hot loop. Returns ``None`` for an unrecognized shape (the caller
    leaves the timestamp unset rather than failing the whole line).
    """
    inner = value.strip("[]")
    try:
        date_part, _, zone = inner.partition(" ")
        day, mon, rest = date_part.split("/", 2)
        year, hour, minute, second = rest.split(":")
        month = _MONTHS[mon]
        stamp = datetime(int(year), month, int(day), int(hour), int(minute), int(second))
    except (ValueError, KeyError):
        return None
    if zone and len(zone) == 5 and zone[0] in "+-":
        offset_min = int(zone[1:3]) * 60 + int(zone[3:5])
        if zone[0] == "-":
            offset_min = -offset_min
        return stamp.replace(tzinfo=timezone(timedelta(minutes=offset_min)))
    return stamp


# --- setter factories for the common shapes -------------------------------


def _str_setter(attr: str) -> Setter:
    def setter(builder: _Builder, value: str) -> None:
        setattr(builder, attr, None if value == "-" else value)

    return setter


def _int_setter(attr: str) -> Setter:
    def setter(builder: _Builder, value: str) -> None:
        setattr(builder, attr, None if value == "-" else int(value))

    return setter


def _extra_setter(key: str) -> Setter:
    def setter(builder: _Builder, value: str) -> None:
        if value != "-":
            builder.extra[key] = value

    return setter


# --- dedicated setters for multi-field / special directives ----------------


def _set_time(builder: _Builder, value: str) -> None:
    builder.timestamp = parse_clf_time(value)


def _set_bytes_clf(builder: _Builder, value: str) -> None:
    builder.bytes_sent = 0 if value == "-" else int(value)


def _set_secs(builder: _Builder, value: str) -> None:
    builder.response_usec = None if value == "-" else int(round(float(value) * 1_000_000))


def _set_request(builder: _Builder, value: str) -> None:
    value = _unescape(value)
    if value == "-":
        builder.raw_request = ""
        return
    builder.raw_request = value
    parts = value.split(" ")
    if len(parts) == 3:
        builder.method, target, builder.protocol = parts
        path, sep, query = target.partition("?")
        builder.path = path
        builder.query = query if sep else None


def _set_path(builder: _Builder, value: str) -> None:
    builder.path = value


def _set_query(builder: _Builder, value: str) -> None:
    builder.query = value[1:] if value.startswith("?") else (value or None)


def _route_request_header(name: str) -> Setter:
    lname = name.lower()

    def setter(builder: _Builder, value: str) -> None:
        decoded = _unescape(value)
        clean = None if decoded == "-" else decoded
        if lname == "referer":
            builder.referer = clean
        elif lname == "user-agent":
            builder.user_agent = clean
        elif lname == "host":
            builder.host_header = clean
        elif lname == "x-forwarded-for":
            if clean:
                builder.forwarded_for = tuple(p.strip() for p in clean.split(",") if p.strip())
        elif clean is not None:
            builder.extra[name] = clean

    return setter


# --- the table -------------------------------------------------------------

# Non-parameterized directives. ``%a`` (peer IP) shares a home with ``%h``.
_SIMPLE: dict[str, Directive] = {
    "h": Directive(_UNQUOTED, _str_setter("remote_host")),
    "a": Directive(_UNQUOTED, _str_setter("remote_host")),
    "l": Directive(_UNQUOTED, _str_setter("remote_logname")),
    "u": Directive(_UNQUOTED, _str_setter("remote_user")),
    "t": Directive(_BRACKET, _set_time),
    "r": Directive(_QUOTED, _set_request),
    "m": Directive(_UNQUOTED, _str_setter("method")),
    "U": Directive(_URLPATH, _set_path),
    "q": Directive(_QUERY, _set_query),
    "H": Directive(_UNQUOTED, _str_setter("protocol")),
    "s": Directive(_UNQUOTED, _int_setter("status")),
    "b": Directive(_UNQUOTED, _set_bytes_clf),
    "B": Directive(_UNQUOTED, _int_setter("bytes_sent")),
    "D": Directive(_UNQUOTED, _int_setter("response_usec")),
    "T": Directive(_UNQUOTED, _set_secs),
    "I": Directive(_UNQUOTED, _extra_setter("bytes_in")),
    "O": Directive(_UNQUOTED, _extra_setter("bytes_out")),
    "S": Directive(_UNQUOTED, _extra_setter("bytes_total")),
    "v": Directive(_UNQUOTED, _extra_setter("server_name")),
    "V": Directive(_UNQUOTED, _extra_setter("server_name")),
    "p": Directive(_UNQUOTED, _extra_setter("port")),
    "P": Directive(_UNQUOTED, _extra_setter("pid")),
    "k": Directive(_UNQUOTED, _extra_setter("keepalive")),
    "X": Directive(_UNQUOTED, _extra_setter("conn_status")),
    "R": Directive(_UNQUOTED, _extra_setter("handler")),
    "f": Directive(_UNQUOTED, _extra_setter("filename")),
}


def simple_directive(letter: str) -> Directive:
    """Return the spec for a non-parameterized directive, or raise."""
    try:
        return _SIMPLE[letter]
    except KeyError:
        raise FormatSpecError(f"unsupported Apache log directive '%{letter}'") from None


# Parameterized ``%{name}X`` directives that we keep in the ``extra`` bag,
# mapping the trailing letter to (regex fragment, extra-key prefix).
#   o response header   C cookie   n note   e env var   t custom time
#   x mod_ssl/log var (SSL_PROTOCOL, SSL_CIPHER, ...)   p port   P pid/tid
_PARAM_EXTRA: dict[str, tuple[str, str]] = {
    "o": (_QUOTED, "out:"),
    "C": (_QUOTED, "cookie:"),
    "n": (_UNQUOTED, "note:"),
    "e": (_UNQUOTED, "env:"),
    "t": (_UNQUOTED, "time:"),
    "x": (_UNQUOTED, "ssl:"),
    "p": (_UNQUOTED, "port:"),
    "P": (_UNQUOTED, "pid:"),
}


def param_directive(name: str, letter: str) -> Directive:
    """Return the spec for a ``%{name}letter`` directive, or raise."""
    if letter == "i":
        return Directive(_QUOTED, _route_request_header(name))
    spec = _PARAM_EXTRA.get(letter)
    if spec is None:
        raise FormatSpecError(f"unsupported parameterized directive '%{{{name}}}{letter}'")
    pattern, prefix = spec
    return Directive(pattern, _extra_setter(f"{prefix}{name}"))
