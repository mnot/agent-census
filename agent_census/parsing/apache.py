"""Apache access-log parser.

Compiles a verbatim ``LogFormat``/``CustomLog`` directive string into a single
named-group regex once, then applies it per line. This captures Apache's format
grammar declaratively and runs the match in C. Per-line failures become skips,
never exceptions.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping

from ..errors import ConfigError, FormatSpecError
from .apache_directives import Directive, Setter, _Builder, param_directive, simple_directive
from .base import LogParser, ParseOutcome
from .registry import register

# Common named formats, so callers need not type the CLF every time.
PRESETS: dict[str, str] = {
    "common": '%h %l %u %t "%r" %>s %b',
    "combined": '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"',
    "vhost_combined": ('%v:%p %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'),
}

_MODIFIER_CHARS = set("!<>0123456789,")

# Quote-safe fragment for any directive wrapped in "..." in the format, so a
# logged value containing spaces (a request line, a UA, an AS-org name) is
# captured whole rather than truncated at the first space.
_QUOTED_FRAGMENT = r'(?:[^"\\]|\\.)*'

# Backslash escapes Apache honours in a LogFormat literal: ``\t`` -> tab, etc.
# Apache writes the control character to the log, so the parser must match it.
_LIT_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "\\": "\\", '"': '"'}


def _unescape_literal(text: str) -> str:
    """Apply LogFormat backslash escapes to a literal run of the format string."""
    return re.sub(r"\\(.)", lambda m: _LIT_ESCAPES.get(m.group(1), m.group(1)), text)


def _tokenize(fmt: str) -> list[Directive | str]:
    """Split a format string into literal text and directive specs, in order.

    Literals are unescaped (``\\t`` becomes a tab) so they match what Apache
    actually writes, and a directive wrapped in ``"`` gets the quote-safe
    fragment regardless of its type.
    """
    tokens: list[Directive | str] = []
    literal: list[str] = []
    i = 0
    length = len(fmt)

    def flush() -> str:
        text = _unescape_literal("".join(literal))
        if text:
            tokens.append(text)
        literal.clear()
        return text

    while i < length:
        char = fmt[i]
        if char != "%":
            literal.append(char)
            i += 1
            continue
        i += 1
        if i >= length:
            raise FormatSpecError("format ends with a dangling '%'")
        if fmt[i] == "%":
            literal.append("%")
            i += 1
            continue
        flushed = flush()
        quoted_open = flushed.endswith('"')
        # consume status/conditional/which-request modifiers (e.g. !404, <, >)
        while i < length and fmt[i] in _MODIFIER_CHARS:
            i += 1
        if i >= length:
            raise FormatSpecError("format ends mid-directive")
        if fmt[i] == "{":
            close = fmt.find("}", i)
            if close == -1:
                raise FormatSpecError("unterminated '{' in directive")
            name = fmt[i + 1 : close]
            i = close + 1
            if i >= length:
                raise FormatSpecError(f"'%{{{name}}}' missing its type letter")
            directive = param_directive(name, fmt[i])
            i += 1
        else:
            directive = simple_directive(fmt[i])
            i += 1
        if quoted_open and i < length and fmt[i] == '"':
            directive = Directive(_QUOTED_FRAGMENT, directive.setter)
        tokens.append(directive)
    flush()
    return tokens


def _compile_tokens(tokens: list[Directive | str]) -> tuple[str, list[tuple[str, Setter]]]:
    """Build the line regex and the ``(group, setter)`` list from tokens.

    Every field after the first is made optional, nested from the end, so a line
    that omits one or more *trailing* fields still matches (the absent fields are
    left unset). This lets new fields be appended to the format over time while a
    log that mixes old and new lines keeps parsing -- only the tail is forgiving;
    a missing middle field, or any unconsumed text, still fails the full match.

    Inter-field literals are split at their first whitespace: the part before it
    closes the preceding field (e.g. a quote or ``]``), and the whitespace-onward
    part (the separator and any opening delimiter) begins the next field's unit.
    """
    parts: list[str] = []
    setters: list[tuple[str, Setter]] = []
    unit_starts: list[int] = []  # index in `parts` where each optional field-unit begins
    for token in tokens:
        if isinstance(token, str):
            ws = re.search(r"\s", token)
            if ws is not None and parts:
                head, tail = token[: ws.start()], token[ws.start() :]
                if head:
                    parts.append(re.escape(head))
                unit_starts.append(len(parts))
                parts.append(re.escape(tail))
            else:
                parts.append(re.escape(token))
        else:
            group = f"g{len(setters)}"
            parts.append(f"(?P<{group}>{token.pattern})")
            setters.append((group, token.setter))
    if not unit_starts:
        return "".join(parts), setters
    bounds = zip(unit_starts, unit_starts[1:] + [len(parts)])
    units = ["".join(parts[start:end]) for start, end in bounds]
    tail = ""
    for unit in reversed(units):  # nest: head (?:u0 (?:u1 …)? )?
        tail = f"(?:{unit}{tail})?"
    return "".join(parts[: unit_starts[0]]) + tail, setters


class ApacheParser(LogParser):
    """Parser for a single, fixed Apache log format."""

    name = "apache"

    def __init__(self, log_format: str) -> None:
        self.log_format = log_format
        tokens = _tokenize(log_format)
        pattern, setters = _compile_tokens(tokens)
        if not setters:
            raise FormatSpecError("log format contains no directives")
        self._regex = re.compile(pattern)
        self._setters = setters

    def parse_lines(self, lines: Iterator[str]) -> Iterator[ParseOutcome]:
        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.rstrip("\r\n")
            if not stripped.strip():
                continue
            match = self._regex.fullmatch(stripped)
            if match is None:
                yield ParseOutcome(
                    skip_reason="line did not match log format",
                    line_no=line_no,
                    raw_line=stripped,
                )
                continue
            builder = _Builder()
            try:
                for group, setter in self._setters:
                    value = match.group(group)
                    if value is None:
                        continue  # an omitted trailing field — leave it unset
                    setter(builder, value)
            except (ValueError, KeyError) as exc:
                yield ParseOutcome(
                    skip_reason=f"field conversion failed: {exc}",
                    line_no=line_no,
                    raw_line=stripped,
                )
                continue
            yield ParseOutcome(entry=builder.build(line_no), line_no=line_no)


def _factory(opts: Mapping[str, str]) -> ApacheParser:
    fmt = opts.get("format")
    if not fmt:
        raise ConfigError(
            "apache parser requires a log format (--log-format / --log-format-preset)"
        )
    return ApacheParser(fmt)


register("apache", _factory)
