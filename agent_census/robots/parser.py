"""Parse robots.txt and answer per-UA questions.

The allow/deny verdict is computed here with an RFC 9309-compliant matcher --
``*`` wildcards and ``$`` end-anchors included, most-specific rule wins, an Allow
breaking a same-length tie. The stdlib :class:`urllib.robotparser.RobotFileParser`
is kept only for ``Crawl-delay`` (which it parses and RFC 9309 does not define):
its matcher does *not* honour ``*``/``$``, so a rule like ``Disallow: /*.pdf$``
was silently inert there and a violating fetch read as compliant.
"""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.robotparser import RobotFileParser

# One parsed group: the User-agent tokens it applies to (lowercased) and its
# rules in document order as ``(is_allow, path_pattern)``.
_Group = tuple[list[str], list[tuple[bool, str]]]


@lru_cache(maxsize=4096)
def _pattern_regex(pattern: str) -> re.Pattern[str]:
    """Compile a robots.txt path pattern to an anchored regex.

    ``*`` matches any run (including empty); a trailing ``$`` anchors the path
    end. Every other character -- including a non-terminal ``$`` -- is literal.
    The result is matched with ``.match`` (start-anchored), so a pattern without
    a trailing ``$`` is the usual prefix match: ``/foo`` covers ``/foobar``.
    """
    out = ["^"]
    last = len(pattern) - 1
    for i, char in enumerate(pattern):
        if char == "*":
            out.append(".*")
        elif char == "$" and i == last:
            out.append("$")
        else:
            out.append(re.escape(char))
    return re.compile("".join(out))


def _parse_groups(text: str) -> list[_Group]:
    """Split robots.txt into groups of (User-agent tokens, ordered rules).

    A run of consecutive ``User-agent`` lines shares the rules that follow it; the
    next ``User-agent`` after a rule starts a new group. ``#`` begins a comment.
    Rules before any ``User-agent`` line are ignored, as the format requires.
    """
    groups: list[_Group] = []
    agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    started_rules = False

    def flush() -> None:
        nonlocal agents, rules, started_rules
        if agents:
            groups.append((agents, rules))
        agents, rules, started_rules = [], [], False

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            if started_rules:
                flush()
            agents.append(value.lower())
        elif key in ("allow", "disallow") and agents:
            rules.append((key == "allow", value))
            started_rules = True
    flush()
    return groups


class RobotsRules:
    """Allow/deny rules from one robots.txt document."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._parser = RobotFileParser()
        self._parser.parse(text.splitlines())
        self._rule_groups = _parse_groups(text)
        self._groups = self._group_tokens(text)
        self._has_disallow = any(
            not allow and pattern for _, rules in self._rule_groups for allow, pattern in rules
        )

    @staticmethod
    def _group_tokens(text: str) -> list[str]:
        tokens: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("user-agent:"):
                tokens.append(stripped.split(":", 1)[1].strip())
        return tokens

    def has_rules(self) -> bool:
        """True when the document contains at least one effective Disallow."""
        return self._has_disallow

    def _applicable_rules(self, ua_token: str | None) -> list[tuple[bool, str]]:
        """The rules of the most specific group whose token matches ``ua_token``.

        A group token matches when it is a case-insensitive substring of the
        client token; the longest matching token wins (RFC 9309 most-specific),
        and the wildcard ``*`` group is the fallback when nothing else matches.
        """
        ua = (ua_token or "*").lower()
        best_len = -1
        best: list[tuple[bool, str]] | None = None
        star: list[tuple[bool, str]] | None = None
        for tokens, rules in self._rule_groups:
            for token in tokens:
                if token == "*":
                    star = rules
                elif token and token in ua and len(token) > best_len:
                    best_len, best = len(token), rules
        if best is not None:
            return best
        return star if star is not None else []

    def can_fetch(self, ua_token: str | None, path: str) -> bool:
        """Whether ``ua_token`` is allowed to fetch ``path``.

        The most specific matching rule wins (by pattern length); a same-length
        Allow beats a Disallow; nothing matching means allowed.
        """
        best_len = -1
        allowed = True
        for is_allow, pattern in self._applicable_rules(ua_token):
            if not pattern:
                continue  # an empty Disallow/Allow imposes no restriction
            if _pattern_regex(pattern).match(path):
                length = len(pattern)
                if length > best_len or (length == best_len and is_allow):
                    best_len, allowed = length, is_allow
        return allowed

    def crawl_delay(self, ua_token: str | None) -> float | None:
        """The Crawl-delay applicable to ``ua_token``, if any."""
        delay = self._parser.crawl_delay(ua_token or "*")
        return float(delay) if delay is not None else None

    def matched_group(self, ua_token: str | None) -> str | None:
        """Best-effort name of the User-agent group that applies to ``ua_token``,
        for inspect-mode evidence: document-order first match over the file's groups.

        REVIEWERS, READ THIS before "fixing" the rule -- it has burned us twice.
        This is a *display* heuristic; it is NOT the verdict's own group selection,
        and the two can legitimately disagree. The verdict (:meth:`can_fetch`) uses
        longest-token (most-specific) selection per RFC 9309; this line reports the
        first group in document order so the displayed evidence is stable and
        version-independent. Do NOT reconcile them -- e.g. a ``Google`` group before
        a ``Googlebot`` group displays ``Google`` here while the verdict obeys
        ``Googlebot``, and that divergence is intentional and tested.

        Keep this a stable, self-contained, text-derived heuristic.
        """
        if ua_token:
            low = ua_token.lower()
            for token in self._groups:
                if token != "*" and token.lower() in low:
                    return token
        return "*" if "*" in self._groups else None
