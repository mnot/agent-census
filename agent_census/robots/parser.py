"""Parse robots.txt and answer per-UA questions.

Wraps the stdlib :class:`urllib.robotparser.RobotFileParser` for the actual
allow/deny decisions, and adds a thin layer to report *which* User-agent group
applied (the stdlib parser does not expose that) for inspect-mode evidence.
"""

from __future__ import annotations

from urllib.robotparser import RobotFileParser


class RobotsRules:
    """Allow/deny rules from one robots.txt document."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._parser = RobotFileParser()
        self._parser.parse(text.splitlines())
        self._groups = self._group_tokens(text)
        self._has_disallow = any(
            line.strip().lower().startswith("disallow:") and line.split(":", 1)[1].strip()
            for line in text.splitlines()
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

    def can_fetch(self, ua_token: str | None, path: str) -> bool:
        """Whether ``ua_token`` is allowed to fetch ``path``."""
        return self._parser.can_fetch(ua_token or "*", path)

    def crawl_delay(self, ua_token: str | None) -> float | None:
        """The Crawl-delay applicable to ``ua_token``, if any."""
        delay = self._parser.crawl_delay(ua_token or "*")
        return float(delay) if delay is not None else None

    def matched_group(self, ua_token: str | None) -> str | None:
        """Best-effort name of the User-agent group that applies to ``ua_token``."""
        if ua_token:
            low = ua_token.lower()
            for token in self._groups:
                if token != "*" and token.lower() in low:
                    return token
        return "*" if "*" in self._groups else None
