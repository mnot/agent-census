"""User-Agent string heuristics, shared by feature extraction and classifiers.

These are deliberately raw, syntactic checks — "does this string look like a
browser / declare itself a bot" — not verdicts about the client's behavior. UA
strings are trivially forged, so downstream logic always corroborates them with
request behavior.
"""

from __future__ import annotations

import re
from typing import TypeVar

_P = TypeVar("_P")

# A real browser UA starts with a Mozilla token and names a layout engine.
_BROWSER_RE = re.compile(r"mozilla/\d.*(gecko|applewebkit|trident|presto|khtml)", re.I)

# Self-identified automation: crawlers, libraries, and scripted clients.
_BOT_RE = re.compile(
    r"bot\b|bot/|spider|crawl|slurp|scrapy|python-requests|httpx|aiohttp|"
    r"libwww|java/|go-http|okhttp|node-fetch|axios|curl|wget|"
    r"headless|phantomjs|selenium|facebookexternalhit|feedfetcher|"
    r"\bfeed\b|rss|monitor|uptime|pingdom",
    re.I,
)

# Best-effort product token, e.g. "Googlebot/2.1 (...)" -> "Googlebot".
_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]+)/[0-9]")


def is_empty(ua: str | None) -> bool:
    """True when the User-Agent header was absent or blank."""
    return not (ua and ua.strip())


def looks_like_browser(ua: str | None) -> bool:
    """True when the UA syntactically resembles a real browser and not a bot."""
    if is_empty(ua) or ua is None:
        return False
    return bool(_BROWSER_RE.search(ua)) and not declares_bot(ua)


def declares_bot(ua: str | None) -> bool:
    """True when the UA self-identifies as automation."""
    if is_empty(ua) or ua is None:
        return False
    return bool(_BOT_RE.search(ua))


def match_known(ua: str | None, pairs: tuple[tuple[str, _P], ...]) -> tuple[str, _P] | None:
    """Return the first ``(substring, payload)`` whose substring occurs in ``ua``."""
    if is_empty(ua) or ua is None:
        return None
    low = ua.lower()
    for substring, payload in pairs:
        if substring.lower() in low:
            return substring, payload
    return None


def product_token(ua: str | None) -> str | None:
    """Extract a likely product token for robots.txt group matching.

    Prefers the token inside a ``compatible; X/ver`` clause (where crawlers
    usually name themselves), else the first ``name/version`` token.
    """
    if is_empty(ua) or ua is None:
        return None
    compat = re.search(r"compatible;\s*([A-Za-z][A-Za-z0-9._-]+)", ua)
    if compat:
        return compat.group(1)
    match = _TOKEN_RE.search(ua)
    if match and match.group(1).lower() != "mozilla":
        return match.group(1)
    return None
