"""User-Agent string heuristics, shared by feature extraction and classifiers.

These are deliberately raw, syntactic checks — "does this string look like a
browser / declare itself a bot" — not verdicts about the client's behavior. UA
strings are trivially forged, so downstream logic always corroborates them with
request behavior.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import TypeVar

from .dataload import KNOWN_AGENT_CATEGORIES, CrawlerSpec, load_asn_agents, load_tokens

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


@lru_cache(maxsize=16384)
def looks_like_browser(ua: str | None) -> bool:
    """True when the UA syntactically resembles a real browser and not a bot."""
    if is_empty(ua) or ua is None:
        return False
    return bool(_BROWSER_RE.search(ua)) and not declares_bot(ua)


@lru_cache(maxsize=16384)
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


@lru_cache(maxsize=None)
def _lowered(category: str) -> tuple[tuple[str, str, CrawlerSpec], ...]:
    """Category tokens as (lowercased-substring, original, spec); built once each."""
    return tuple((sub.lower(), sub, spec) for sub, spec in load_tokens(category))


@lru_cache(maxsize=32768)
def match_category(ua: str | None, category: str) -> tuple[str, CrawlerSpec] | None:
    """First (substring, spec) in ``category`` whose token occurs in ``ua`` (cached).

    Memoised by (ua, category): classification runs per client and User-Agents
    repeat heavily, so a plain scan would redo the same search for every client.
    """
    if is_empty(ua) or ua is None:
        return None
    low = ua.lower()
    for low_sub, sub, spec in _lowered(category):
        if low_sub in low:
            return sub, spec
    return None


def parse_asn(value: str | None) -> int | None:
    """Parse a logged AS number (``35237`` or ``AS35237``) to an int, or None."""
    if not value:
        return None
    text = value.strip()
    if text[:2].lower() == "as":
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return None


@lru_cache(maxsize=None)
def _asn_index(category: str) -> dict[int, str]:
    return dict(load_asn_agents(category))


def match_asn(as_number: str | None, category: str) -> str | None:
    """Label if the logged AS number names an ASN-recognised agent in ``category``."""
    asn = parse_asn(as_number)
    return _asn_index(category).get(asn) if asn is not None else None


def match_asn_any(as_number: str | None) -> str | None:
    """Label if the AS number names an ASN-recognised agent in any known category."""
    asn = parse_asn(as_number)
    if asn is None:
        return None
    for category in KNOWN_AGENT_CATEGORIES:
        label = _asn_index(category).get(asn)
        if label is not None:
            return label
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
