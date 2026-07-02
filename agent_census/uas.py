"""User-Agent string heuristics, shared by feature extraction and classifiers.

These are deliberately raw, syntactic checks — "does this string look like a
browser / declare itself a bot" — not verdicts about the client's behavior. UA
strings are trivially forged, so downstream logic always corroborates them with
request behavior.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from functools import lru_cache
from typing import TypeVar

from .dataload import (
    KNOWN_AGENT_CATEGORIES,
    BrowserRelease,
    CrawlerSpec,
    load_asn_agents,
    load_browser_releases,
    load_list,
    load_tokens,
    load_ua_signatures,
)

_P = TypeVar("_P")

# The token lists these regexes are built from live in data/signatures/ua_signatures.toml;
# only the structure (the Mozilla anchor, the word-boundary rules) is fixed here.
_SIG = load_ua_signatures()

# A real browser UA starts with a Mozilla token and names a layout engine.
_BROWSER_RE = re.compile(
    r"mozilla/\d.*(" + "|".join(re.escape(e) for e in _SIG.browser_engines) + r")", re.I
)

# Self-identified automation: crawlers, libraries, and scripted clients. Distinctive
# substrings match anywhere; the short words are anchored so they don't fire inside
# unrelated tokens (whole word for "feed", word-ending for "bot" -> "Googlebot").
_BOT_RE = re.compile(
    "|".join(
        [
            *(re.escape(t) for t in _SIG.automation_substrings),
            *(r"\b" + re.escape(w) + r"\b" for w in _SIG.automation_standalone_words),
            *(re.escape(w) + r"\b" for w in _SIG.automation_suffix_words),
        ]
    ),
    re.I,
)

# A '+'-prefixed contact URL or e-mail is the convention bots use to give
# webmasters a way to reach the operator -- "(+https://example.com/bot)" or
# "+ops@example.com". A real browser never advertises one, so it marks
# self-identified automation even when the product token carries no bot/crawl
# word (e.g. "Claude-User", "SomeFetcher") and wears a browser-shaped shell.
_BOT_CONTACT_RE = re.compile(r"\+(?:https?://|www\.|mailto:|[\w.%+-]+@)", re.I)

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
    return bool(_BOT_RE.search(ua) or _BOT_CONTACT_RE.search(ua))


# Browser engines driven by automation frameworks. They render like a real browser
# (so they load assets), but the UA names the harness -- a deliberate tell.
_HEADLESS_RE = re.compile("|".join(re.escape(e) for e in _SIG.headless_engines), re.I)


@lru_cache(maxsize=16384)
def is_headless(ua: str | None) -> bool:
    """True when the UA names a headless / automation-driven browser engine."""
    if is_empty(ua) or ua is None:
        return False
    return bool(_HEADLESS_RE.search(ua))


# Anonymous HTTP clients: a library/tool name with no product identity of its own.
_LIBRARY_RE = re.compile("|".join(re.escape(n) for n in _SIG.library_names), re.I)


@lru_cache(maxsize=16384)
def is_library(ua: str | None) -> bool:
    """True when the UA is a generic HTTP library/tool rather than a named agent."""
    if is_empty(ua) or ua is None:
        return False
    return bool(_LIBRARY_RE.search(ua))


# Native-app networking-stack tokens (Apple's CFNetwork, Flutter's dart:io, …),
# from data/signatures/app_clients.toml.
_APP_CLIENT_RE = re.compile("|".join(re.escape(t) for t in load_list("app_clients")), re.I)


@lru_cache(maxsize=16384)
def app_stack_token(ua: str | None) -> str | None:
    """The native-app networking token in the UA, or None."""
    if is_empty(ua) or ua is None:
        return None
    match = _APP_CLIENT_RE.search(ua)
    return match.group(0) if match else None


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


# Declared-crawler data categories: a UA recognised in any of these belongs to that
# category's classifier (search engine, AI crawler, …), not the generic crawler one.
KNOWN_CRAWLER_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
    "data_harvester",
)


@lru_cache(maxsize=16384)
def names_known_crawler(ua: str | None) -> bool:
    """True if the UA names a crawler we recognise in a specific category."""
    return any(match_category(ua, category) is not None for category in KNOWN_CRAWLER_CATEGORIES)


@lru_cache(maxsize=16384)
def names_user_triggered_agent(ua: str | None) -> bool:
    """True if the UA names a known agent the operator designates as user-driven.

    These are the ``-User`` / on-behalf-of proxies (ChatGPT-User, Amzn-User,
    YandexUserproxy …) whose spec sets ``user_triggered``. The flag records the
    operator's stated purpose for the token -- a fetch made in response to a present
    user's action rather than autonomous crawling -- which we take on trust: whether
    a human actually prompted any given request isn't observable here, and identity
    verification (where available) confirms who the agent is, not that a user drove
    it. Orthogonal to the kind: such an agent is still an ai_crawler or search_engine.
    """
    for category in KNOWN_CRAWLER_CATEGORIES:
        match = match_category(ua, category)
        if match is not None and match[1].user_triggered:
            return True
    return False


@lru_cache(maxsize=16384)
def declared_wba_operator(ua: str | None) -> str | None:
    """The Web Bot Auth operator a UA claims to be, by its declared agent entry.

    Reads the matched ``[[agent]]``'s own ``wba_operator`` field -- the same
    matcher :func:`match_category` uses everywhere else -- rather than a second,
    independent UA scan. ``None`` when the UA names no known agent, or a known
    agent with no ``wba_operator`` declared.
    """
    for category in KNOWN_CRAWLER_CATEGORIES:
        match = match_category(ua, category)
        if match is not None and match[1].wba_operator:
            return match[1].wba_operator
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


# Major-version tokens per family. Firefox and Chrome first; every Chromium
# browser (Chrome, Edge, Opera, Brave, …) carries a "Chrome/<n>" token at the
# Chromium major, so matching it covers them all. The iOS browsers wear their own
# tokens -- Chrome for iOS is "CriOS/<n>" and Firefox for iOS is "FxiOS/<n>" --
# but track the same release trains, so fold them into the respective family.
# Safari's real version is the "Version/<n>" token (the trailing "Safari/605.x" is
# a frozen WebKit build); Chrome desktop UAs carry no "Version/" token, so the
# Chrome check wins first.
# Bound the major-version capture to at most 9 digits. Real browser majors are
# two or three digits; without the bound a crafted UA carrying a multi-thousand
# digit run (e.g. "Chrome/999...") would reach int(), which raises ValueError on
# Python 3.11+ (the 4300-digit integer-string-conversion limit) and abort the run.
_FIREFOX_VER_RE = re.compile(r"(?:firefox|fxios)/(\d{1,9})", re.I)
_CHROME_VER_RE = re.compile(r"(?:chrome|crios)/(\d{1,9})", re.I)
_SAFARI_VER_RE = re.compile(r"version/(\d{1,9})[\d._]*\s+(?:mobile/\S+\s+)?safari", re.I)


def browser_version(ua: str | None) -> tuple[str, int] | None:
    """``(family, major)`` for a recognised browser UA, else None.

    Firefox and Chromium-based browsers report their auto-update major; Safari
    reports its ``Version/`` major (aged leniently downstream). Other UAs yield
    None.
    """
    if is_empty(ua) or ua is None:
        return None
    match = _FIREFOX_VER_RE.search(ua)
    if match:
        return "firefox", int(match.group(1))
    match = _CHROME_VER_RE.search(ua)
    if match:
        return "chrome", int(match.group(1))
    match = _SAFARI_VER_RE.search(ua)
    if match:
        return "safari", int(match.group(1))
    return None


@lru_cache(maxsize=None)
def _release_index() -> dict[str, BrowserRelease]:
    return {rel.name.lower(): rel for rel in load_browser_releases()}


# Safari's major jumped 18 (2024) -> 26 (2025) when Apple aligned every OS and
# Safari to the year-based number (26 = the 2025 release, like iOS/macOS 26),
# skipping 19-25. Map the year-based majors back onto the continuous pre-jump
# scale (26 -> 19, 27 -> 20, …) so the one-major-per-year cadence stays linear and
# Safari ages correctly in both directions. Pre-jump numbers are unchanged.
_SAFARI_JUMP_FROM = 26  # first year-based major
_SAFARI_JUMP_GAP = 7  # 26 follows 18, so 19..25 were skipped


def _safari_continuous_major(major: int) -> int:
    """Safari's major on the continuous timeline, undoing the 2025 year-renumber."""
    return major - _SAFARI_JUMP_GAP if major >= _SAFARI_JUMP_FROM else major


def version_age_months(ua: str | None, as_of: datetime | None) -> float | None:
    """How many months out of date the UA's browser version was at ``as_of``.

    Estimates the claimed major's release date from the family's linear cadence
    and measures its age when the client was active. Negative means newer than
    the model expects (fresh). None when the family/version can't be read, or no
    ``as_of`` is known. Modern browsers auto-update, so a large positive age is
    evidence the UA is a frozen, spoofed string rather than a real browser.
    """
    if as_of is None:
        return None
    parsed = browser_version(ua)
    if parsed is None:
        return None
    family, major = parsed
    release = _release_index().get(family)
    if release is None:
        return None
    if family == "safari":
        major = _safari_continuous_major(major)
    estimated = release.anchor_date + timedelta(
        days=(major - release.anchor_major) * release.days_per_major
    )
    return (as_of.date() - estimated).days / 30.4


def _safari_age_band(age: float) -> str | None:
    """Version-age band for Safari, judged on its roughly yearly cadence.

    Safari is OS-bundled (not silently auto-updating) and lingers on old Apple
    hardware, so it never earns the ``impossible``/``ancient`` cap the auto-update
    families get. With the year-renumber undone upstream the cadence is one major
    per year, so ``current`` spans the ~year the release stays latest and ``stale``
    means at least two annual versions behind. A version between those (roughly one
    year behind) is normal for OS-bundled Safari and gives no freshness signal
    either way, so it returns ``None`` -- the neutral middle, not ``current`` or
    ``stale``.
    """
    if age < -13:
        return None  # implausibly ahead of the yearly cadence -- no freshness credit
    if age <= 13:
        return "current"
    return "stale" if age >= 24 else None


def version_age_band(ua: str | None, as_of: datetime | None) -> str | None:
    """Classify the UA's browser version age: ``current`` / ``stale`` / ``ancient``.

    None when no browser version or active time is known. Auto-updating families
    (Chrome/Firefox) are judged tightly -- years behind is ``ancient``, far ahead
    is ``impossible``. Safari is OS-bundled and judged on its yearly cadence
    (:func:`_safari_age_band`): ``current``, ``stale``, or ``None`` for the neutral
    ~one-year-behind middle (it never earns ``impossible``/``ancient``). The single
    source of truth for both the browser classifier's confidence nudge and the
    ``*-ua`` tags.
    """
    parsed = browser_version(ua)
    age = version_age_months(ua, as_of)
    if parsed is None or age is None:
        return None
    if parsed[0] == "safari":
        return _safari_age_band(age)
    if age < -12:
        # Claims a version more than a year ahead of the family's release cadence:
        # impossible for a real auto-updating browser, so it's a forged UA (e.g.
        # Chrome/999 to look maximally fresh), not a "current" one.
        return "impossible"
    if age <= 6:
        return "current"
    if age >= 36:
        return "ancient"
    return "stale" if age >= 18 else None
