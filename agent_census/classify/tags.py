"""Secondary tags and the impersonation verdict.

Tags are orthogonal descriptors layered on top of the primary kind: how the
client treats robots.txt, whether DNS confirms its declared identity, and
behavioural notes. They do not compete with the kind.

Impersonation is different: it *is* the kind. :func:`impersonation` decides
whether a client is pretending to be something it is not -- a declared crawler
whose IP fails DNS / range verification -- and the combiner makes such a client
an ``impersonator``. Bad behaviour (probing, ignoring robots) is only ever a
tag; a genuine crawler can misbehave without forging its identity.
"""

from __future__ import annotations

from functools import lru_cache

from .. import uas
from ..dataload import load_list
from ..model import (
    BotVerification,
    ClientFeatures,
    ComplianceReport,
    RobotsVerdict,
    VerificationStatus,
)

_UA_ROTATION_THRESHOLD = 4
# Declared-crawler data categories, checked individually so per-UA results cache.
_CRAWLER_CATEGORIES = ("search_engine", "social_preview", "archiver", "ai_crawler", "seo_marketing")
_FEED_TOKENS = tuple(token.lower() for token in load_list("feed_readers"))


@lru_cache(maxsize=16384)
def _ua_names_crawler(ua: str | None) -> bool:
    return any(uas.match_category(ua, category) for category in _CRAWLER_CATEGORIES)


@lru_cache(maxsize=16384)
def _ua_names_feed_reader(ua: str | None) -> bool:
    low = (ua or "").lower()
    return any(token in low for token in _FEED_TOKENS)


def _declares_known_crawler(features: ClientFeatures) -> bool:
    return _ua_names_crawler(features.user_agent)


def impersonation(verification: BotVerification | None) -> tuple[bool, tuple[str, ...]]:
    """Decide whether the client is impersonating a declared identity.

    Impersonation is a forged *identity*: only DNS / IP-range verification saying
    the address isn't really that crawler counts. Misbehaviour such as ignoring
    robots.txt or probing for vulnerabilities is tagged, not treated as identity
    theft -- a real crawler can still behave badly.
    """
    if verification is not None and verification.status is VerificationStatus.IMPERSONATOR:
        return True, verification.evidence or (
            "DNS / IP range does not confirm the declared crawler",
        )
    return False, ()


def identifies_as_known_agent(features: ClientFeatures) -> bool:
    """True if the UA positively names a non-browser agent: a feed reader, a known
    crawler/archiver, or a self-declared bot.

    Such a client is not a browser however it behaves (it can render and co-load
    sub-resources like one), and the browser-specific signals -- fake-browser,
    forged-referer -- don't apply to it; its declared identity decides the kind.
    """
    return (
        features.ua_declares_bot
        or _ua_names_crawler(features.user_agent)
        or _ua_names_feed_reader(features.user_agent)
    )


def looks_like_fake_browser(features: ClientFeatures) -> bool:
    """A browser User-Agent showing none of the behaviour a real browser shows.

    Real browsers pull a page's sub-resources (CSS/JS/images) and follow links
    via the referer. A client claiming to be a browser that never co-loads assets
    and never follows a referer is presenting a costume, not browsing. Needs at
    least two requests -- a single request reveals nothing either way. A UA that
    names a known agent (feed reader / crawler / bot) is identifying itself, not
    faking a browser, so it is excluded.
    """
    return (
        features.ua_looks_like_browser
        and not identifies_as_known_agent(features)
        and features.request_count >= 2
        and features.asset_coload_ratio == 0.0
        and features.referer_following_ratio == 0.0
    )


def derive_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    *,
    datacenter: bool = False,
) -> set[str]:
    """Compute the secondary tags for a client."""
    tags: set[str] = set()

    if datacenter:
        tags.add("datacenter")
    if looks_like_fake_browser(features):
        tags.add("fake-browser")

    if features.fetched_robots_txt:
        tags.add("checked-robots")
    if features.ua_empty:
        tags.add("no-user-agent")
    if features.ua_count_for_ip >= _UA_ROTATION_THRESHOLD:
        # Many UAs on one IP reads two ways. From a hosting IP, or paired with a
        # browser costume and no browser behaviour, it's evasive rotation. Other-
        # wise it's almost always a shared egress (NAT / VPN / proxy / carrier)
        # where many real clients share the address -- benign, so name it plainly.
        if datacenter or looks_like_fake_browser(features):
            tags.add("ua-rotating")
        else:
            tags.add("shared-ip")

    if compliance is not None:
        if compliance.verdict is RobotsVerdict.RESPECTS:
            tags.add("respects-robots")
        elif compliance.verdict is RobotsVerdict.IGNORES:
            tags.add("ignores-robots")

    if verification is not None and verification.status is VerificationStatus.VERIFIED:
        tags.add("verified")

    if _declares_known_crawler(features):
        tags.add("declares-known-bot")

    if features.vuln_path_hits > 0 or features.traversal_hits > 0:
        tags.add("probing")  # badly behaved, but not necessarily a forged identity

    if (
        features.self_referer_ratio >= 0.5
        and features.request_count >= 4
        # Only meaningful for a client posing as a browser: a Referer faked to mimic
        # navigation. A non-browser UA (or a declared agent) self-referring is not
        # faking browser traffic, so the tag says nothing there.
        and features.ua_looks_like_browser
        and not identifies_as_known_agent(features)
    ):
        tags.add("forged-referer")  # Referer set to the requested URL -- faked navigation

    return tags
