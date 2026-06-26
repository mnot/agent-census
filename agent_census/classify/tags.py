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
from ..model import (
    BotVerification,
    ClientFeatures,
    ComplianceReport,
    RobotsVerdict,
    VerificationStatus,
)
from .feed_reader import ua_is_feed_reader

_UA_ROTATION_THRESHOLD = 4
# Declared-crawler data categories, checked individually so per-UA results cache.
_CRAWLER_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
    "data_harvester",
)


@lru_cache(maxsize=16384)
def _ua_names_crawler(ua: str | None) -> bool:
    return any(uas.match_category(ua, category) for category in _CRAWLER_CATEGORIES)


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
    """True if the client is a non-browser agent: a feed reader, a known
    crawler/archiver, a self-declared bot, or a crawler recognised by origin AS.

    Such a client is not a browser however it behaves (it can render and co-load
    sub-resources like one), and the browser-specific signals -- fake-browser,
    forged-referer -- don't apply to it; its identity decides the kind. The AS
    case matters for operators that crawl behind spoofed browser User-Agents: the
    UA looks like Chrome and even co-loads assets, but the origin network gives it
    away, so the browser hypothesis must still bow to the crawler classification.
    """
    return (
        features.ua_declares_bot
        or _ua_names_crawler(features.user_agent)
        or ua_is_feed_reader(features.user_agent)
        or uas.match_asn_any(features.as_number) is not None
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


def _fingerprint_tags(features: ClientFeatures) -> set[str]:
    """The behavioural fingerprint: one tag per dimension we can actually measure.

    Each dimension emits its observed value (a polar pair, or a gradation) only
    when there is enough data to judge it -- so an absent tag means "couldn't
    tell", never a silent "no". This is the evidence a reader weighs themselves.
    """
    tags: set[str] = set()

    # Cadence: how regular the inter-arrival timing is (clockwork vs. human).
    reg = features.rate_regularity
    if reg is not None and features.request_count >= 5:
        tags.add("metronomic" if reg < 0.15 else "bursty" if reg > 0.6 else "steady")

    # Sub-resource loading: a browser pulls a page's CSS/JS/images. Only judgeable
    # when the client actually fetched HTML pages.
    if features.page_count > 0:
        if features.asset_coload_ratio > 0.4:
            tags.add("loads-assets")
        elif features.asset_coload_ratio < 0.1:
            tags.add("no-assets")

    # Navigation: following on-site links (referer is a path fetched earlier).
    # Only judgeable when some request carried a Referer at all.
    if features.referer_count > 0 and features.request_count >= 4:
        if features.referer_following_ratio > 0.3:
            tags.add("follows-links")
        elif features.referer_following_ratio < 0.1:
            tags.add("cold")

    # Caching: a 304 proves a real cache. Its absence alone is content/server-
    # dependent, but re-fetching the same URLs (or high volume) without ever
    # earning a 304 does prove no cache -- see ClientFeatures.holds_no_cache.
    if features.status_counts.get(304, 0) > 0:
        tags.add("has-cache")
    elif features.holds_no_cache:
        tags.add("no-browser-cache")

    # A headless / automation-driven browser engine: renders (so it can load
    # assets) but the UA names the harness. A machine tell regardless of behaviour.
    if uas.is_headless(features.user_agent):
        tags.add("headless-browser")

    # User-Agent shape, when one is present -- one mutually-exclusive tag. For a
    # browser the version age is folded in (current/stale/ancient-browser-ua);
    # plain browser-ua means a browser shell whose version we couldn't read.
    # Otherwise a generic HTTP library, or a self-declared bot we *don't*
    # recognise (a recognised crawler is the declares-known-bot fact instead).
    if not features.ua_empty:
        band = uas.version_age_band(features.user_agent, features.last_seen)
        if band is not None:
            tags.add(f"{band}-browser-ua")
        elif features.ua_looks_like_browser:
            tags.add("browser-ua")
        elif uas.is_library(features.user_agent):
            tags.add("generic-ua")
        elif (
            features.ua_declares_bot
            and not _declares_known_crawler(features)
            and not ua_is_feed_reader(features.user_agent)
        ):
            # A self-declared bot we don't recognise -- but a feed reader names
            # itself a feed tool, not a generic bot, so it's never "bot-ua".
            tags.add("bot-ua")

    return tags


def _conduct_tags(features: ClientFeatures) -> set[str]:
    """Noteworthy behaviour, flagged only when present (no negative pole)."""
    tags: set[str] = set()
    # Path-traversal / injection markers are unambiguous, so any is enough. Plain
    # vuln-path hits are gated on a ratio: a broad crawler that grazes a few
    # attack-shaped URLs over tens of thousands of requests isn't a scanner, while
    # a focused probe run is mostly probes (and a lone pure probe is ratio 1.0).
    if features.traversal_hits > 0 or features.vuln_path_ratio >= 0.05:
        tags.add("probing")
    if features.ratio_404 > 0.6 and features.distinct_404_paths >= 15:
        tags.add("404-storm")
    if features.exotic_method_count > 0:
        tags.add("exotic-method")  # PUT/DELETE/PROPFIND/CONNECT … — scanners, WebDAV probes
    if features.head_ratio > 0.1:
        tags.add("uses-HEAD")
    if features.post_ratio > 0.5 and features.request_count >= 5:
        tags.add("post-heavy")
    if (
        features.self_referer_ratio >= 0.5
        and features.request_count >= 4
        # Only meaningful for a client posing as a browser: a fabricated Referer.
        and features.ua_looks_like_browser
        and not identifies_as_known_agent(features)
    ):
        tags.add("forged-referer")
    return tags


def _fact_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    datacenter: bool,
) -> set[str]:
    """Established facts about the client's identity and origin (no behaviour)."""
    tags: set[str] = set()
    if datacenter:
        tags.add("datacenter")
    if features.ua_empty:
        tags.add("no-user-agent")
    if features.fetched_robots_txt:
        tags.add("checked-robots")
    if uas.match_asn_any(features.as_number):
        tags.add("asn-attributed")  # identity *is* the origin AS, not the User-Agent
    if verification is not None and verification.status is VerificationStatus.VERIFIED:
        tags.add("verified")
    if verification is not None and verification.status is VerificationStatus.ASN_ASSOCIATED:
        # UA names a crawler and its origin AS is one that crawler uses -- corroborated.
        tags.add("asn-associated")
    if _declares_known_crawler(features):
        tags.add("declares-known-bot")
    # Only the actionable robots case is tagged; respecting it is the quiet norm.
    if compliance is not None and compliance.verdict is RobotsVerdict.IGNORES:
        tags.add("ignores-robots")
    if features.ua_count_for_ip >= _UA_ROTATION_THRESHOLD:
        # Many UAs on one IP: evasive rotation from a hosting IP or a browser
        # costume; otherwise a benign shared egress (NAT / VPN / proxy / carrier).
        if datacenter or looks_like_fake_browser(features):
            tags.add("ua-rotating")
        else:
            tags.add("shared-ip")
    return tags


def derive_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    *,
    datacenter: bool = False,
) -> set[str]:
    """The client's tags: a measured behavioural fingerprint, conduct flags, and facts."""
    return (
        _fingerprint_tags(features)
        | _conduct_tags(features)
        | _fact_tags(features, compliance, verification, datacenter)
    )
