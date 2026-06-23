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

from .. import uas
from ..dataload import load_list, load_tokens
from ..model import (
    BotVerification,
    ClientFeatures,
    ComplianceReport,
    RobotsVerdict,
    VerificationStatus,
)

_UA_ROTATION_THRESHOLD = 4


def _declares_known_crawler(features: ClientFeatures) -> bool:
    pairs = (
        load_tokens("search_engine")
        + load_tokens("social_preview")
        + load_tokens("ai_crawler")
        + load_tokens("seo_marketing")
    )
    return uas.match_known(features.user_agent, pairs) is not None


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


def _identifies_as_known_agent(features: ClientFeatures) -> bool:
    """True if the UA positively names a non-browser agent it could only be lying about.

    Feed readers, known crawlers, and self-declared bots routinely wear a Safari
    or Chrome prefix with their product token appended (``... NetNewsWire/6``).
    That is an honest identity, not a browser costume, so it must not count as a
    fake browser.
    """
    if features.ua_declares_bot or _declares_known_crawler(features):
        return True
    ua = (features.user_agent or "").lower()
    return any(token.lower() in ua for token in load_list("feed_readers"))


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
        and not _identifies_as_known_agent(features)
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

    return tags
