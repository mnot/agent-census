"""Secondary tags and the impersonation verdict.

Tags are orthogonal descriptors layered on top of the primary kind: how the
client treats robots.txt, whether DNS confirms its declared identity, and
behavioural notes. They do not compete with the kind.

Impersonation is different: it *is* the kind. :func:`impersonation` decides
whether a client is pretending to be something it is not -- a declared crawler
whose DNS does not check out, or one that probes for vulnerabilities while
claiming a search/AI/SEO identity -- and the combiner makes such a client an
``impersonator``.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_tokens
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
        load_tokens("search_engines.txt")
        + load_tokens("social_preview.txt")
        + load_tokens("ai_crawlers.txt")
        + load_tokens("seo_marketing.txt")
    )
    return uas.match_known(features.user_agent, pairs) is not None


def impersonation(
    features: ClientFeatures, verification: BotVerification | None
) -> tuple[bool, tuple[str, ...]]:
    """Decide whether the client is impersonating a declared identity.

    Returns ``(is_impersonator, evidence)``. Merely ignoring robots.txt is not
    impersonation -- plenty of real crawlers do that -- so only a DNS mismatch
    or vulnerability probing under a crawler UA counts.
    """
    if verification is not None and verification.status is VerificationStatus.IMPERSONATOR:
        return True, verification.evidence or ("DNS does not confirm the declared crawler",)
    if _declares_known_crawler(features) and (
        features.vuln_path_hits > 0 or features.traversal_hits > 0
    ):
        return True, (
            "claims a known-crawler User-Agent but probes for vulnerabilities "
            f"({features.vuln_path_hits} probe paths, {features.traversal_hits} traversal markers)",
        )
    return False, ()


def derive_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
) -> set[str]:
    """Compute the secondary tags for a client."""
    tags: set[str] = set()

    if features.fetched_robots_txt:
        tags.add("checked-robots")
    if features.ua_empty:
        tags.add("no-user-agent")
    if features.ua_count_for_ip >= _UA_ROTATION_THRESHOLD:
        tags.add("ua-rotating")

    if compliance is not None:
        if compliance.verdict is RobotsVerdict.RESPECTS:
            tags.add("respects-robots")
        elif compliance.verdict is RobotsVerdict.IGNORES:
            tags.add("ignores-robots")

    if verification is not None and verification.status is VerificationStatus.VERIFIED:
        tags.add("verified")

    if _declares_known_crawler(features):
        tags.add("declares-known-bot")

    return tags
