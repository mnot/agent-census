"""Secondary tag derivation.

Tags are orthogonal descriptors layered on top of the primary kind: how the
client treats robots.txt, whether DNS confirms its declared identity, and
behavioral red flags. They do not compete with the kind — a vuln scanner that
avoids disallowed paths is still a vuln scanner — but a couple of them (notably
``impersonator``) feed back into the combiner to demote a falsely-claimed
good-bot identity.
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
    pairs = load_tokens("good_bots.txt") + load_tokens("ai_crawlers.txt")
    return uas.match_known(features.user_agent, pairs) is not None


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

    if verification is not None:
        if verification.status is VerificationStatus.VERIFIED:
            tags.add("verified")
        elif verification.status is VerificationStatus.IMPERSONATOR:
            tags.add("impersonator")

    # Behavioral impersonation: a real search/AI crawler never probes for
    # vulnerabilities. That (or a DNS mismatch, handled above) is spoofing
    # evidence — merely ignoring robots.txt is not, since plenty of declared
    # crawlers do that; it gets the `ignores-robots` tag instead.
    if _declares_known_crawler(features):
        tags.add("declares-known-bot")
        if features.vuln_path_hits > 0 or features.traversal_hits > 0:
            tags.add("impersonator")

    return tags
