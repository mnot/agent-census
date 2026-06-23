"""Combine classifier signals into a final classification.

Confidence is treated as an ordinal strength per label, not a probability, so
signals are aggregated per kind (taking the strongest) rather than multiplied.
The strongest label wins; ties break by a fixed priority. Below a threshold the
honest answer is ``UNKNOWN``. Tags are derived separately and can demote a
falsely-claimed good-bot identity.
"""

from __future__ import annotations

from ..model import (
    BotVerification,
    Classification,
    ClientFeatures,
    ComplianceReport,
    Kind,
    Signal,
)
from .tags import derive_tags

# Tie-break order when two kinds share the top confidence: earlier wins.
_PRIORITY: tuple[Kind, ...] = (
    Kind.GOOD_BOT,
    Kind.AI_CRAWLER,
    Kind.VULN_SCANNER,
    Kind.SPAM_BOT,
    Kind.FEED_READER,
    Kind.MONITOR,
    Kind.BROWSER,
    Kind.SCRAPER,
    Kind.CRAWLER,
    Kind.UNKNOWN,
)
_RANK = {kind: i for i, kind in enumerate(_PRIORITY)}

DEFAULT_UNKNOWN_THRESHOLD = 0.45


def _pick(by_label: dict[Kind, float]) -> Kind:
    return max(by_label, key=lambda k: (by_label[k], -_RANK.get(k, len(_PRIORITY))))


def _top_evidence(signals: tuple[Signal, ...]) -> tuple[str, ...]:
    if not signals:
        return ("no classifier produced a signal",)
    strongest = max(signals, key=lambda s: s.confidence)
    return strongest.evidence or ("no specific evidence recorded",)


def combine(
    signals: list[Signal],
    features: ClientFeatures,
    *,
    compliance: ComplianceReport | None = None,
    verification: BotVerification | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
) -> Classification:
    """Aggregate ``signals`` into a primary kind plus secondary tags."""
    by_label: dict[Kind, float] = {}
    for signal in signals:
        by_label[signal.kind] = max(by_label.get(signal.kind, 0.0), signal.confidence)

    tags = derive_tags(features, compliance, verification)
    if "impersonator" in tags:
        # A claimed good/AI bot that DNS or behavior contradicts is not one.
        by_label.pop(Kind.GOOD_BOT, None)
        by_label.pop(Kind.AI_CRAWLER, None)

    all_signals = tuple(signals)
    if not by_label or max(by_label.values()) < unknown_threshold:
        confidence = max(by_label.values()) if by_label else 0.0
        return Classification(
            primary=Kind.UNKNOWN,
            confidence=confidence,
            tags=frozenset(tags),
            evidence=_top_evidence(all_signals),
            all_signals=all_signals,
        )

    primary = _pick(by_label)
    if primary is Kind.FEED_READER and _fetches_non_feeds(features):
        tags.add("fetches-non-feeds")
    evidence = tuple(e for s in signals if s.kind is primary for e in s.evidence)
    return Classification(
        primary=primary,
        confidence=by_label[primary],
        tags=frozenset(tags),
        evidence=evidence,
        all_signals=all_signals,
    )


def _fetches_non_feeds(features: ClientFeatures) -> bool:
    """True if a feed reader also requested non-feed resources (robots.txt aside)."""
    non_feed = features.request_count - features.feed_requests
    if features.fetched_robots_txt:
        non_feed -= 1  # a polite robots.txt fetch does not count as content scraping
    return non_feed > 0
