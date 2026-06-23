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
from .tags import derive_tags, impersonation, looks_like_fake_browser

# Tie-break order when two kinds share the top confidence: earlier wins.
_PRIORITY: tuple[Kind, ...] = (
    Kind.IMPERSONATOR,
    Kind.SEARCH_ENGINE,
    Kind.SOCIAL_PREVIEW,
    Kind.ARCHIVER,
    Kind.AI_CRAWLER,
    Kind.SEO_MARKETING,
    Kind.VULN_SCANNER,
    Kind.SPAM_BOT,
    Kind.FEED_READER,
    Kind.MONITOR,
    Kind.BROWSER,
    Kind.SCRAPER,
    Kind.CRAWLER,
    Kind.SPOOFED_BROWSER,
    Kind.SINGLETON,
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
    datacenter: bool = False,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
) -> Classification:
    """Aggregate ``signals`` into a primary kind plus secondary tags.

    ``keep_signals`` retains every contributing signal on the result for inspect
    mode's rationale. The ``analyze`` report never reads them, so it passes
    ``False`` to avoid holding a Signal (and its evidence strings) per client.
    """
    by_label: dict[Kind, float] = {}
    for signal in signals:
        by_label[signal.kind] = max(by_label.get(signal.kind, 0.0), signal.confidence)

    # A person rarely browses from hosting infrastructure, so nudge a datacenter
    # "browser" verdict down a little -- enough to tip a borderline one, not to
    # overrule a strongly-behaving real browser.
    if datacenter and Kind.BROWSER in by_label:
        by_label[Kind.BROWSER] = max(0.0, by_label[Kind.BROWSER] - 0.1)

    tags = derive_tags(features, compliance, verification, datacenter=datacenter)
    stored = tuple(signals) if keep_signals else ()

    # Impersonation is decisive: a client faking a declared identity is an
    # impersonator, whatever else it looks like.
    faking, why = impersonation(verification)
    if faking:
        return Classification(
            primary=Kind.IMPERSONATOR,
            confidence=0.9,
            tags=frozenset(tags),
            evidence=why,
            all_signals=stored,
        )

    if not by_label or max(by_label.values()) < unknown_threshold:
        # A would-be-unknown client wearing a browser UA from a hosting IP, with
        # no browser behaviour, is automation in disguise -- name it as such.
        if datacenter and looks_like_fake_browser(features):
            return Classification(
                primary=Kind.SPOOFED_BROWSER,
                confidence=0.6,
                tags=frozenset(tags),
                evidence=("browser User-Agent from a datacenter IP, without browser behaviour",),
                all_signals=stored,
            )
        # A would-be-unknown client with a single request gets its own bucket:
        # one hit is too little to characterize, so we file it by volume.
        if features.request_count == 1:
            return Classification(
                primary=Kind.SINGLETON,
                confidence=1.0,
                tags=frozenset(tags),
                evidence=("single request — too little activity to characterize",),
                all_signals=stored,
            )
        confidence = max(by_label.values()) if by_label else 0.0
        return Classification(
            primary=Kind.UNKNOWN,
            confidence=confidence,
            tags=frozenset(tags),
            evidence=_top_evidence(tuple(signals)),
            all_signals=stored,
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
        all_signals=stored,
    )


def _fetches_non_feeds(features: ClientFeatures) -> bool:
    """True if a feed reader also requested non-feed resources (robots.txt aside)."""
    non_feed = features.request_count - features.feed_requests
    if features.fetched_robots_txt:
        non_feed -= 1  # a polite robots.txt fetch does not count as content scraping
    return non_feed > 0
