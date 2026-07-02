"""Combine classifier signals into a final classification.

Confidence is treated as an ordinal strength per label, not a probability, so
signals are aggregated per kind (taking the strongest) rather than multiplied.
The strongest label wins; ties break by a fixed priority. Below a threshold the
honest answer is ``UNKNOWN``. Tags are derived separately and can demote a
falsely-claimed good-bot identity.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_shared_tuning, load_tuning
from ..model import (
    BotVerification,
    Classification,
    ClientFeatures,
    ComplianceReport,
    Kind,
    Signal,
    WbaResult,
)
from .tags import derive_tag_evidence, impersonation, looks_like_fake_browser

# Numeric knobs: this module's own in data/tuning/combiner.toml, the unknown
# threshold in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "round_digits": "round_digits",
    "dc_browser_penalty": "datacenter.browser_penalty",
    "dc_scraper_min_requests": "datacenter.scraper_min_requests",
    "dc_scraper_min_distinct": "datacenter.scraper_min_distinct_paths",
    "fallback_spoofed_browser": "fallback.spoofed_browser",
    "fallback_scraper": "fallback.scraper",
    "fallback_automation": "fallback.automation",
    "impersonator_confidence": "impersonator.confidence",
}
_T = load_tuning("combiner", _TUNING_SCHEMA)
_S = load_shared_tuning()
_ROUND = int(_T["round_digits"])

# Tie-break order when two kinds share the top confidence: earlier wins.
_PRIORITY: tuple[Kind, ...] = (
    Kind.IMPERSONATOR,
    Kind.SEARCH_ENGINE,
    Kind.SOCIAL_PREVIEW,
    Kind.ARCHIVER,
    Kind.AI_CRAWLER,
    Kind.SEO_MARKETING,
    Kind.DATA_HARVESTER,
    Kind.VULN_SCANNER,
    Kind.SPAM_BOT,
    Kind.FEED_READER,
    Kind.MONITOR,
    Kind.BROWSER,
    Kind.APP,
    Kind.SCRAPER,
    Kind.CRAWLER,
    Kind.SPOOFED_BROWSER,
    Kind.AUTOMATION,
    Kind.UNKNOWN,
)
_RANK = {kind: i for i, kind in enumerate(_PRIORITY)}

DEFAULT_UNKNOWN_THRESHOLD = _S["unknown_threshold"]

# Positive "this is a machine" tells (tags). A would-be-unknown client carrying one
# is automation of an unidentified kind, not a true unknown -- characterisable even
# from a single request. Kept to tells that are definitional (a library UA, a
# self-declared bot, a headless engine) or behaviourally proven (re-fetching without
# ever caching) -- never mere absence of human signal. A datacenter origin is a
# further tell, handled separately (it isn't a tag the classifiers emit).
_AUTOMATION_TELLS = frozenset({"headless-browser", "lacks-cache", "generic-ua", "bot-ua"})


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
    wba: WbaResult | None = None,
    datacenter: bool = False,
    aggregate: bool = False,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
) -> Classification:
    """Aggregate ``signals`` into a primary kind plus secondary tags.

    ``keep_signals`` retains every contributing signal on the result for inspect
    mode's rationale. The ``analyze`` report never reads them, so it passes
    ``False`` to avoid holding a Signal (and its evidence strings) per client.

    ``aggregate`` marks a multi-client display fold, suppressing per-client
    cadence tags (see :func:`~agent_census.classify.tags.derive_tags`).

    ``wba`` is the Web Bot Auth verdict -- the cryptographic-identity channel,
    weighed alongside the network ``verification`` (phase 2 lets a definitive WBA
    verdict drive the impersonator decision; phase 1 only contributes its tag).
    """
    by_label: dict[Kind, float] = {}
    for signal in signals:
        # Round when aggregating: classifiers build confidence from 0.05-step
        # increments, and float error (0.3 + 0.15 == 0.44999999996) would otherwise
        # drop a sum that equals the threshold just below it -- misfiling a clear
        # client as UNKNOWN while it still displays as the rounded percentage.
        by_label[signal.kind] = max(
            by_label.get(signal.kind, 0.0), round(signal.confidence, _ROUND)
        )

    # A person rarely browses from hosting infrastructure, so nudge a datacenter
    # "browser" verdict down a little -- enough to tip a borderline one, not to
    # overrule a strongly-behaving real browser.
    if datacenter and Kind.BROWSER in by_label:
        by_label[Kind.BROWSER] = round(
            max(0.0, by_label[Kind.BROWSER] - _T["dc_browser_penalty"]), _ROUND
        )

    tag_ev = derive_tag_evidence(
        features, compliance, verification, wba, datacenter=datacenter, aggregate=aggregate
    )
    tags = set(tag_ev)
    stored = tuple(signals) if keep_signals else ()
    # Per-tag evidence is inspect-only detail, held on the same terms as signals.
    tag_evidence = tuple(tag_ev.items()) if keep_signals else ()

    # Impersonation is decisive: a client faking a declared identity is an
    # impersonator, whatever else it looks like. Web Bot Auth (cryptographic)
    # outranks the network channel here -- a valid signature clears it, a forged
    # one forces it.
    faking, why = impersonation(verification, wba, features)
    if faking:
        return Classification(
            primary=Kind.IMPERSONATOR,
            confidence=_T["impersonator_confidence"],
            tags=frozenset(tags),
            evidence=why,
            all_signals=stored,
            tag_evidence=tag_evidence,
        )

    if not by_label or max(by_label.values()) < unknown_threshold:
        return _below_threshold(
            features, tags, tag_evidence, tuple(signals), stored, datacenter, by_label
        )

    primary = _pick(by_label)
    if primary is Kind.FEED_READER and _fetches_non_feeds(features):
        tags.add("fetches-non-feeds")
        if keep_signals:
            tag_evidence += (
                ("fetches-non-feeds", "a feed reader that also requested non-feed resources"),
            )
    primary_signals = [s for s in signals if s.kind is primary]
    evidence = tuple(e for s in primary_signals for e in s.evidence)
    agent_name = next((s.agent_name for s in primary_signals if s.agent_name), None)
    return Classification(
        primary=primary,
        confidence=by_label[primary],
        tags=frozenset(tags),
        evidence=evidence,
        all_signals=stored,
        tag_evidence=tag_evidence,
        agent_name=agent_name,
    )


def _below_threshold(
    features: ClientFeatures,
    tags: set[str],
    tag_evidence: tuple[tuple[str, str], ...],
    signals: tuple[Signal, ...],
    stored: tuple[Signal, ...],
    datacenter: bool,
    by_label: dict[Kind, float],
) -> Classification:
    """Pick a fallback when no classifier cleared the bar, narrowing UNKNOWN where we can."""

    def verdict(primary: Kind, confidence: float, evidence: str) -> Classification:
        return Classification(
            primary=primary,
            confidence=confidence,
            tags=frozenset(tags),
            evidence=(evidence,),
            all_signals=stored,
            tag_evidence=tag_evidence,
        )

    # A browser UA from a hosting IP with no browser behaviour is automation in disguise.
    if datacenter and looks_like_fake_browser(features):
        return verdict(
            Kind.SPOOFED_BROWSER,
            _T["fallback_spoofed_browser"],
            "browser User-Agent from a datacenter IP, without browser behaviour",
        )
    # A generic HTTP library (or no UA) fetching several pages from hosting infrastructure
    # is harvesting content -- a scraper. The datacenter origin is what tips it.
    if datacenter and _looks_like_datacenter_scraper(features):
        return verdict(
            Kind.SCRAPER,
            _T["fallback_scraper"],
            "generic HTTP client harvesting pages from a datacenter IP",
        )
    # A positive machine tell with no purpose behind it: automation, kind
    # unidentified. A self-declared bot / library / headless engine names itself;
    # a hosting (datacenter) origin gives it away even on a single request -- a
    # person rarely browses from infrastructure. Either way it is not a true unknown.
    if tags & _AUTOMATION_TELLS:
        return verdict(
            Kind.AUTOMATION,
            _T["fallback_automation"],
            "a machine tell is present, but no purpose could be identified",
        )
    if datacenter:
        return verdict(
            Kind.AUTOMATION,
            _T["fallback_automation"],
            "from datacenter infrastructure, with no human signal",
        )
    confidence = max(by_label.values()) if by_label else 0.0
    return Classification(
        primary=Kind.UNKNOWN,
        confidence=confidence,
        tags=frozenset(tags),
        evidence=_top_evidence(signals),
        all_signals=stored,
        tag_evidence=tag_evidence,
    )


def _looks_like_datacenter_scraper(features: ClientFeatures) -> bool:
    """A generic-library / UA-less client harvesting several pages, benignly."""
    return (
        features.request_count >= _T["dc_scraper_min_requests"]
        and features.distinct_paths >= _T["dc_scraper_min_distinct"]
        and (uas.is_library(features.user_agent) or features.ua_empty)
        and features.vuln_path_hits == 0
        and features.traversal_hits == 0
        and features.evasion_hits == 0
    )


def _fetches_non_feeds(features: ClientFeatures) -> bool:
    """True if a feed reader also requested non-feed resources (robots.txt aside)."""
    non_feed = features.request_count - features.feed_requests
    if features.fetched_robots_txt:
        non_feed -= 1  # a polite robots.txt fetch does not count as content scraping
    return non_feed > 0
