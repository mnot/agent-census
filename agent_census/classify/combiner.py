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
from .tags import derive_tag_evidence, impersonation

# Numeric knobs: this module's own in data/tuning/combiner.toml, the unknown
# threshold in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "round_digits": "round_digits",
    "dc_browser_penalty": "datacenter.browser_penalty",
    "dc_scraper_min_requests": "datacenter.scraper_min_requests",
    "dc_scraper_min_distinct": "datacenter.scraper_min_distinct_paths",
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


def _top_evidence(signals: tuple[Signal, ...]) -> tuple[tuple[str, ...], bool]:
    """The strongest (even if losing) signal's evidence, paired with whether its
    lead entry is boilerplate -- carried through so a below-threshold known-agent
    or app match still gets its identity declaration skipped as a caption."""
    if not signals:
        return (("no classifier produced a signal",), False)
    strongest = max(signals, key=lambda s: s.confidence)
    return strongest.evidence or ("no specific evidence recorded",), strongest.boilerplate_lead


def combine(
    signals: list[Signal],
    features: ClientFeatures,
    *,
    compliance: ComplianceReport | None = None,
    verification: BotVerification | None = None,
    wba: WbaResult | None = None,
    datacenter: bool = False,
    aggregate: bool = False,
    redirect_shadow: str | None = None,
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

    # "Spoofed browser" and "browser" are one claim with opposite verdicts. The spoof
    # classifier fires only on genuine costume / forgery tells that a real browser never
    # trips (impossible-referer, HEAD-heavy, no cache at volume, fabricated referers),
    # so once it fires it has settled the browser question -- drop the browser vote so a
    # sophisticated costume that also fakes browser-shaped behaviour (co-loading assets
    # while replaying an impossible Referer) isn't out-competed by the very
    # browser-ness it is faking. This is the accumulation-model successor to the two
    # combiner special-cases #101 used (see issue #100); every other kind still competes
    # with spoofed_browser on confidence as normal.
    if Kind.SPOOFED_BROWSER in by_label:
        by_label.pop(Kind.BROWSER, None)

    # A client that probes attack paths is a vuln_scanner, whatever costume it wears: the
    # hostile activity is a more actionable, specific verdict than the disguise. So once
    # vuln_scanner clears the bar it takes precedence over spoofed_browser, whose accumulated
    # costume score can otherwise out-confidence it (a datacenter no-cache costume scores
    # 0.9 while its probing scores 0.7, so the scan would read as a mere costume). The
    # behavioural costume tags still show on the row -- only the primary verdict changes.
    if Kind.VULN_SCANNER in by_label and by_label[Kind.VULN_SCANNER] >= unknown_threshold:
        by_label.pop(Kind.SPOOFED_BROWSER, None)

    tag_ev = derive_tag_evidence(
        features,
        compliance,
        verification,
        wba,
        datacenter=datacenter,
        aggregate=aggregate,
        redirect_shadow=redirect_shadow,
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
    boilerplate_lead = primary_signals[0].boilerplate_lead if primary_signals else False
    return Classification(
        primary=primary,
        confidence=by_label[primary],
        tags=frozenset(tags),
        evidence=evidence,
        all_signals=stored,
        tag_evidence=tag_evidence,
        agent_name=agent_name,
        boilerplate_lead=boilerplate_lead,
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
    """Pick a fallback when no classifier cleared the bar, narrowing UNKNOWN where we can.

    Note the browser-costume case does *not* live here any more: it is a first-class
    verdict now, produced by the ``SpoofedBrowserClassifier`` as a scored signal that
    competes in normal aggregation (see issue #100). A capped or under-threshold browser
    costume therefore arrives here only when the spoof score did not clear the bar, and
    falls through to the automation / unknown rungs below like any other weak client.
    """

    def verdict(primary: Kind, confidence: float, evidence: str) -> Classification:
        # Every call below passes the one fixed sentence that *is* the fallback
        # rule -- restating why it's this kind, not a fact specific to the client
        # -- so it's boilerplate by construction (see Signal.boilerplate_lead).
        return Classification(
            primary=primary,
            confidence=confidence,
            tags=frozenset(tags),
            evidence=(evidence,),
            all_signals=stored,
            tag_evidence=tag_evidence,
            boilerplate_lead=True,
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
    evidence, boilerplate_lead = _top_evidence(signals)
    return Classification(
        primary=Kind.UNKNOWN,
        confidence=confidence,
        tags=frozenset(tags),
        evidence=evidence,
        all_signals=stored,
        tag_evidence=tag_evidence,
        boilerplate_lead=boilerplate_lead,
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
