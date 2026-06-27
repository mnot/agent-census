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
from ..model import (
    BotVerification,
    ClientFeatures,
    ComplianceReport,
    RobotsVerdict,
    VerificationStatus,
)
from .feed_reader import ua_is_feed_reader

_UA_ROTATION_THRESHOLD = 4

# Inter-arrival cadence tags: one is emitted from a single client's request timing.
# On a multi-client display aggregate (a privacy-relay / VPN egress fold that folds
# many independent users into one row) the interleaved arrivals carry no cadence, so
# these are suppressed there -- see ``ClientProfile.is_aggregate``.
CADENCE_TAGS = frozenset({"metronomic", "bursty", "steady"})

# Browser fingerprint thresholds, shared with the relative-tag reference predicate
# (``classify.relative.is_reference_browser``) so "what counts as browser-like" is
# defined once. A real browser co-loads a page's sub-resources and follows on-site
# links; these are the lower bounds the ``loads-assets`` / ``follows-links`` tags use.
BROWSER_COLOAD_MIN = 0.4  # asset_coload_ratio at/above which a client "loads-assets"
BROWSER_FOLLOW_MIN = 0.3  # referer_following_ratio at/above which it "follows-links"


def _declares_known_crawler(features: ClientFeatures) -> bool:
    return uas.names_known_crawler(features.user_agent)


def impersonation(verification: BotVerification | None) -> tuple[bool, tuple[str, ...]]:
    """Decide whether the client is impersonating a declared identity.

    Impersonation is a forged *identity*: a verification verdict that the origin
    isn't really that crawler -- its reverse DNS, IP range, or AS number disagrees.
    Misbehaviour such as ignoring robots.txt or probing for vulnerabilities is
    tagged, not treated as identity theft -- a real crawler can still behave badly.
    """
    if verification is not None and verification.status is VerificationStatus.IMPERSONATOR:
        return True, verification.evidence or (
            "origin does not confirm the declared crawler (DNS / IP range / AS)",
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
    return features.ua_declares_bot or recognised_specific_agent(features)


def recognised_specific_agent(features: ClientFeatures) -> bool:
    """A *positively identified* agent: a known crawler (by UA token or origin AS),
    or a feed reader. Unlike :func:`identifies_as_known_agent` this excludes a bare
    self-declared bot -- one that says it's a bot but names no specific identity.

    The generic ``crawler`` / ``scraper`` classifiers defer to such an agent: it has
    a specific classifier of its own, whose verdict a behavioural score must not
    outrank (a recognised crawler that also crawls broadly is not a generic crawler).
    """
    return (
        uas.names_known_crawler(features.user_agent)
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


def _fingerprint_tags(features: ClientFeatures, aggregate: bool) -> dict[str, str]:
    """The behavioural fingerprint: one tag per dimension we can actually measure.

    Each dimension emits its observed value (a polar pair, or a gradation) only
    when there is enough data to judge it -- so an absent tag means "couldn't
    tell", never a silent "no". This is the evidence a reader weighs themselves.

    Each tag maps to the concrete measurement that earned it, so inspect mode can
    show *why* it fired (not just that it did) -- see :func:`derive_tag_evidence`.

    ``aggregate`` marks a multi-client display fold (a privacy-relay / VPN row):
    its cadence is suppressed because interleaved users have no shared timing. The
    other dimensions (asset co-load, link-following, caching, UA shape) are
    per-request or per-UA ratios that survive folding, so they still apply.
    """
    tags: dict[str, str] = {}
    count = features.request_count

    # Cadence: how regular the inter-arrival timing is (clockwork vs. human).
    # Meaningless once many independent clients are interleaved into one row.
    reg = features.rate_regularity
    if not aggregate and reg is not None and count >= 5:
        if reg < 0.15:
            tags["metronomic"] = f"inter-arrival CV {reg:.2f} < 0.15 over {count:,} requests"
        elif reg > 0.6:
            tags["bursty"] = f"inter-arrival CV {reg:.2f} > 0.6 over {count:,} requests"
        else:
            tags["steady"] = f"inter-arrival CV {reg:.2f} (0.15–0.6) over {count:,} requests"

    # Sub-resource loading: a browser pulls a page's CSS/JS/images. Only judgeable
    # when the client actually fetched HTML pages.
    if features.page_count > 0:
        ratio = features.asset_coload_ratio
        if ratio > BROWSER_COLOAD_MIN:
            tags["loads-assets"] = (
                f"co-loaded sub-resources after {ratio:.0%} of {features.page_count:,} "
                f"HTML page(s) (> {BROWSER_COLOAD_MIN:.0%})"
            )
        elif ratio < 0.1:
            tags["no-assets"] = (
                f"co-loaded sub-resources after only {ratio:.0%} of {features.page_count:,} "
                "HTML page(s) (< 10%)"
            )

    # Navigation: following on-site links (referer is a path fetched earlier).
    # Only judgeable when some request carried a Referer at all.
    if features.referer_count > 0 and count >= 4:
        ratio = features.referer_following_ratio
        if ratio > BROWSER_FOLLOW_MIN:
            tags["follows-links"] = (
                f"{ratio:.0%} of requests had an on-site Referer (> {BROWSER_FOLLOW_MIN:.0%}); "
                f"{features.referer_count:,} carried one"
            )
        elif ratio < 0.1:
            tags["cold"] = (
                f"only {ratio:.0%} of requests followed an on-site Referer (< 10%); "
                f"{features.referer_count:,} carried one"
            )

    # Caching: a 304 proves a real cache. Its absence alone is content/server-
    # dependent, but re-fetching the same URLs (or high volume) without ever
    # earning a 304 does prove no cache -- see ClientFeatures.holds_no_cache.
    if features.status_counts.get(304, 0) > 0:
        tags["has-cache"] = (
            f"received {features.status_counts[304]:,} 304 Not Modified response(s) — "
            "makes conditional requests"
        )
    elif features.holds_no_cache:
        tags["lacks-cache"] = (
            f"{count - features.distinct_paths:,} re-fetches across {count:,} requests, no 304s"
        )

    # A headless / automation-driven browser engine: renders (so it can load
    # assets) but the UA names the harness. A machine tell regardless of behaviour.
    if uas.is_headless(features.user_agent):
        tags["headless-browser"] = "User-Agent names a headless / automation browser engine"

    # User-Agent shape, when one is present -- one mutually-exclusive tag. For a
    # browser the version age is folded in (current/stale/ancient-browser-ua);
    # plain browser-ua means a browser shell whose version we couldn't read.
    # Otherwise a generic HTTP library, or a self-declared bot we *don't*
    # recognise (a recognised crawler is the declares-known-bot fact instead).
    if not features.ua_empty:
        band = uas.version_age_band(features.user_agent, features.last_seen)
        if band is not None:
            tags[f"{band}-browser-ua"] = (
                f"browser User-Agent version reads as '{band}' for its active period"
            )
        elif features.ua_looks_like_browser:
            tags["browser-ua"] = (
                "User-Agent matches a browser profile (Mozilla + a layout engine), "
                "but carries no readable version to age"
            )
        elif uas.is_library(features.user_agent):
            tags["generic-ua"] = "User-Agent is a generic HTTP library / tool, not a named agent"
        elif (
            features.ua_declares_bot
            and not _declares_known_crawler(features)
            and not ua_is_feed_reader(features.user_agent)
        ):
            # A self-declared bot we don't recognise -- but a feed reader names
            # itself a feed tool, not a generic bot, so it's never "bot-ua".
            tags["bot-ua"] = "User-Agent self-declares a bot, but not one we recognise"

    return tags


def _conduct_tags(features: ClientFeatures) -> dict[str, str]:
    """Noteworthy behaviour, flagged only when present (no negative pole)."""
    tags: dict[str, str] = {}
    # Hostile request shapes, split by what was actually seen. Probe-path hits are
    # gated (a raw burst, or a meaningful share of traffic) so a broad crawler that
    # grazes a few attack-shaped URLs over tens of thousands of requests isn't
    # mistaken for a scan. Traversal / injection and encoding-evasion markers have
    # no legitimate use, so a single one is enough.
    if features.vuln_path_hits >= 3 or features.vuln_path_ratio >= 0.05:
        why = (
            f"{features.vuln_path_hits:,} known-probe path hit(s) "
            f"({features.vuln_path_ratio:.0%} of traffic)"
        )
        if features.sample_vuln_paths:
            why += f"; e.g. {', '.join(features.sample_vuln_paths[:3])}"
        tags["probe-paths"] = why
    if features.traversal_hits > 0:
        tags["traversal"] = (
            f"{features.traversal_hits:,} path-traversal / injection marker(s) in request paths"
        )
    if features.evasion_hits > 0:
        tags["encoding-evasion"] = (
            f"{features.evasion_hits:,} double / overlong percent-encoded request(s)"
        )
    if features.ratio_404 > 0.6 and features.distinct_404_paths >= 15:
        tags["404-storm"] = (
            f"{features.ratio_404:.0%} 404s across {features.distinct_404_paths:,} distinct paths"
        )
    if features.exotic_method_count > 0:
        # PUT/DELETE/PROPFIND/CONNECT … — scanners, WebDAV probes
        tags["exotic-method"] = (
            f"{features.exotic_method_count:,} request(s) using uncommon methods "
            "(PUT/DELETE/PROPFIND/CONNECT…)"
        )
    if features.head_ratio > 0.1:
        tags["uses-HEAD"] = f"HEAD is {features.head_ratio:.0%} of requests (> 10%)"
    if features.post_ratio > 0.5 and features.request_count >= 5:
        tags["post-heavy"] = (
            f"POST is {features.post_ratio:.0%} of {features.request_count:,} requests (> 50%)"
        )
    if (
        features.self_referer_ratio >= 0.5
        and features.request_count >= 4
        # Only meaningful for a client posing as a browser: a fabricated Referer.
        and features.ua_looks_like_browser
        and not identifies_as_known_agent(features)
    ):
        tags["forged-referer"] = (
            f"Referer equals the requested URL on {features.self_referer_ratio:.0%} of requests "
            "— fabricated navigation"
        )
    return tags


def _fact_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    datacenter: bool,
) -> dict[str, str]:
    """Established facts about the client's identity and origin (no behaviour)."""
    tags: dict[str, str] = {}
    if features.request_count == 1:
        tags["singleton"] = "made exactly one request"  # a volume fact, any kind
    if datacenter:
        why = "origin is hosting / datacenter infrastructure"
        if features.as_org:
            why += f" ({features.as_org})"
        tags["datacenter"] = why
    if features.ua_empty:
        tags["no-user-agent"] = "sent no User-Agent header"
    if features.fetched_robots_txt:
        tags["checked-robots"] = "requested /robots.txt at some point"
    if uas.match_asn_any(features.as_number):
        # identity *is* the origin AS, not the User-Agent
        tags["asn-attributed"] = (
            f"origin AS {features.as_number or '–'} is a recognised crawler network"
        )
    if verification is not None and verification.status is VerificationStatus.VERIFIED:
        tags["verified"] = (
            verification.evidence[0]
            if verification.evidence
            else "reverse/forward DNS or a published IP range confirmed the declared crawler"
        )
    if verification is not None and verification.status is VerificationStatus.ASN_ASSOCIATED:
        # UA names a crawler and its origin AS is one that crawler uses -- corroborated.
        tags["asn-associated"] = (
            verification.evidence[0]
            if verification.evidence
            else "User-Agent names a known crawler and its origin AS is one that crawler uses"
        )
    if (
        verification is not None
        and verification.network_checked
        and verification.status in (VerificationStatus.IMPERSONATOR, VerificationStatus.UNVERIFIED)
    ):
        # Had rdns/range info to check the declared identity against, but it failed
        # or was inconclusive -- the mirror of `verified`. Always surfaced so a
        # not-confirmed declared crawler is visible; the kind/verdict are unchanged.
        tags["unverified"] = (
            verification.evidence[0]
            if verification.evidence
            else "declared a crawler we could check, but DNS / IP range didn't confirm it"
        )
    if _declares_known_crawler(features):
        tags["declares-known-bot"] = "User-Agent names a known crawler"
    # Only the actionable robots case is tagged; respecting it is the quiet norm.
    if compliance is not None and compliance.verdict is RobotsVerdict.IGNORES:
        why = (
            f"requested {compliance.disallowed_hits:,} path(s) disallowed by the "
            "applicable robots.txt group"
        )
        if compliance.sample_disallowed:
            why += f"; e.g. {', '.join(compliance.sample_disallowed[:3])}"
        tags["ignores-robots"] = why
    if features.ua_count_for_ip >= _UA_ROTATION_THRESHOLD:
        # Many UAs on one IP: evasive rotation from a hosting IP or a browser
        # costume; otherwise a benign shared egress (NAT / VPN / proxy / carrier).
        if datacenter or looks_like_fake_browser(features):
            tags["ua-rotating"] = (
                f"{features.ua_count_for_ip:,} distinct User-Agents on one IP, with a "
                "hosting origin or non-browser behaviour"
            )
        else:
            tags["shared-ip"] = (
                f"{features.ua_count_for_ip:,} distinct User-Agents on one IP, behaving "
                "normally — a shared egress (NAT / VPN / proxy / carrier)"
            )
    return tags


def derive_tag_evidence(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    *,
    datacenter: bool = False,
    aggregate: bool = False,
) -> dict[str, str]:
    """The client's tags paired with the concrete measurement that earned each.

    The single source for both the tag set (:func:`derive_tags` is ``set()`` of the
    keys) and inspect mode's per-tag rationale, so a tag and its evidence can never
    drift apart -- the line that decides a tag writes its reason.
    """
    evidence: dict[str, str] = {}
    evidence.update(_fingerprint_tags(features, aggregate))
    evidence.update(_conduct_tags(features))
    evidence.update(_fact_tags(features, compliance, verification, datacenter))
    return evidence


def derive_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    *,
    datacenter: bool = False,
    aggregate: bool = False,
) -> set[str]:
    """The client's tags: a measured behavioural fingerprint, conduct flags, and facts.

    ``aggregate`` marks a multi-client display fold, suppressing the per-client
    cadence tags (see :func:`_fingerprint_tags`).
    """
    return set(
        derive_tag_evidence(
            features, compliance, verification, datacenter=datacenter, aggregate=aggregate
        )
    )
