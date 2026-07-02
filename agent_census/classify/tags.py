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

from typing import Literal

from .. import uas
from ..dataload import load_shared_tuning, load_tuning
from ..model import (
    BotVerification,
    ChannelVerdict,
    ClientFeatures,
    ComplianceReport,
    RobotsVerdict,
    VerificationStatus,
    WbaResult,
    WbaStatus,
)
from ..wba import operator_for_ua
from .feed_reader import ua_is_feed_reader

# Numeric knobs: the tags' own thresholds in data/tuning/tags.toml, and the ones
# shared with the classifiers (cadence bands, browser-shape cutoffs, notable-HEAD,
# fabricated referer, 404 storm) in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "ua_rotation_threshold": "ua_rotation.distinct_ua_min",
    "cadence_min_requests": "cadence.min_requests",
    "follows_min_requests": "link_following.min_requests",
    "probe_paths_min_hits": "probe_paths.min_hits",
    "probe_paths_min_ratio": "probe_paths.min_ratio",
    "post_heavy_ratio_min": "post_heavy.ratio_min",
    "post_heavy_min_requests": "post_heavy.min_requests",
    "fake_browser_min_requests": "fake_browser.min_requests",
}
_T = load_tuning("tags", _TUNING_SCHEMA)
_S = load_shared_tuning()

# Inter-arrival cadence tags: one is emitted from a single client's request timing.
# On a multi-client display aggregate (a privacy-relay / VPN egress fold that folds
# many independent users into one row) the interleaved arrivals carry no cadence, so
# these are suppressed there -- see ``ClientProfile.is_aggregate``.
CADENCE_TAGS = frozenset({"metronomic", "bursty", "steady"})

# Tags that record an incidental fact about *this batch's own requests* -- did they
# happen to hit /robots.txt, earn a 304, co-load a page's assets, follow on-site
# links, arrive as a single request, use HEAD/POST heavily, run long, or transfer/
# request at a high rate -- rather than the client's identity or conduct. Two IPs of
# the same verified crawler can differ on these purely because of which slice of its
# traffic each accumulator happened to observe, so the report-time actor grouping in
# ``report/aggregate.py`` excludes them from its folding key -- they'd otherwise
# split an already-identical actor into separate rows.
#
# ``long-session``/``high-rate``/``high-bytes``/``wide-breadth`` are defined in
# ``classify/relative.py`` (its ``_METRIC_TAGS``), not here -- same per-member
# magnitude shape as the rest, just literals rather than an import, since
# ``relative.py`` already imports from this module and the reverse would cycle.
OBSERVATIONAL_TAGS = (
    frozenset(
        {
            "checked-robots",
            "has-cache",
            "lacks-cache",
            "loads-assets",
            "no-assets",
            "follows-links",
            "cold",
            "singleton",
            "uses-HEAD",
            "post-heavy",
            "long-session",
            "high-rate",
            "high-bytes",
            "wide-breadth",
        }
    )
    | CADENCE_TAGS
)

# Observational tags worth showing on a folded row -- all of them except
# ``singleton``, unioned across members: has-cache/lacks-cache and the cadence trio
# are mutually exclusive per profile (``if``/``elif`` in this module), so both poles
# appearing together can only mean the members disagree -- a true, informative fact
# about the group ("some members cache, some don't"), not a contradiction to hide.
# ``singleton`` is excluded outright instead: it's a volume claim ("made exactly one
# request") that's false of the merged actor the moment >1 member is folded
# together, regardless of whether every member individually satisfies it.
OBSERVATIONAL_DISPLAY_TAGS = OBSERVATIONAL_TAGS - {"singleton"}

# Browser fingerprint thresholds, shared with the relative-tag reference predicate
# (``classify.relative.is_reference_browser``) so "what counts as browser-like" is
# defined once. A real browser co-loads a page's sub-resources and follows on-site
# links; these are the lower bounds the ``loads-assets`` / ``follows-links`` tags
# use, read from data/tuning/shared.toml.
BROWSER_COLOAD_MIN = _S["browser_coload_min"]  # asset_coload_ratio -> "loads-assets"
BROWSER_FOLLOW_MIN = _S["browser_follow_min"]  # referer_following_ratio -> "follows-links"


def _declares_known_crawler(features: ClientFeatures) -> bool:
    return uas.names_known_crawler(features.user_agent)


def impersonation(
    verification: BotVerification | None,
    wba: WbaResult | None = None,
    features: ClientFeatures | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Decide whether the client is impersonating a declared identity.

    Impersonation is a forged *identity*. Two channels feed the verdict, with the
    cryptographic one (Web Bot Auth) outranking the network one (reverse DNS / IP
    range / AS number):

    * A Web Bot Auth signature that *fails* against the operator's authentic key is
      forgery, whatever the network channel says.
    * A *valid* signature is cryptographic proof of identity: it clears a network
      impersonator verdict -- unless the User-Agent names a *different* registered
      operator than the one that actually signed (claiming to be one operator while
      validly signed by another is itself a forged identity).
    * Only when Web Bot Auth gives no definitive verdict (absent, present-only, or
      unverifiable) does the network channel decide, as before.

    Misbehaviour such as ignoring robots.txt or probing is tagged, not treated as
    identity theft -- a real crawler can still behave badly.
    """
    if wba is not None:
        if wba.status is WbaStatus.FORGED:
            return True, wba.evidence or (
                "Web Bot Auth signature failed against the operator's key",
            )
        if wba.status in (WbaStatus.VERIFIED, WbaStatus.EXPIRED):
            claimed = operator_for_ua(features.user_agent if features is not None else None)
            if claimed is not None and wba.operator is not None and claimed != wba.operator:
                return True, (
                    f"User-Agent claims {claimed}, but the request is validly signed by "
                    f"{wba.operator} -- a forged identity",
                )
            return False, ()  # cryptographically confirmed; outranks the network channel
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
        and features.request_count >= _T["fake_browser_min_requests"]
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
    metronomic_max = _S["cadence_metronomic_max"]
    bursty_min = _S["cadence_bursty_min"]
    if not aggregate and reg is not None and count >= _T["cadence_min_requests"]:
        if reg < metronomic_max:
            tags["metronomic"] = (
                f"inter-arrival CV {reg:.2f} < {metronomic_max:g} over {count:,} requests"
            )
        elif reg > bursty_min:
            tags["bursty"] = f"inter-arrival CV {reg:.2f} > {bursty_min:g} over {count:,} requests"
        else:
            tags["steady"] = (
                f"inter-arrival CV {reg:.2f} ({metronomic_max:g}–{bursty_min:g}) "
                f"over {count:,} requests"
            )

    # Sub-resource loading: a browser pulls a page's CSS/JS/images. Only judgeable
    # when the client actually fetched HTML pages.
    if features.page_count > 0:
        ratio = features.asset_coload_ratio
        if ratio > BROWSER_COLOAD_MIN:
            tags["loads-assets"] = (
                f"co-loaded sub-resources after {ratio:.0%} of {features.page_count:,} "
                f"HTML page(s) (> {BROWSER_COLOAD_MIN:.0%})"
            )
        elif ratio < _S["browser_no_coload_max"]:
            tags["no-assets"] = (
                f"co-loaded sub-resources after only {ratio:.0%} of {features.page_count:,} "
                f"HTML page(s) (< {_S['browser_no_coload_max']:.0%})"
            )

    # Navigation: following on-site links (referer is a path fetched earlier).
    # Only judgeable when some request carried a Referer at all.
    if features.referer_count > 0 and count >= _T["follows_min_requests"]:
        ratio = features.referer_following_ratio
        if ratio > BROWSER_FOLLOW_MIN:
            tags["follows-links"] = (
                f"{ratio:.0%} of requests had an on-site Referer (> {BROWSER_FOLLOW_MIN:.0%}); "
                f"{features.referer_count:,} carried one"
            )
        elif ratio < _S["browser_no_follow_max"]:
            tags["cold"] = (
                f"only {ratio:.0%} of requests followed an on-site Referer "
                f"(< {_S['browser_no_follow_max']:.0%}); {features.referer_count:,} carried one"
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
        # holds_no_cache fires on re-fetches-without-304s or sheer volume-without-304s,
        # so lead with the 304 fact -- it reads right even when re-fetches are 0.
        tags["lacks-cache"] = (
            f"never a 304 across {count:,} requests "
            f"({count - features.distinct_paths:,} re-fetched)"
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
    if (
        features.vuln_path_hits >= _T["probe_paths_min_hits"]
        or features.vuln_path_ratio >= _T["probe_paths_min_ratio"]
    ):
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
    if (
        features.ratio_404 > _S["storm_404_ratio_min"]
        and features.distinct_404_paths >= _S["storm_404_distinct_paths_min"]
    ):
        tags["404-storm"] = (
            f"{features.ratio_404:.0%} 404s across {features.distinct_404_paths:,} distinct paths"
        )
    if features.exotic_method_count > 0:
        # PUT/DELETE/PROPFIND/CONNECT … — scanners, WebDAV probes
        tags["exotic-method"] = (
            f"{features.exotic_method_count:,} request(s) using uncommon methods "
            "(PUT/DELETE/PROPFIND/CONNECT…)"
        )
    if features.head_ratio > _S["head_notable_ratio"]:
        tags["uses-HEAD"] = (
            f"HEAD is {features.head_ratio:.0%} of requests (> {_S['head_notable_ratio']:.0%})"
        )
    if features.post_ratio > _T["post_heavy_ratio_min"] and (
        features.request_count >= _T["post_heavy_min_requests"]
    ):
        tags["post-heavy"] = (
            f"POST is {features.post_ratio:.0%} of {features.request_count:,} requests "
            f"(> {_T['post_heavy_ratio_min']:.0%})"
        )
    if (
        features.self_referer_ratio >= _S["fabricated_self_referer_min"]
        and features.request_count >= _S["fabricated_min_requests"]
        # Only meaningful for a client posing as a browser: a fabricated Referer.
        and features.ua_looks_like_browser
        and not identifies_as_known_agent(features)
    ):
        tags["forged-referer"] = (
            f"Referer equals the requested URL on {features.self_referer_ratio:.0%} of requests "
            "— fabricated navigation"
        )
    return tags


# The phase-1 WBA states map to one tag each; the verification tier (phase 2) adds
# the verified/expired/unverified/violation states. `wba-violation` (FORGED) is
# additional detail alongside the `impersonator` kind it also drives -- it names
# *which* channel caught the forgery, since dns/ip/wba can each independently
# verify or violate on the same client.
_WBA_TAGS: dict[WbaStatus, str] = {
    WbaStatus.PRESENT: "wba",
    WbaStatus.VERIFIED: "wba-verified",
    WbaStatus.EXPIRED: "wba-expired",
    WbaStatus.UNVERIFIABLE: "wba-unverified",
    WbaStatus.FORGED: "wba-violation",
}
_WBA_TAG_DEFAULT: dict[str, str] = {
    "wba": "presented a Web Bot Auth signature (not yet cryptographically verified)",
    "wba-verified": "a valid, fresh Web Bot Auth signature confirmed the operator",
    "wba-expired": "a valid Web Bot Auth signature, but past its expiry at request time",
    "wba-unverified": "presented a Web Bot Auth signature that couldn't be checked",
    "wba-violation": "Web Bot Auth signature failed against the operator's authentic key",
}


def _wba_tag(wba: WbaResult | None) -> dict[str, str]:
    """The Web Bot Auth tags: one mutually-exclusive status tag, plus orthogonal
    flags for a mixed identity and nonce replay/reuse.

    The status is a single tag -- no stacking. ``NOT_APPLICABLE`` means no
    signature, so nothing to tag. ``mixed`` / ``replayed`` / ``nonce_reused``
    are independent dimensions layered on top when present.
    """
    if wba is None:
        return {}
    tags: dict[str, str] = {}
    status_tag = _WBA_TAGS.get(wba.status)
    if status_tag is not None:
        tags[status_tag] = (
            wba.reason
            or (wba.evidence[0] if wba.evidence else None)
            or _WBA_TAG_DEFAULT[status_tag]
        )
    if wba.mixed:
        tags["wba-mixed"] = (
            "a sample of this client's signed requests disagreed -- some signatures "
            "verified, some did not"
        )
    if wba.replayed:
        tags["wba-replay"] = (
            "a signature nonce from this client also appeared from a different origin "
            "-- a captured signature replayed"
        )
    elif wba.nonce_reused:
        tags["wba-nonce-reuse"] = (
            "this client reused a signature nonce across its own requests "
            "(a signer reusing nonces, not a replay)"
        )
    return tags


# The default evidence text per channel/verdict, used only when the channel
# didn't supply its own (it always does in practice; this is a fallback so the
# tag is never left without a reason). `NOT_CHECKED` emits no tag at all --
# absence (nothing declared for this channel, or a fallback that skipped it) is
# never read as a signal.
_CHANNEL_NAMES = {"dns": "reverse/forward DNS", "ip": "the published IP ranges"}
_CHANNEL_DEFAULT: dict[ChannelVerdict, str] = {
    ChannelVerdict.VERIFIED: "confirmed the declared crawler",
    ChannelVerdict.UNVERIFIED: "was inconclusive (a timeout, or unfetchable data)",
    ChannelVerdict.VIOLATION: "did not confirm the declared crawler",
}


def _channel_tags(
    channel: Literal["dns", "ip"], verdict: ChannelVerdict, evidence: str | None
) -> dict[str, str]:
    """The `<channel>-verified` / `<channel>-unverified` / `<channel>-violation` tag
    for one independent identity channel, or nothing when it was never checked.

    `dns` and `ip` are surfaced separately (rather than one merged network tag) so
    a reader can see which specific channel confirmed or disagreed -- an agent
    declaring both can have one verify while the other doesn't.
    """
    if verdict is ChannelVerdict.NOT_CHECKED:
        return {}
    why = evidence or f"{_CHANNEL_NAMES[channel]} {_CHANNEL_DEFAULT[verdict]}"
    return {f"{channel}-{verdict.value}": why}


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
    if verification is not None:
        tags.update(_channel_tags("dns", verification.dns, verification.dns_evidence))
        tags.update(_channel_tags("ip", verification.ip, verification.ip_evidence))
    if verification is not None and verification.status is VerificationStatus.ASN_ASSOCIATED:
        # UA names a crawler and its origin AS is one that crawler uses -- corroborated.
        tags["asn-associated"] = (
            verification.evidence[0]
            if verification.evidence
            else "User-Agent names a known crawler and its origin AS is one that crawler uses"
        )
    if _declares_known_crawler(features):
        tags["declares-known-bot"] = "User-Agent names a known crawler"
    if ua_is_feed_reader(features.user_agent):
        tags["fetches-feeds"] = "User-Agent names a feed reader or generic feed tool"
    app_token = uas.app_stack_token(features.user_agent)
    if app_token is not None:
        tags["declares-app-client"] = (
            f"User-Agent names a native-app networking stack ({app_token})"
        )
    if uas.names_user_triggered_agent(features.user_agent):
        tags["user-triggered"] = (
            "User-Agent names a fetcher the operator designates as acting on behalf "
            "of a present user, not an autonomous crawler"
        )
    # Only the actionable robots case is tagged; respecting it is the quiet norm.
    if compliance is not None and compliance.verdict is RobotsVerdict.IGNORES:
        why = (
            f"requested {compliance.disallowed_hits:,} path(s) disallowed by the "
            "applicable robots.txt group"
        )
        if compliance.sample_disallowed:
            why += f"; e.g. {', '.join(compliance.sample_disallowed[:3])}"
        tags["ignores-robots"] = why
    if features.ua_count_for_ip >= _T["ua_rotation_threshold"]:
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
    wba: WbaResult | None = None,
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
    evidence.update(_wba_tag(wba))
    return evidence


def derive_tags(
    features: ClientFeatures,
    compliance: ComplianceReport | None,
    verification: BotVerification | None,
    wba: WbaResult | None = None,
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
            features, compliance, verification, wba, datacenter=datacenter, aggregate=aggregate
        )
    )
