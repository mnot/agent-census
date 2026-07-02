"""Small formatting helpers shared by the report and inspect renderers."""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache

from ..dataload import load_egress_networks
from ..model import ChannelVerdict, ClientFeatures, ClientProfile, Kind, WbaStatus

_KHTML_MARKER = "(khtml, like gecko)"
# Layout-engine tokens: their presence in a trimmed preamble means the UA wore a
# real browser costume (worth flagging) rather than plain Mozilla boilerplate.
_ENGINE_RE = re.compile(r"applewebkit|gecko|khtml|trident|presto", re.I)


def elide_ua(ua: str | None, *, is_browser: bool = False) -> str | None:
    """Trim a bot UA's ``Mozilla/...`` boilerplate down to its agent token.

    Two preambles are handled:

    - ``Mozilla/5.0 (compatible; Googlebot/2.1; +url)`` -> ``… Googlebot/2.1; +url``
    - ``...AppleWebKit/605 (KHTML, like Gecko) NetNewsWire/6`` -> ``[browser] NetNewsWire/6``

    The second covers macOS/iOS agents (feed readers, etc.) that wear a Safari
    prefix with their product appended -- the bit that actually identifies them.
    A leading marker shows a preamble was trimmed: ``[browser]`` when the elided
    shell carried a real layout engine (a browser costume), else ``…``. Left
    untouched for browsers (whose preamble is meaningful) and for UAs with
    neither marker.
    """
    if not ua or is_browser:
        return ua
    pos = ua.lower().find("compatible;")
    if pos != -1:
        rest = ua[pos + len("compatible;") :].strip()
        if rest.endswith(")"):  # drop the now-orphaned closing paren of the preamble
            rest = rest[:-1].rstrip()
        if not rest:
            return ua
        marker = "[browser]" if _ENGINE_RE.search(ua[:pos]) else "…"
        return f"{marker} {rest}"
    pos = ua.lower().find(_KHTML_MARKER)
    if pos != -1:
        rest = ua[pos + len(_KHTML_MARKER) :].strip()
        return f"[browser] {rest}" if rest else ua
    return ua


def top_evidence(profile: ClientProfile) -> str:
    """The single most salient *extra* fact about a client -- something its
    identity, tags, and other columns on the same row don't already say.

    Verification evidence is never used here: whether merged ("N IP(s)
    verified as X") or per-IP ("A ↔ B confirmed for X"), it only restates the
    identity already headlining the row and the dns-verified / ip-verified
    tag already carrying that channel's own description. Classification
    evidence is preferred, but when a classifier set ``agent_name`` (only
    :mod:`classify.known_bot`, for both its UA and ASN matches) its own
    leading evidence line is that same declaration by construction, so it's
    skipped in favour of whatever supporting fact follows it, if any.
    """
    evidence = profile.classification.evidence
    if profile.classification.agent_name and evidence:
        evidence = evidence[1:]
    return evidence[0] if evidence else "–"


def as_label(org: str, number: str | None = None) -> str:
    """Format an AS org (+ optional number) like ``Amazon.com, Inc. (AS16509)``."""
    if not number:
        return org
    num = number[2:] if number[:2].upper() == "AS" else number
    return f"{org} (AS{num})"


# Tag display order: the behavioural fingerprint first (grouped by dimension and
# read left-to-right), then conduct flags, then established facts. Tags outside
# this list (egress networks, etc.) sort to the end alphabetically.
_TAG_ORDER = {
    tag: i
    for i, tag in enumerate(
        (
            "current-browser-ua",
            "stale-browser-ua",
            "ancient-browser-ua",
            "browser-ua",
            "generic-ua",
            "bot-ua",
            "bursty",
            "steady",
            "metronomic",
            "loads-assets",
            "no-assets",
            "follows-links",
            "cold",
            "has-cache",
            "probe-paths",
            "traversal",
            "encoding-evasion",
            "404-storm",
            "exotic-method",
            "uses-HEAD",
            "post-heavy",
            "forged-referer",
            "datacenter",
            "asn-attributed",
            "wba-verified",
            "wba-expired",
            "wba",
            "wba-unverified",
            "wba-violation",
            "wba-mixed",
            "wba-replay",
            "wba-nonce-reuse",
            "dns-verified",
            "ip-verified",
            "asn-associated",
            "dns-violation",
            "ip-violation",
            "dns-unverified",
            "ip-unverified",
            "declares-known-bot",
            "declares-app-client",
            "fetches-feeds",
            "user-triggered",
            "no-user-agent",
            "checked-robots",
            "ignores-robots",
            "ua-rotating",
            "shared-ip",
        )
    )
}


def ordered_tags(tags: frozenset[str] | set[str]) -> list[str]:
    """Tags in fingerprint → conduct → fact reading order; unknowns trail, sorted."""
    return sorted(tags, key=lambda t: (_TAG_ORDER.get(t, len(_TAG_ORDER)), t))


# Hover descriptions for the tags (rendered as a native title= tooltip in HTML, and
# the fallback rationale in inspect when a tag carries no per-client evidence). Egress
# network tags are described from the data file, so new networks get descriptions
# without touching this table.
_TAG_HELP: dict[str, str] = {
    "datacenter": "Source IP is in a known datacenter / cloud hosting range, "
    "not a consumer or ISP network.",
    "bursty": "Irregular, bursty request timing — human-like, not clockwork.",
    "steady": "Moderately regular request timing.",
    "loads-assets": "After fetching pages it pulled their sub-resources (CSS/JS/images) — "
    "the browser fingerprint.",
    "no-assets": "Fetched HTML pages but never their sub-resources — not rendering them "
    "like a browser.",
    "follows-links": "Often arrives at a page via a Referer it fetched earlier — on-site "
    "navigation.",
    "cold": "Requests pages cold, without following on-site links.",
    "browser-ua": "User-Agent matches a real browser profile (Mozilla + a layout engine), but "
    "carries no readable version to age.",
    "generic-ua": "User-Agent is a generic HTTP library/tool (curl, python-requests…), not a "
    "named agent.",
    "bot-ua": "User-Agent self-identifies as a bot, but not one we recognise — obscure, new, "
    "or fabricated.",
    "post-heavy": "Most requests are POSTs — form/submission traffic, e.g. comment or login spam.",
    "has-cache": "Received 304 Not Modified responses — makes conditional requests "
    "and holds a real cache, the mark of a browser or a polite poller.",
    "lacks-cache": "Re-fetches the same URLs (or makes many requests) yet never receives "
    "a 304 — makes no use of HTTP caching / revalidation, unlike a browser or polite poller.",
    "singleton": "Made exactly one request — too little on its own to characterise, "
    "so the kind leans on its UA and origin alone.",
    "headless-browser": "User-Agent names a headless / automation-driven browser engine "
    "(HeadlessChrome, PhantomJS, Puppeteer…) — a real engine, but machine-driven.",
    "uses-HEAD": "Issues HEAD requests for more than an incidental share of its traffic "
    "— browsers fetch with GET, so this points to a monitor, link-checker, or other bot.",
    "current-browser-ua": "Browser User-Agent whose version is current for when the client "
    "was active — consistent with a real, auto-updating browser.",
    "stale-browser-ua": "Browser User-Agent whose version is well behind the release cadence "
    "for its active period; unusual for an auto-updating browser.",
    "ancient-browser-ua": "Browser User-Agent whose version is years out of date. Chromium and "
    "Firefox auto-update, so this is almost always a frozen, spoofed User-Agent.",
    "impossible-browser-ua": "Browser User-Agent claiming a version newer than any that has "
    "been released for its active period — a forged User-Agent.",
    "checked-robots": "Requested /robots.txt at some point.",
    "no-user-agent": "Sent no User-Agent header.",
    "ua-rotating": "Many distinct User-Agents from one IP, paired with a hosting origin "
    "or non-browser behaviour — likely UA rotation to evade limits.",
    "shared-ip": "Many distinct User-Agents from one IP but behaving normally — a shared "
    "egress such as NAT, VPN, proxy, or carrier gateway.",
    "ignores-robots": "Requested paths disallowed by the applicable robots.txt group.",
    "dns-verified": "Reverse DNS resolved the client's IP to a host under the declared "
    "crawler's domain, and forward DNS confirmed it back to the same IP.",
    "ip-verified": "The client's IP falls within a published IP range for the declared crawler.",
    "asn-associated": "User-Agent names a known crawler and its origin AS is one that "
    "crawler is configured to use -- corroboration, a lighter check than DNS / IP-range "
    "verification (which take precedence when available).",
    "declares-known-bot": "User-Agent names a known crawler (identity verified separately).",
    "declares-app-client": "User-Agent names a native app's platform networking stack "
    "(CFNetwork, Flutter's dart:io…) rather than a browser engine or crawler.",
    "fetches-feeds": "User-Agent names a feed reader or generic feed tool (rss/atom…).",
    "user-triggered": "User-Agent names an on-behalf-of proxy (a '-User' fetcher like "
    "ChatGPT-User or Amzn-User) that the operator designates as acting for a present user "
    "rather than crawling autonomously. The user-driven part is taken on trust -- not "
    "observable here, and identity verification confirms who the agent is, not that a user "
    "drove the request.",
    "dns-violation": "Reverse/forward DNS definitively disagreed with the declared crawler "
    "(a wrong or absent PTR) — drives the 'impersonator' kind.",
    "ip-violation": "The client's IP definitively falls outside every published range for "
    "the declared crawler — drives the 'impersonator' kind.",
    "dns-unverified": "Declared a crawler with a domain to check by reverse DNS, but the "
    "check was inconclusive (a timeout) rather than a pass or a definitive fail.",
    "ip-unverified": "Declared a crawler with IP ranges to check, but they could not be "
    "obtained (e.g. the published range feed was unreachable).",
    "wba": "Presented a Web Bot Auth signature (a cryptographically signed request), "
    "not yet checked against the operator's key — run with --verify-bots to verify it.",
    "wba-verified": "A valid, fresh Web Bot Auth signature, checked against the operator's "
    "published Ed25519 key — cryptographic proof of identity, stronger than reverse-DNS or "
    "IP-range inference, and it outranks them.",
    "wba-expired": "A valid Web Bot Auth signature whose `expires` was already past at request "
    "time — the key genuinely signed it, but outside the signature's freshness window.",
    "wba-unverified": "Presented a Web Bot Auth signature that couldn't be checked — the key "
    "was unobtainable (e.g. rotated since), a covered field wasn't logged, or the body was "
    "signed. Never read as forgery: that requires a signature that fails against a fetched key.",
    "wba-violation": "A Web Bot Auth signature that failed against the operator's authentic, "
    "fetched key — cryptographic proof of a forged identity. Drives the 'impersonator' kind; "
    "shown alongside it so a client verified by one channel but forged on another is visible.",
    "wba-mixed": "A sample of this client's signed requests disagreed — some signatures verified "
    "and some did not. One identity presenting both valid and non-valid signatures is worth a "
    "look; the headline verdict is the representative request's.",
    "wba-replay": "A signature nonce from this client also appeared from a different origin — a "
    "captured, validly-signed request replayed elsewhere. The whole-log view catches this where "
    "an edge server checking one request can't; a valid signature alone wouldn't.",
    "wba-nonce-reuse": "This client reused a signature nonce across its own requests — a signer "
    "reusing nonces rather than a replay. Milder than a cross-origin replay; noted, not alarming.",
    "asn-attributed": "Identity is the origin AS itself -- an asn_primary network that "
    "crawls behind spoofed User-Agents, recognised by AS number rather than by its UA.",
    "probe-paths": "Requested known-vulnerable / probe paths (.env, /wp-login.php, .git/config…) "
    "— a burst of them, or a meaningful share of its traffic.",
    "traversal": "Used path-traversal or injection markers in the request path (../, injection "
    "patterns) — no legitimate use.",
    "encoding-evasion": "Used double or overlong percent-encoding — a deliberate attempt to slip "
    "past filters / a WAF.",
    "exotic-method": "Used uncommon HTTP methods (PUT/DELETE/PROPFIND/CONNECT…) — typical of "
    "scanners and WebDAV probes, not browsers.",
    "404-storm": "A high share of 404s spread across many distinct paths — scanning for "
    "content, or a broken integration.",
    "metronomic": "Near-constant intervals between requests — clockwork timing characteristic "
    "of automation, not a human.",
    "forged-referer": "Sends a Referer equal to the requested URL — fabricated "
    "navigation, not something a real browser produces.",
    "fetches-non-feeds": "A feed reader that also requested non-feed resources.",
    "high-rate": "Peak requests-per-minute well above this site's real browsers — a "
    "request rate no human-driven browser here reaches.",
    "high-bytes": "Mean response size well above this site's real browsers — pulling large "
    "objects / heavy downloads, not merely making many requests.",
    "wide-breadth": "Ranges across the site's structure more widely than its real browsers "
    "do — broad crawling rather than reading a few areas.",
    "long-session": "Active over a far longer span than this site's real browsers — a session "
    "length no human visit reaches.",
}


@lru_cache(maxsize=None)
def _egress_tag_help() -> dict[str, str]:
    return {
        net.tag: f"{net.name}: a shared-egress network (privacy relay / proxy). "
        "Its requests are folded into one entry per User-Agent."
        for net in load_egress_networks()
        if net.tag
    }


def tag_title(tag: str) -> str:
    """Hover / fallback description for a tag, or '' if none is known."""
    return _TAG_HELP.get(tag) or _egress_tag_help().get(tag, "")


def as_display(org: str | None, number: str | None) -> str:
    """An AS for display: org + number, just the number, just the org, or ``–``."""
    if org and number:
        return as_label(org, number)
    if number:
        num = number[2:] if number[:2].upper() == "AS" else number
        return f"AS{num}"
    return org or "–"


def count(num: int, noun: str, plural: str | None = None) -> str:
    """A count with its noun pluralised to match, e.g. ``1 client`` / ``2 clients``.

    Defaults to the regular ``+s`` plural; pass ``plural`` for an irregular noun.
    """
    word = noun if num == 1 else (plural or f"{noun}s")
    return f"{num:,} {word}"


def actor_spread(distinct_ips: int, distinct_asns: int) -> str:
    """Summarise a collapsed group's footprint, e.g. ``12 IPs · 3 ASNs``."""
    label = count(distinct_ips, "IP")
    if distinct_asns:
        label += f" · {count(distinct_asns, 'ASN')}"
    return label


def client_id_parts(profile: ClientProfile) -> tuple[str, str | None, str | None]:
    """Split a client's identity into ``(prefix, as_org, user_agent)`` for display.

    ``prefix`` is the IP / subnet / network name; ``as_org`` is the logged AS org
    (only for datacenter clients, else None); ``user_agent`` is the elided UA.
    Shared by the one-line :func:`client_label` and the HTML stacked cell.

    When the identity carries no UA -- an entry folded across many UAs, e.g. an
    ASN-recognised operator -- fall back to a sample UA from the features so the
    row isn't blank.
    """
    cid = profile.client_id
    prefix = cid.subnet if cid.subnet is not None else cid.ip
    ua = elide_ua(full_ua(profile), is_browser=profile.classification.primary is Kind.BROWSER)
    org = profile.features.as_org if "datacenter" in profile.classification.tags else None
    return prefix, org, ua


def full_ua(profile: ClientProfile) -> str | None:
    """The un-elided User-Agent behind a stacked cell's clamped/elided line --
    for a hover tooltip, so a truncated UA is never a dead end."""
    cid = profile.client_id
    return cid.user_agent if cid.user_agent is not None else profile.features.user_agent


def agent_identity(profile: ClientProfile) -> str | None:
    """A known agent's own identity for a header line: its declared name, else
    its Web Bot Auth operator, else an rDNS-confirmed hostname. ``None``
    otherwise -- in particular, the raw UA substring a classifier matched on is
    deliberately never used here even as a last resort: it is only a claim the
    client's own User-Agent header makes, not a confirmed identity, and heading
    a row with it would read as more certain than it is.

    WBA sits ahead of rDNS: a signature cryptographically confirmed against the
    operator's key -- VERIFIED and EXPIRED alike, the same pair the impersonator
    gate in the combiner already treats as outranking the network channel -- is
    proof of the operator, stronger evidence than a resolved hostname. Gated on
    ``wba.operator`` specifically, not :func:`wba.display_operator`'s
    ``signer_domain`` fallback: a signature can verify against a key fetched
    from the claimed Signature-Agent URL itself, with no curated-operator match
    at all, and that self-published domain is only as trustworthy as the
    client's own claim about itself -- exactly the "confusing identity" this
    function already declines to show for an rDNS CIDR or a raw UA token.

    The rDNS check specifically -- not the merged verification status -- decides
    the last tier: an agent verified by IP range alone (no declared domains)
    has its ``resolved_host`` set to the matched CIDR by :mod:`netverify`, which
    is a network, not a name, and would be a confusing "identity" to show.
    """
    cls = profile.classification
    if cls.agent_name:
        return cls.agent_name
    wba = profile.wba
    if wba is not None and wba.status in (WbaStatus.VERIFIED, WbaStatus.EXPIRED) and wba.operator:
        return wba.operator
    verification = profile.verification
    if (
        verification is not None
        and verification.dns is ChannelVerdict.VERIFIED
        and verification.resolved_host
    ):
        return verification.resolved_host
    return None


def client_label(profile: ClientProfile) -> str:
    """The one-line ``identity | user-agent [· AS org]`` label (Markdown, headers)."""
    prefix, org, ua = client_id_parts(profile)
    label = f"{prefix} | {ua if ua is not None else '-'}"
    if org:
        label += f" · {org}"
    return label


def kind_label(kind: Kind) -> str:
    """Human-facing category name: the enum slug with underscores shown as spaces."""
    return kind.value.replace("_", " ")


def truncate(text: str, limit: int = 80) -> str:
    """Shorten ``text`` to ``limit`` chars with an ellipsis (full detail is in inspect)."""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def human_bytes(num: int) -> str:
    """Render a byte count as a compact human-readable string."""
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def human_duration(seconds: float) -> str:
    """Render a duration in seconds as two tiers, e.g. ``1w 3d`` or ``2h 5m``.

    Picks the largest fitting unit (week / day / hour / minute / second) and
    pairs it with the next one down, but drops that lower unit when it's zero --
    so a whole week reads ``1w`` rather than ``7d 0h``, and ``3d`` rather than
    ``3d 0h``.
    """
    secs = int(seconds)
    if secs < 60:
        return f"{secs}s"
    for unit, size in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            lower, lsize = {"w": ("d", 86400), "d": ("h", 3600), "h": ("m", 60), "m": ("s", 1)}[
                unit
            ]
            high, rem = secs // size, secs % size
            low = rem // lsize
            return f"{high}{unit} {low}{lower}" if low else f"{high}{unit}"
    return f"{secs}s"


def fmt_ts(stamp: datetime | None) -> str:
    """Format a timestamp for display, or ``-`` when absent."""
    return stamp.strftime("%Y-%m-%d %H:%M:%S%z") if stamp is not None else "-"


def md_escape(text: str) -> str:
    """Escape the Markdown table-breaking characters in free text."""
    # A lone carriage return (a malformed request line, a non-LF line ending)
    # renders as a line break in many Markdown viewers and terminals, corrupting
    # the row, so neutralise CR as well as LF -- not just the pipe.
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def feature_rows(feats: ClientFeatures) -> list[tuple[str, str]]:
    """Flatten a feature vector into labelled metric rows for inspect output.

    Shared by the Markdown and HTML inspect renderers so both show the same
    metrics in the same order.
    """

    def pct(value: float) -> str:
        return f"{value:.0%}"

    def secs(value: float | None) -> str:
        return f"{value:.2f}" if value is not None else "–"

    methods = ", ".join(f"{m} {c}" for m, c in sorted(feats.method_counts.items())) or "–"
    rows = [
        (
            "status mix",
            f"2xx {pct(feats.ratio_2xx)} · 3xx {pct(feats.ratio_3xx)} · "
            f"4xx {pct(feats.ratio_4xx)} · 5xx {pct(feats.ratio_5xx)}",
        ),
        ("404s", f"{pct(feats.ratio_404)} across {feats.distinct_404_paths} distinct paths"),
        (
            "vuln-path hits",
            f"{feats.vuln_path_hits} ({pct(feats.vuln_path_ratio)}); "
            f"traversal {feats.traversal_hits}; evasion {feats.evasion_hits}",
        ),
        ("distinct paths", f"{feats.distinct_paths} (coverage {pct(feats.coverage)})"),
        ("feed requests", f"{feats.feed_requests} ({pct(feats.feed_ratio)})"),
        ("asset co-load", pct(feats.asset_coload_ratio)),
        ("static ratio", pct(feats.static_ratio)),
        ("referer-following", pct(feats.referer_following_ratio)),
        ("self-referer (fabricated)", pct(feats.self_referer_ratio)),
        ("breadth", pct(feats.breadth_ratio)),
        ("methods", methods),
        (
            "timing (median/min/p95)",
            f"{secs(feats.inter_arrival_median)}/{secs(feats.inter_arrival_min)}/"
            f"{secs(feats.inter_arrival_p95)} s; peak {feats.peak_requests_per_minute}/min",
        ),
        ("rate regularity (CV)", secs(feats.rate_regularity)),
        (
            "UA flags",
            f"browser={feats.ua_looks_like_browser}, bot={feats.ua_declares_bot}, "
            f"empty={feats.ua_empty}, UAs-on-IP={feats.ua_count_for_ip}",
        ),
        ("fetched robots.txt", str(feats.fetched_robots_txt)),
    ]
    if feats.as_org:
        rows.append(("AS / network", as_label(feats.as_org, feats.as_number)))
    return rows
