"""Small formatting helpers shared by the report and inspect renderers."""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache

from ..dataload import load_egress_networks
from ..model import ClientFeatures, ClientProfile, Kind, VerificationStatus

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
    """The single most salient evidence line for a client.

    A verified identity is the strongest thing we can say about a client, so it
    always wins the headline; otherwise fall back to the primary classifier's
    own evidence.
    """
    verification = profile.verification
    if (
        verification is not None
        and verification.status is VerificationStatus.VERIFIED
        and verification.evidence
    ):
        return verification.evidence[0]
    evidence = profile.classification.evidence
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
            "verified",
            "asn-associated",
            "unverified",
            "declares-known-bot",
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


# The conduct tier: noteworthy behaviour flagged only when present. When one is
# near-universal within a kind it's summarised in the section header ("typically:
# …") and dropped from the rows, so per-row conduct shows only the exceptions.
CONDUCT_TAGS = frozenset(
    {
        "probe-paths",
        "traversal",
        "encoding-evasion",
        "404-storm",
        "exotic-method",
        "uses-HEAD",
        "post-heavy",
        "forged-referer",
    }
)


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
    "verified": "Reverse/forward DNS or a published IP range confirmed the declared "
    "crawler identity.",
    "asn-associated": "User-Agent names a known crawler and its origin AS is one that "
    "crawler is configured to use -- corroboration, a lighter check than DNS / IP-range "
    "verification (which take precedence when available).",
    "declares-known-bot": "User-Agent names a known crawler (identity verified separately).",
    "unverified": "Declared a crawler we could check by reverse DNS or IP range, but the check "
    "didn't confirm it — it failed, or was inconclusive (a DNS timeout, unfetchable ranges). "
    "The mirror of 'verified'; the kind and verdict are unchanged.",
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
    raw_ua = cid.user_agent if cid.user_agent is not None else profile.features.user_agent
    ua = elide_ua(raw_ua, is_browser=profile.classification.primary is Kind.BROWSER)
    org = profile.features.as_org if "datacenter" in profile.classification.tags else None
    return prefix, org, ua


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
    """Render a duration in seconds as e.g. ``2h 5m`` or ``45s``."""
    secs = int(seconds)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    if secs < 86400:
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    return f"{secs // 86400}d {(secs % 86400) // 3600}h"


def fmt_ts(stamp: datetime | None) -> str:
    """Format a timestamp for display, or ``-`` when absent."""
    return stamp.strftime("%Y-%m-%d %H:%M:%S%z") if stamp is not None else "-"


def md_escape(text: str) -> str:
    """Escape the Markdown table-breaking characters in free text."""
    return text.replace("|", "\\|").replace("\n", " ")


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
