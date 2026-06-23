"""Aggregation shared by the Markdown and HTML renderers."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..model import ClientProfile, Kind

# Order kinds appear in reports: a rough good -> bad gradient, with the
# can't-say buckets (singleton, unknown) at the very end.
KIND_ORDER: tuple[Kind, ...] = (
    Kind.BROWSER,
    Kind.FEED_READER,
    Kind.SOCIAL_PREVIEW,
    Kind.SEARCH_ENGINE,
    Kind.AI_CRAWLER,
    Kind.SEO_MARKETING,
    Kind.MONITOR,
    Kind.CRAWLER,
    Kind.SCRAPER,
    Kind.SPOOFED_BROWSER,
    Kind.SPAM_BOT,
    Kind.VULN_SCANNER,
    Kind.IMPERSONATOR,
    Kind.SINGLETON,
    Kind.UNKNOWN,
)

KIND_BLURB: dict[Kind, str] = {
    Kind.BROWSER: "Interactive browsers loading pages and their sub-resources.",
    Kind.CRAWLER: "Bots walking the site by following links at a steady pace.",
    Kind.SEARCH_ENGINE: "Declared search-engine crawlers indexing the site.",
    Kind.SOCIAL_PREVIEW: "Link-unfurl fetchers building share previews.",
    Kind.AI_CRAWLER: "AI / LLM data-gathering crawlers.",
    Kind.SEO_MARKETING: "SEO / marketing / brand-monitoring crawlers.",
    Kind.IMPERSONATOR: "Clients faking a declared crawler identity (DNS / IP-range mismatch).",
    Kind.SCRAPER: "Content harvesters hitting pages cold, without following links.",
    Kind.VULN_SCANNER: "Clients probing for known-vulnerable paths and misconfigurations.",
    Kind.SPOOFED_BROWSER: "Datacenter clients wearing a browser UA without browser behaviour.",
    Kind.SPAM_BOT: "Form/comment spam and credential-stuffing bots.",
    Kind.FEED_READER: "RSS/Atom feed pollers.",
    Kind.MONITOR: "Uptime / monitoring checks on a fixed schedule.",
    Kind.SINGLETON: "One-request clients with no other signal to characterize them.",
    Kind.UNKNOWN: "Clients that no classifier could characterize with confidence.",
}


def by_kind(profiles: tuple[ClientProfile, ...]) -> dict[Kind, list[ClientProfile]]:
    """Group profiles by their primary kind."""
    groups: dict[Kind, list[ClientProfile]] = defaultdict(list)
    for profile in profiles:
        groups[profile.classification.primary].append(profile)
    return groups


def time_range(profiles: tuple[ClientProfile, ...]) -> tuple[datetime | None, datetime | None]:
    """Earliest first-seen and latest last-seen across all profiles."""
    firsts = [p.features.first_seen for p in profiles if p.features.first_seen]
    lasts = [p.features.last_seen for p in profiles if p.features.last_seen]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def robots_counts(group: list[ClientProfile]) -> tuple[int, int]:
    """Return (respects, ignores) counts for a group of profiles."""
    respects = sum(1 for p in group if "respects-robots" in p.classification.tags)
    ignores = sum(1 for p in group if "ignores-robots" in p.classification.tags)
    return respects, ignores
