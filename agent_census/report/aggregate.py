"""Aggregation shared by the Markdown and HTML renderers."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..model import ClientProfile, Kind

# Order kinds appear in reports; UNKNOWN always last.
KIND_ORDER: tuple[Kind, ...] = (
    Kind.BROWSER,
    Kind.CRAWLER,
    Kind.GOOD_BOT,
    Kind.AI_CRAWLER,
    Kind.SCRAPER,
    Kind.VULN_SCANNER,
    Kind.SPAM_BOT,
    Kind.FEED_READER,
    Kind.MONITOR,
    Kind.UNKNOWN,
)

KIND_BLURB: dict[Kind, str] = {
    Kind.BROWSER: "Interactive browsers loading pages and their sub-resources.",
    Kind.CRAWLER: "Bots walking the site by following links at a steady pace.",
    Kind.GOOD_BOT: "Declared search-engine and social-preview crawlers.",
    Kind.AI_CRAWLER: "AI / LLM data-gathering crawlers.",
    Kind.SCRAPER: "Content harvesters hitting pages cold, without following links.",
    Kind.VULN_SCANNER: "Clients probing for known-vulnerable paths and misconfigurations.",
    Kind.SPAM_BOT: "Form/comment spam and credential-stuffing bots.",
    Kind.FEED_READER: "RSS/Atom feed pollers.",
    Kind.MONITOR: "Uptime / monitoring checks on a fixed schedule.",
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
