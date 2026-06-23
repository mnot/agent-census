"""Aggregation shared by the Markdown and HTML renderers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, KindRollup

# Order kinds appear in reports: a rough good -> bad gradient, with the
# can't-say buckets (singleton, unknown) at the very end.
KIND_ORDER: tuple[Kind, ...] = (
    Kind.BROWSER,
    Kind.FEED_READER,
    Kind.SOCIAL_PREVIEW,
    Kind.SEARCH_ENGINE,
    Kind.ARCHIVER,
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
    Kind.ARCHIVER: "Web-archiving / preservation crawlers (Internet Archive / Wayback Machine).",
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


def time_range(
    rollups: dict[Kind, KindRollup],
) -> tuple[datetime | None, datetime | None]:
    """Earliest first-seen and latest last-seen across all clients (exact)."""
    firsts = [r.first_seen for r in rollups.values() if r.first_seen]
    lasts = [r.last_seen for r in rollups.values() if r.last_seen]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


# How many distinct datacenter providers get their own column before the rest
# are folded into an "Other hosting" column.
MAX_DATACENTER_COLUMNS = 6


@dataclass(frozen=True)
class NetworkMatrix:
    """A kind x network cross-tab of request counts, ready to render."""

    networks: tuple[str, ...]  # column order
    kinds: tuple[Kind, ...]  # row order (only kinds with traffic)
    requests: dict[tuple[str, Kind], int]  # cell value, missing == 0
    col_totals: dict[str, int]
    row_totals: dict[Kind, int]
    total: int

    def cell(self, network: str, kind: Kind) -> int:
        return self.requests.get((network, kind), 0)


def network_matrix(
    network_rollups: dict[str, dict[Kind, KindRollup]],
    network_categories: dict[str, str],
    *,
    max_datacenter: int = MAX_DATACENTER_COLUMNS,
) -> NetworkMatrix | None:
    """Build the kind x network request cross-tab, or None if not worth showing.

    Only datacenter providers are collapsible: the busiest ``max_datacenter`` keep
    their own column and the rest fold into ``OTHER_HOSTING``. Shared-egress
    networks and the residential bucket always stand alone. Returns None when no
    network beyond residential appears (the table would be a single column).
    """
    if not any(cat != "residential" for cat in network_categories.values()):
        return None

    net_total = {
        net: sum(r.requests for r in kinds.values()) for net, kinds in network_rollups.items()
    }
    datacenters = sorted(
        (n for n, c in network_categories.items() if c == "datacenter"),
        key=lambda n: net_total.get(n, 0),
        reverse=True,
    )
    collapsed = set(datacenters[max_datacenter:])

    def column_of(net: str) -> str:
        return OTHER_HOSTING if net in collapsed else net

    requests: dict[tuple[str, Kind], int] = defaultdict(int)
    col_totals: dict[str, int] = defaultdict(int)
    row_totals: dict[Kind, int] = defaultdict(int)
    for net, kinds in network_rollups.items():
        col = column_of(net)
        for kind, rollup in kinds.items():
            requests[(col, kind)] += rollup.requests
            col_totals[col] += rollup.requests
            row_totals[kind] += rollup.requests

    # Columns biggest-first, with the residential and Other-hosting catch-alls
    # pinned to the right so the named networks read first.
    def column_sort(col: str) -> tuple[int, int]:
        rank = 2 if col == OTHER_HOSTING else 1 if col == RESIDENTIAL_NETWORK else 0
        return (rank, -col_totals[col])

    columns = tuple(sorted(col_totals, key=column_sort))
    kinds_present = tuple(k for k in KIND_ORDER if row_totals.get(k))
    return NetworkMatrix(
        networks=columns,
        kinds=kinds_present,
        requests=dict(requests),
        col_totals=dict(col_totals),
        row_totals=dict(row_totals),
        total=sum(col_totals.values()),
    )
