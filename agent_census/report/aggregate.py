"""Aggregation shared by the Markdown and HTML renderers."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, KindRollup
from .format import CONDUCT_TAGS

# Order kinds appear in reports: a rough good -> bad gradient, with the
# can't-say buckets (singleton, unknown) at the very end.
KIND_ORDER: tuple[Kind, ...] = (
    Kind.BROWSER,
    Kind.APP,
    Kind.FEED_READER,
    Kind.SOCIAL_PREVIEW,
    Kind.SEARCH_ENGINE,
    Kind.ARCHIVER,
    Kind.AI_CRAWLER,
    Kind.SEO_MARKETING,
    Kind.DATA_HARVESTER,
    Kind.MONITOR,
    Kind.CRAWLER,
    Kind.SCRAPER,
    Kind.SPAM_BOT,
    Kind.VULN_SCANNER,
    Kind.SPOOFED_BROWSER,
    Kind.IMPERSONATOR,
    Kind.AUTOMATION,
    Kind.SINGLETON,
    Kind.UNKNOWN,
)

KIND_BLURB: dict[Kind, str] = {
    Kind.BROWSER: "Interactive browsers loading pages and their sub-resources.",
    Kind.APP: "Native mobile / desktop apps requesting via a platform networking stack.",
    Kind.CRAWLER: "Bots fetching pages without browser sub-resource loading -- a "
    "self-declared crawler UA, or systematic link-following / broad coverage.",
    Kind.SEARCH_ENGINE: "Declared search-engine crawlers indexing the site.",
    Kind.ARCHIVER: "Web-archiving / preservation crawlers (Internet Archive / Wayback Machine).",
    Kind.SOCIAL_PREVIEW: "Link-unfurl fetchers building share previews.",
    Kind.AI_CRAWLER: "AI / LLM data-gathering crawlers.",
    Kind.SEO_MARKETING: "SEO / marketing / brand-monitoring crawlers.",
    Kind.DATA_HARVESTER: "Crawlers ingesting content into a private corpus or dataset "
    "(plagiarism indexes, data brokers) -- not public search, preservation, or AI training.",
    Kind.IMPERSONATOR: "Clients faking a declared crawler identity -- the origin's reverse "
    "DNS, IP range, or AS number doesn't match the crawler it names.",
    Kind.SCRAPER: "Content harvesters hitting pages cold, without following links.",
    Kind.VULN_SCANNER: "Clients probing for known-vulnerable paths and misconfigurations.",
    Kind.SPOOFED_BROWSER: "Datacenter clients wearing a browser UA without browser behaviour.",
    Kind.AUTOMATION: "Clearly automated clients (headless engine, no browser cache, or a "
    "library UA) whose specific purpose couldn't be identified.",
    Kind.SPAM_BOT: "Form/comment spam and credential-stuffing bots.",
    Kind.FEED_READER: "RSS/Atom feed pollers.",
    Kind.MONITOR: "Uptime / monitoring checks on a fixed schedule.",
    Kind.SINGLETON: "One-request clients with no other signal to characterize them.",
    Kind.UNKNOWN: "Clients no classifier could characterize -- and with no machine tell to "
    "mark them even as automation.",
}


def by_kind(profiles: tuple[ClientProfile, ...]) -> dict[Kind, list[ClientProfile]]:
    """Group profiles by their primary kind."""
    groups: dict[Kind, list[ClientProfile]] = defaultdict(list)
    for profile in profiles:
        groups[profile.classification.primary].append(profile)
    return groups


@dataclass(frozen=True)
class ActorGroup:
    """Profiles that differ only by IP/ASN -- i.e. share a User-Agent and tags.

    A single-member group renders like an ordinary client row; a multi-member
    group (:attr:`collapsed`) is shown as one summary row whose members are
    listed on demand, with each member's own traffic preserved.
    """

    members: tuple[ClientProfile, ...]  # request-volume desc; members[0] is the lead

    @property
    def lead(self) -> ClientProfile:
        return self.members[0]

    @property
    def collapsed(self) -> bool:
        return len(self.members) > 1

    @property
    def requests(self) -> int:
        return sum(m.features.request_count for m in self.members)

    @property
    def total_bytes(self) -> int:
        return sum(m.features.total_bytes for m in self.members)

    @property
    def distinct_ips(self) -> int:
        return len({m.client_id.subnet or m.client_id.ip for m in self.members})

    @property
    def distinct_asns(self) -> int:
        return len({m.features.as_number for m in self.members if m.features.as_number})


def typical_conduct(
    profiles: Sequence[ClientProfile], *, min_clients: int = 3, threshold: float = 0.8
) -> frozenset[str]:
    """Conduct tags shared by ~all of a kind's clients -- its baseline conduct.

    Hoisted into the section header ("typically: …") and dropped from the rows so
    per-row conduct shows only the exceptions. Empty for a kind too small to
    generalise from.
    """
    total = len(profiles)
    if total < min_clients:
        return frozenset()
    counts: dict[str, int] = defaultdict(int)
    for profile in profiles:
        for tag in profile.classification.tags & CONDUCT_TAGS:
            counts[tag] += 1
    return frozenset(tag for tag, seen in counts.items() if seen / total >= threshold)


def group_actors(profiles: Sequence[ClientProfile]) -> list[ActorGroup]:
    """Collapse profiles differing only by IP/ASN into actor groups, biggest-first.

    The signature is ``(User-Agent, tags)``: clients are folded together only when
    they are indistinguishable apart from their address and origin AS. Within a
    group members are ordered by request volume; groups are ordered the same way
    by their combined requests.
    """
    buckets: dict[tuple[str | None, frozenset[str]], list[ClientProfile]] = {}
    for profile in profiles:
        key = (profile.client_id.user_agent, frozenset(profile.classification.tags))
        buckets.setdefault(key, []).append(profile)
    groups = [
        ActorGroup(tuple(sorted(members, key=lambda p: p.features.request_count, reverse=True)))
        for members in buckets.values()
    ]
    groups.sort(key=lambda g: g.requests, reverse=True)
    return groups


def time_range(
    rollups: dict[Kind, KindRollup],
) -> tuple[datetime | None, datetime | None]:
    """Earliest first-seen and latest last-seen across all clients (exact)."""
    firsts = [r.first_seen for r in rollups.values() if r.first_seen]
    lasts = [r.last_seen for r in rollups.values() if r.last_seen]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


# How many distinct datacenter providers get their own column before the rest
# are folded into an "Other datacenter" column.
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
    categories: dict[str, str]  # column -> datacenter | egress | residential

    def cell(self, network: str, kind: Kind) -> int:
        return self.requests.get((network, kind), 0)

    def is_hosting(self, network: str) -> bool:
        """True for datacenter/hosting columns; False for egress and residential."""
        return self.categories.get(network) == "datacenter"


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
    categories: dict[str, str] = {OTHER_HOSTING: "datacenter"}
    for net, kinds in network_rollups.items():
        col = column_of(net)
        categories.setdefault(col, network_categories.get(net, "residential"))
        for kind, rollup in kinds.items():
            requests[(col, kind)] += rollup.requests
            col_totals[col] += rollup.requests
            row_totals[kind] += rollup.requests

    # Group hosting on the left (named providers biggest-first, then the Other
    # hosting catch-all), then the non-hosting columns: egress networks, then the
    # residential bucket pinned far right.
    def column_sort(col: str) -> tuple[int, int]:
        if col == OTHER_HOSTING:
            rank = 1
        elif col == RESIDENTIAL_NETWORK:
            rank = 3
        else:
            rank = 0 if categories[col] == "datacenter" else 2  # 2 = egress
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
        categories=categories,
    )
