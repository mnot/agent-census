"""Aggregation shared by the Markdown and HTML renderers."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from ..classify.tags import OBSERVATIONAL_DISPLAY_TAGS, OBSERVATIONAL_TAGS
from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, KindRollup


# Kinds are grouped into clusters that band the report by what the traffic *is or
# does* -- never by a presumed beneficiary or intent (the kind wheel is
# classification, not judgement). Reading top to bottom is a rough good -> can't-say
# gradient, ending with the two unattributed buckets. Each label names the band's
# common trait: Human-like traffic behaves the way a person would (a feed reader is
# a person, just in other software) -- "-like" because a browser-shaped behaviour
# profile and a self-declared app UA are both inferred, never confirmed; individual
# kind blurbs below spell out what each one's evidence actually is. Utility bots
# reference or observe content (index, snapshot, unfurl, ping) rather than ingest
# it; Harvesters ingest content for a third party's reuse; Suspicious is defined by
# conduct (probing, forging identity, injecting), not by whether the actor is
# malicious; Unattributed is machine-or-maybe-machine with no purpose pinned down.
@dataclass(frozen=True)
class KindCluster:
    """An ordered band of kinds shown together, under one side label."""

    label: str
    kinds: tuple[Kind, ...]


KIND_CLUSTERS: tuple[KindCluster, ...] = (
    KindCluster("Human-like", (Kind.BROWSER, Kind.APP, Kind.FEED_READER)),
    KindCluster(
        "Utility bots",
        (Kind.SEARCH_ENGINE, Kind.ARCHIVER, Kind.SOCIAL_PREVIEW, Kind.MONITOR),
    ),
    KindCluster(
        "Harvesters",
        (
            Kind.AI_CRAWLER,
            Kind.SEO_MARKETING,
            Kind.DATA_HARVESTER,
            Kind.CRAWLER,
            Kind.SCRAPER,
        ),
    ),
    KindCluster(
        "Suspicious",
        (Kind.SPAM_BOT, Kind.VULN_SCANNER, Kind.SPOOFED_BROWSER, Kind.IMPERSONATOR),
    ),
    KindCluster("Unattributed", (Kind.AUTOMATION, Kind.UNKNOWN)),
)

# Derived so the flat order and the banding can never drift: the report's row order
# *is* the clusters, flattened. The assert makes a newly added Kind that nobody
# placed in a cluster a hard failure at import, not a silent drop from every table.
KIND_ORDER: tuple[Kind, ...] = tuple(k for c in KIND_CLUSTERS for k in c.kinds)
assert set(KIND_ORDER) == set(Kind) and len(KIND_ORDER) == len(
    Kind
), "every Kind must belong to exactly one cluster"


def clusters_present(
    is_present: Callable[[Kind], bool],
) -> list[tuple[KindCluster, list[Kind]]]:
    """Clusters in order, each paired with its kinds that pass ``is_present``.

    A cluster with no present kinds is dropped entirely (no empty band, no orphan
    label). Both renderers share this so their banding stays identical.
    """
    out: list[tuple[KindCluster, list[Kind]]] = []
    for cluster in KIND_CLUSTERS:
        members = [k for k in cluster.kinds if is_present(k)]
        if members:
            out.append((cluster, members))
    return out


KIND_BLURB: dict[Kind, str] = {
    Kind.BROWSER: "Browser-like clients -- loading pages and their sub-resources with "
    "human-like timing.",
    Kind.APP: "Clients whose User-Agent names a native-app networking stack (Apple's "
    "CFNetwork, Flutter's dart:io, ...) rather than a browser engine or crawler.",
    Kind.CRAWLER: "Bots fetching pages without browser sub-resource loading -- a "
    "self-declared crawler UA, or systematic link-following / broad coverage.",
    Kind.SEARCH_ENGINE: "Declared search-engine crawlers indexing the site.",
    Kind.ARCHIVER: "Declared web-archiving / preservation crawlers (Internet Archive / "
    "Wayback Machine).",
    Kind.SOCIAL_PREVIEW: "Declared link-unfurl fetchers building share previews.",
    Kind.AI_CRAWLER: "Declared AI / LLM data-gathering crawlers.",
    Kind.SEO_MARKETING: "Declared SEO / marketing / brand-monitoring crawlers.",
    Kind.DATA_HARVESTER: "Declared crawlers whose stated purpose is building a private "
    "corpus or dataset (plagiarism indexes, data brokers) -- not public search, "
    "preservation, or AI training.",
    Kind.IMPERSONATOR: "Clients faking a declared crawler identity -- the origin's reverse "
    "DNS, IP range, or AS number doesn't match the crawler it names.",
    Kind.SCRAPER: "Content harvesters hitting pages cold, without following links.",
    Kind.VULN_SCANNER: "Clients probing for known-vulnerable paths and misconfigurations.",
    Kind.SPOOFED_BROWSER: "Datacenter clients wearing a browser UA without browser behaviour.",
    Kind.AUTOMATION: "Clearly automated clients (headless engine, no browser cache, or a "
    "library UA) whose specific purpose couldn't be identified.",
    Kind.SPAM_BOT: "Form/comment spam and submission-endpoint abuse (comment forms, login, "
    "xmlrpc).",
    Kind.FEED_READER: "RSS/Atom feed pollers.",
    Kind.MONITOR: "Uptime / monitoring checks on a fixed schedule.",
    Kind.UNKNOWN: "Clients no classifier could characterize -- and with no machine tell to "
    "mark them even as automation.",
}
# Same enforcement as KIND_ORDER above: a newly added Kind with no blurb should fail
# at import, not render as a silent blank paragraph in every report.
assert set(KIND_BLURB) == set(Kind), "every Kind must have a blurb"


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
    def slug(self) -> str:
        """A stable, filesystem-safe id for this group, used to name its inspect
        data file and to link a report row to it. Derived from the lead's identity
        tuple, which is unique per group, so the report and the data writer agree."""
        cid = self.lead.client_id
        key = f"{cid.ip}|{cid.user_agent or ''}|{cid.subnet or ''}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

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

    @property
    def shared_asn(self) -> tuple[str | None, str | None] | None:
        """The one ``(org, number)`` every member with an ASN shares, else ``None``.

        ``None`` unless the members carrying an AS all carry the *same* one -- so a
        collapsed group can name its origin AS when it has just one, but stays silent
        when they span several (or none).
        """
        numbers = {m.features.as_number for m in self.members if m.features.as_number}
        if len(numbers) != 1:
            return None
        (number,) = numbers
        org = next(
            (m.features.as_org for m in self.members if m.features.as_number == number),
            None,
        )
        return org, number

    @property
    def observational_tags(self) -> frozenset[str]:
        """Observational tags to show on the folded row -- any member's, unioned.

        Excluded from :func:`group_actors`'s folding key (see ``OBSERVATIONAL_TAGS``)
        since they're incidental to which slice of an actor's traffic a given member
        happened to carry, not its identity -- but still worth surfacing on the row.
        See ``OBSERVATIONAL_DISPLAY_TAGS`` for why ``singleton`` alone is dropped.
        """
        tags: set[str] = set()
        for member in self.members:
            tags |= member.classification.tags & OBSERVATIONAL_DISPLAY_TAGS
        return frozenset(tags)


def group_actors(profiles: Sequence[ClientProfile]) -> list[ActorGroup]:
    """Collapse profiles differing only by IP/ASN into actor groups, biggest-first.

    The signature is ``(User-Agent, tags)``, excluding ``OBSERVATIONAL_TAGS``:
    clients are folded together when they are indistinguishable apart from their
    address, origin AS, and incidental per-batch observations (a robots.txt hit, a
    304, request-volume/method-mix facts). Within a group members are ordered by
    request volume; groups are ordered the same way by their combined requests.
    """
    buckets: dict[tuple[str | None, frozenset[str]], list[ClientProfile]] = {}
    for profile in profiles:
        key = (
            profile.client_id.user_agent,
            frozenset(profile.classification.tags - OBSERVATIONAL_TAGS),
        )
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


# The busiest this-many datacentres always get their own column in the cross-tab.
# Beyond it, a datacentre is promoted to its own column only when it is substantial
# (see ``network_matrix``); the rest fold into "Other datacenters". The datacentre
# columns scroll horizontally in the HTML report while Other stays pinned.
MAX_DATACENTER_COLUMNS = 6

# Promotion floor (per kind): beyond the always-shown top columns, a datacentre
# earns its own column when it carries at least this share of *some single kind's*
# traffic -- keyed per kind (not overall) so a provider concentrated in one
# category surfaces even when it is a sliver of total volume. (Still the
# ``--breakout-min-pct`` flag, for continuity.)
BREAKOUT_MIN_SHARE = 0.10

# Absolute guard on promotion: 10% of a tiny kind is only a handful of requests, so
# a promoted datacentre must also clear this floor -- the larger of a share of total
# traffic or an absolute request count. The always-shown top columns are exempt.
PROMOTE_GUARD_SHARE = 0.0001  # 0.01% of total requests
PROMOTE_GUARD_REQUESTS = 100


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
    min_breakout_share: float = BREAKOUT_MIN_SHARE,
    guard_share: float = PROMOTE_GUARD_SHARE,
    guard_requests: int = PROMOTE_GUARD_REQUESTS,
) -> NetworkMatrix | None:
    """Build the kind x network request cross-tab, or None if not worth showing.

    The busiest ``max_datacenter`` datacentres always get their own column. Beyond
    those, a datacentre is promoted to its own column when it carries at least
    ``min_breakout_share`` of *some single kind's* traffic (so a provider big within
    one category surfaces) **and** clears an absolute guard -- ``guard_requests`` or
    ``guard_share`` of total traffic, whichever is larger. Every other datacentre
    folds into ``OTHER_HOSTING``. Shared-egress networks and the residential bucket
    always stand alone. Returns None when no network beyond residential appears.
    """
    if not any(cat != "residential" for cat in network_categories.values()):
        return None

    net_total = {
        net: sum(r.requests for r in kinds.values()) for net, kinds in network_rollups.items()
    }
    row_totals: dict[Kind, int] = defaultdict(int)
    for kinds in network_rollups.values():
        for kind, rollup in kinds.items():
            row_totals[kind] += rollup.requests
    grand_total = sum(net_total.values())

    datacenters = sorted(
        (n for n, c in network_categories.items() if c == "datacenter"),
        key=lambda n: net_total.get(n, 0),
        reverse=True,
    )
    # The busiest few are always shown. Beyond them a datacentre needs both a per-kind
    # share (it matters within some category) and an absolute floor (it is not
    # negligible overall) to earn its own column; the rest fold into Other.
    guard = max(guard_share * grand_total, guard_requests)

    def promotable(net: str) -> bool:
        if net_total[net] < guard:
            return False
        return any(
            rollup.requests >= min_breakout_share * row_totals[kind]
            for kind, rollup in network_rollups[net].items()
            if row_totals[kind]
        )

    shown = set(datacenters[:max_datacenter])
    shown.update(net for net in datacenters[max_datacenter:] if promotable(net))
    collapsed = set(datacenters) - shown

    def column_of(net: str) -> str:
        return OTHER_HOSTING if net in collapsed else net

    requests: dict[tuple[str, Kind], int] = defaultdict(int)
    col_totals: dict[str, int] = defaultdict(int)
    categories: dict[str, str] = {OTHER_HOSTING: "datacenter"}
    for net, kinds in network_rollups.items():
        col = column_of(net)
        categories.setdefault(col, network_categories.get(net, "residential"))
        for kind, rollup in kinds.items():
            requests[(col, kind)] += rollup.requests
            col_totals[col] += rollup.requests

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
