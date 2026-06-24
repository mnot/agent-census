"""Orchestration: parse -> accumulate per client -> classify -> profiles.

This is the seam that turns log files into a list of :class:`ClientProfile`. It
streams: each parsed line is folded into its client's feature accumulator and
discarded, so peak memory is bounded by the number of distinct clients (plus a
compact per-client accumulator), not the number of log lines. Raw entries are
never retained here -- ``inspect`` collects them for the selected clients in a
cheap second pass via :func:`collect_entries`.
"""

from __future__ import annotations

import gzip
import heapq
import itertools
from collections import OrderedDict, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Protocol

from . import egress, uas
from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .features import DisallowedCheck, FeatureAccumulator
from .hosting import (
    datacenter_provider,
    datacenter_provider_for_asn,
    datacenter_subnet,
    is_datacenter_ip,
)
from .identity import ClientKeyStrategy
from .model import (
    BotVerification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
    LogEntry,
    VerificationStatus,
)
from .parsing.base import LogParser
from .robots import RobotsRules, report_from_signals

# Default inactivity gap after which a client is considered finished and evicted.
DEFAULT_QUIESCENT_SECONDS = 24 * 60 * 60

# Default cap on detailed client profiles kept per kind. The per-kind summary
# stays exact regardless (see KindRollup); only the lowest-volume clients beyond
# the cap lose their individual row. 0 disables the cap (keep every profile).
DEFAULT_MAX_PER_KIND = 1000

# Evicted (quiescent) clients are parked here rather than finalised outright, so a
# client that goes quiet and later returns is coalesced into one profile instead of
# fragmenting. The park is a bounded LRU: only when more than this many distinct
# clients are dormant at once do the longest-dormant get finalised for real (and a
# later return from one of those would re-fragment -- the memory ceiling's cost).
DEFAULT_RETIRED_CAP = 50_000

# Declared-crawler categories, checked individually so per-UA matches cache.
_CRAWLER_CATEGORIES = ("search_engine", "social_preview", "archiver", "ai_crawler", "seo_marketing")

# Network buckets for the kind x network cross-tab. A client's network is the
# hosting provider its IP belongs to, the shared-egress network it came through,
# or this catch-all for everything else (ISPs, mobile, unknown).
RESIDENTIAL_NETWORK = "Residential / unknown"
# Fallback provider label, and the column the report collapses the long tail into.
OTHER_HOSTING = "Other hosting"
_NET_DATACENTER = "datacenter"
_NET_EGRESS = "egress"
_NET_RESIDENTIAL = "residential"


def _declares_crawler(ua: str | None) -> bool:
    """True if the UA names any known crawler (kept resident, never evicted)."""
    return any(uas.match_category(ua, category) for category in _CRAWLER_CATEGORIES)


def _parse_asn(value: str | None) -> int | None:
    """Parse a logged AS number (``16509`` or ``AS16509``) to an int, or None."""
    if not value:
        return None
    text = value.strip()
    if text[:2].lower() == "as":
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return None


class BotVerifier(Protocol):
    """Verifies declared crawlers (implemented by :class:`agent_census.netverify.BotVerifier`)."""

    def needs(self, ua: str | None) -> bool: ...

    def verify_all(
        self, items: Sequence[tuple[ClientId, str | None]]
    ) -> dict[ClientId, BotVerification]: ...


@dataclass(frozen=True, slots=True)
class SkipStats:
    """How many lines parsed vs. were skipped, and why."""

    total_lines: int
    parsed: int
    skipped: int
    reasons: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IdentityStats:
    """Diagnostics on how the identity strategy grouped the data."""

    client_count: int
    singletons: int
    ips_with_multiple_uas: int


@dataclass(frozen=True, slots=True)
class KindRollup:
    """Exact per-kind totals over *every* client of a kind, including any whose
    individual profile the per-kind cap dropped. Keeps the summary exact."""

    clients: int = 0
    requests: int = 0
    total_bytes: int = 0
    respects_robots: int = 0
    ignores_robots: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class _RollupAcc:
    """Mutable per-kind accumulator, frozen into a :class:`KindRollup` at the end."""

    __slots__ = (
        "clients", "requests", "total_bytes", "respects", "ignores", "first_seen", "last_seen",
    )  # fmt: skip

    def __init__(self) -> None:
        self.clients = self.requests = self.total_bytes = self.respects = self.ignores = 0
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None

    def add(self, features: ClientFeatures, tags: frozenset[str]) -> None:
        self.clients += 1
        self.requests += features.request_count
        self.total_bytes += features.total_bytes
        if "respects-robots" in tags:
            self.respects += 1
        elif "ignores-robots" in tags:
            self.ignores += 1
        first, last = features.first_seen, features.last_seen
        if first is not None and (self.first_seen is None or first < self.first_seen):
            self.first_seen = first
        if last is not None and (self.last_seen is None or last > self.last_seen):
            self.last_seen = last

    def freeze(self) -> KindRollup:
        return KindRollup(
            clients=self.clients,
            requests=self.requests,
            total_bytes=self.total_bytes,
            respects_robots=self.respects,
            ignores_robots=self.ignores,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
        )


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """The full output of an analysis run."""

    profiles: tuple[ClientProfile, ...]
    skips: SkipStats
    identity_strategy: str
    identity_stats: IdentityStats
    # Exact per-kind totals over all clients; the summary reads these, so it stays
    # exact even when `profiles` is capped to the top clients per kind.
    rollups: dict[Kind, KindRollup] = field(default_factory=dict)
    # Exact per-kind totals split by the client's network (hosting provider /
    # shared-egress network / residential), for the kind x network cross-tab.
    network_rollups: dict[str, dict[Kind, KindRollup]] = field(default_factory=dict)
    # Each network label's category (datacenter / egress / residential), so the
    # report can collapse only the datacenter tail.
    network_categories: dict[str, str] = field(default_factory=dict)


def read_lines(path: Path) -> Iterator[str]:
    """Yield lines from a plain or gzip-compressed log file."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle
    else:
        with path.open("rt", encoding="utf-8", errors="replace") as handle:
            yield from handle


def read_many(paths: Sequence[Path]) -> Iterator[str]:
    """Yield lines from several log files in order, as one stream."""
    for path in paths:
        yield from read_lines(path)


def _disallowed_check(rules: RobotsRules, token: str | None) -> DisallowedCheck:
    def check(path: str) -> bool:
        return not rules.can_fetch(token, path)

    return check


def _matched_domain(verification: BotVerification) -> str:
    host = (verification.resolved_host or "").lower().rstrip(".")
    for domain in verification.expected_domains:
        if host == domain or host.endswith("." + domain):
            return domain
    if verification.expected_domains:
        return verification.expected_domains[0]
    return verification.resolved_host or "verified"


def _merge_verified(
    accumulators: dict[ClientId, FeatureAccumulator],
    tokens: dict[ClientId, str | None],
    verifications: dict[ClientId, BotVerification],
) -> dict[ClientId, tuple[str, ...]]:
    """Collapse all IPs of each DNS-verified bot into one entry keyed by its domain.

    Returns the IPs that went into each merged entry. Mutates ``accumulators``,
    ``tokens`` and ``verifications`` in place: the per-IP keys are replaced by a
    single ``ClientId`` whose ``ip`` is the verified reverse-DNS domain.
    """
    groups: dict[tuple[str, str | None], list[ClientId]] = defaultdict(list)
    for key, verification in verifications.items():
        if verification.status is VerificationStatus.VERIFIED:
            groups[(_matched_domain(verification), tokens.get(key))].append(key)

    member_ips: dict[ClientId, tuple[str, ...]] = {}
    for (domain, token), keys in groups.items():
        merged = FeatureAccumulator()
        ips: list[str] = []
        for key in keys:
            merged.merge(accumulators.pop(key))
            ips.append(key.ip)
            verifications.pop(key, None)
            tokens.pop(key, None)
        new_id = ClientId(ip=domain, user_agent=merged.user_agent)
        accumulators[new_id] = merged
        tokens[new_id] = token
        verifications[new_id] = BotVerification(
            VerificationStatus.VERIFIED,
            resolved_host=domain,
            evidence=(f"{len(ips)} IP(s) verified as {domain}",),
        )
        member_ips[new_id] = tuple(ips)
    return member_ips


def analyze(  # pylint: disable=too-many-locals,too-many-statements
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    *,
    robots: RobotsRules | None = None,
    verifier: BotVerifier | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
    quiescent_seconds: float | None = None,
    retired_cap: int = DEFAULT_RETIRED_CAP,
    max_per_kind: int = DEFAULT_MAX_PER_KIND,
) -> AnalysisResult:
    """Stream one or more log files into per-client profiles.

    Multiple files are read in order as one stream and pooled, so a client that
    appears across rotated logs is treated as one. Entries are not retained;
    pass the result to :func:`collect_entries` if you need raw request traces.

    With ``quiescent_seconds`` set, a client that has been silent for that long
    (relative to the latest log timestamp) is finalised and its live accumulator
    freed mid-stream, so peak memory tracks the active window rather than the
    whole run. Declared crawlers are kept resident so their IPs can still be
    merged. ``keep_signals=False`` drops per-client classifier signals (only
    inspect reads them).
    """
    paths = [logs] if isinstance(logs, Path) else list(logs)
    resident: dict[ClientId, FeatureAccumulator] = {}
    evictable: OrderedDict[ClientId, FeatureAccumulator] = OrderedDict()
    retired: OrderedDict[ClientId, FeatureAccumulator] = OrderedDict()
    # Shared-egress traffic is folded as it streams: one accumulator per
    # (network, UA), keyed past the rotating source IPs, with its member IPs and
    # tag tracked alongside.
    egress_acc: OrderedDict[tuple[str, str | None], FeatureAccumulator] = OrderedDict()
    egress_token: dict[tuple[str, str | None], str | None] = {}
    egress_members: dict[tuple[str, str | None], set[str]] = {}
    egress_tag: dict[str, str] = {}
    # Datacenter clients sharing a /24 (or /48) and UA are lumped into one entry,
    # keyed by (subnet, UA), the same way -- an adjacent VM fleet is one actor.
    dc_acc: OrderedDict[tuple[str, str | None], FeatureAccumulator] = OrderedDict()
    dc_token: dict[tuple[str, str | None], str | None] = {}
    dc_members: dict[tuple[str, str | None], set[str]] = {}
    tokens: dict[ClientId, str | None] = {}
    uas_by_ip: dict[str, set[str | None]] = {}
    ip_refs: dict[str, int] = defaultdict(int)
    # Output is bounded: exact per-kind rollups over all clients, plus a per-kind
    # heap of the highest-volume profiles (the only ones kept in detail).
    rollups: dict[Kind, _RollupAcc] = defaultdict(_RollupAcc)
    # Same totals, split by network, for the kind x network cross-tab.
    net_rollups: dict[str, dict[Kind, _RollupAcc]] = defaultdict(lambda: defaultdict(_RollupAcc))
    net_categories: dict[str, str] = {}
    kept: dict[Kind, list[tuple[int, int, ClientProfile]]] = defaultdict(list)
    seq = itertools.count()
    total = parsed = skipped = 0
    client_count = singleton_count = multi_ua_ips = 0
    latest_ts: float | None = None
    reasons: dict[str, int] = defaultdict(int)

    def emit(
        key: ClientId,
        acc: FeatureAccumulator,
        verification: BotVerification | None,
        member: tuple[str, ...],
        extra_tags: frozenset[str] = frozenset(),
        datacenter: bool | None = None,
        network: str | None = None,
        network_category: str | None = None,
    ) -> None:
        nonlocal singleton_count
        ua_count = len(uas_by_ip.get(key.ip) or (None,))
        features = acc.finalize(ua_count_for_ip=ua_count)
        if features.request_count == 1:
            singleton_count += 1
        compliance = None
        if robots is not None:
            compliance = report_from_signals(
                robots,
                tokens.get(key),
                disallowed_hits=acc.disallowed_hits,
                sample_disallowed=tuple(acc.disallowed_sample or ()),
                fetched_robots_first=acc.robots_fetched_first,
                fetched_robots_txt=features.fetched_robots_txt,
                request_count=features.request_count,
                median_interval=features.inter_arrival_median,
            )
        if network is None:
            # A regular client: attribute it to its hosting provider. Try the IP
            # ranges first, then the AS number the log carries (if any) -- so a
            # provider we know only by ASN is still recognised as a datacenter.
            provider = datacenter_provider(key.ip)
            if provider is None:
                provider = datacenter_provider_for_asn(_parse_asn(features.as_number))
            in_datacenter = provider is not None if datacenter is None else datacenter
            network = provider if provider is not None else RESIDENTIAL_NETWORK
            network_category = _NET_DATACENTER if provider is not None else _NET_RESIDENTIAL
        else:
            in_datacenter = is_datacenter_ip(key.ip) if datacenter is None else datacenter
        classification = classify_client(
            features,
            compliance=compliance,
            verification=verification,
            datacenter=in_datacenter,
            unknown_threshold=unknown_threshold,
            keep_signals=keep_signals,
        )
        if extra_tags:
            classification = replace(classification, tags=classification.tags | extra_tags)
        profile = ClientProfile(
            client_id=key,
            entries=(),
            features=features,
            classification=classification,
            compliance=compliance,
            verification=verification,
            member_ips=member,
            network=network,
        )
        kind = classification.primary
        rollups[kind].add(features, classification.tags)  # every client counts here
        net_rollups[network][kind].add(features, classification.tags)
        net_categories.setdefault(network, network_category or _NET_RESIDENTIAL)
        # Keep only the highest-volume profiles per kind in detail; the rest are
        # already fully reflected in the rollup above.
        heap = kept[kind]
        item = (features.request_count, next(seq), profile)
        if max_per_kind <= 0 or len(heap) < max_per_kind:
            heapq.heappush(heap, item)
        elif features.request_count > heap[0][0]:
            heapq.heappushpop(heap, item)

    def drop_client(key: ClientId) -> None:
        tokens.pop(key, None)
        remaining = ip_refs.get(key.ip, 0) - 1
        if remaining <= 0:
            ip_refs.pop(key.ip, None)
            uas_by_ip.pop(key.ip, None)
        else:
            ip_refs[key.ip] = remaining

    def evict(cutoff: float) -> None:
        while evictable:
            key = next(iter(evictable))
            last_seen = evictable[key].last_seen
            if last_seen is None or last_seen.timestamp() >= cutoff:
                break
            # Park, don't finalise: a return visit reanimates this accumulator.
            retired[key] = evictable.pop(key)
        while len(retired) > retired_cap:
            old_key, acc = retired.popitem(last=False)
            emit(old_key, acc, None, ())
            drop_client(old_key)

    def fold(
        store: "OrderedDict[tuple[str, str | None], FeatureAccumulator]",
        token_store: dict[tuple[str, str | None], str | None],
        members: dict[tuple[str, str | None], set[str]],
        gkey: tuple[str, str | None],
        entry: LogEntry,
    ) -> None:
        """Collapse a request into a shared (group, UA) accumulator, tracking its IPs."""
        acc = store.get(gkey)
        if acc is None:
            token = uas.product_token(entry.user_agent) if robots is not None else None
            check = _disallowed_check(robots, token) if robots is not None else None
            acc = FeatureAccumulator(disallowed_check=check)
            store[gkey] = acc
            token_store[gkey] = token
            members[gkey] = set()
        acc.add(entry)
        members[gkey].add(entry.remote_host)

    for outcome in parser.parse_lines(read_many(paths)):
        total += 1
        entry = outcome.entry
        if entry is None:
            skipped += 1
            reasons[outcome.skip_reason or "unknown"] += 1
            continue
        parsed += 1
        network = egress.lookup(entry.remote_host)
        subnet = None if network is not None else datacenter_subnet(entry.remote_host)
        if network is not None:
            # A relay/proxy egress IP is a throwaway; fold by network + UA.
            fold(egress_acc, egress_token, egress_members, (network.name, entry.user_agent), entry)
            egress_tag.setdefault(network.name, network.tag)
        elif subnet is not None and not _declares_crawler(entry.user_agent):
            # An adjacent datacenter fleet (same /24 or /48 + UA) is one actor.
            # Declared crawlers are left out so they still reach DNS verification.
            fold(dc_acc, dc_token, dc_members, (subnet, entry.user_agent), entry)
        else:
            key = strategy.key(entry)
            acc = resident.get(key)
            if acc is None:
                acc = evictable.get(key)
                if acc is not None:
                    evictable.move_to_end(key)
            if acc is None and key in retired:
                # A dormant client is back: resume its accumulator, don't recount it.
                acc = retired.pop(key)
                evictable[key] = acc
            if acc is None:
                client_count += 1
                ip_refs[key.ip] += 1
                token = uas.product_token(entry.user_agent) if robots is not None else None
                tokens[key] = token
                check = _disallowed_check(robots, token) if robots is not None else None
                acc = FeatureAccumulator(disallowed_check=check)
                if quiescent_seconds is not None and not _declares_crawler(entry.user_agent):
                    evictable[key] = acc
                else:
                    resident[key] = acc
            acc.add(entry)

            agents = uas_by_ip.get(entry.remote_host)
            if agents is None:
                uas_by_ip[entry.remote_host] = {entry.user_agent}
            elif entry.user_agent not in agents:
                agents.add(entry.user_agent)
                if len(agents) == 2:
                    multi_ua_ips += 1

        if quiescent_seconds is not None and entry.timestamp is not None:
            ts = entry.timestamp.timestamp()
            if latest_ts is None or ts > latest_ts:
                latest_ts = ts
            evict(latest_ts - quiescent_seconds)

    # DNS-verify declared crawlers (all resident) as one deduped, concurrent batch.
    verifications: dict[ClientId, BotVerification] = {}
    member_ips: dict[ClientId, tuple[str, ...]] = {}
    if verifier is not None:
        candidates = [
            (key, acc.user_agent) for key, acc in resident.items() if verifier.needs(acc.user_agent)
        ]
        verifications = verifier.verify_all(candidates)
        member_ips = _merge_verified(resident, tokens, verifications)

    for key, acc in resident.items():
        emit(key, acc, verifications.get(key), member_ips.get(key, ()))
    for key, acc in evictable.items():
        emit(key, acc, None, ())
    for key, acc in retired.items():
        emit(key, acc, None, ())
    for (name, user_agent), acc in egress_acc.items():
        # One client per (network, UA), identified by the network, not an IP.
        eid = ClientId(ip=name, user_agent=user_agent)
        tokens[eid] = egress_token[(name, user_agent)]
        emit(
            eid,
            acc,
            None,
            tuple(sorted(egress_members[(name, user_agent)])),
            extra_tags=frozenset({egress_tag[name]}),
            network=name,
            network_category=_NET_EGRESS,
        )
        client_count += 1
    for (subnet, user_agent), acc in dc_acc.items():
        # One client per datacenter (subnet, UA); the subnet is its identity.
        did = ClientId(ip=subnet, user_agent=user_agent)
        tokens[did] = dc_token[(subnet, user_agent)]
        members = dc_members[(subnet, user_agent)]
        rep_ip = next(iter(members), "")  # any member resolves to the same provider
        emit(
            did,
            acc,
            None,
            tuple(sorted(members)),
            datacenter=True,
            network=datacenter_provider(rep_ip) or OTHER_HOSTING,
            network_category=_NET_DATACENTER,
        )
        client_count += 1

    profiles = [profile for heap in kept.values() for (_, _, profile) in heap]
    profiles.sort(key=lambda p: p.features.request_count, reverse=True)
    return AnalysisResult(
        profiles=tuple(profiles),
        skips=SkipStats(total, parsed, skipped, dict(reasons)),
        identity_strategy=strategy.name,
        identity_stats=IdentityStats(client_count, singleton_count, multi_ua_ips),
        rollups={kind: acc.freeze() for kind, acc in rollups.items()},
        network_rollups={
            net: {kind: acc.freeze() for kind, acc in kinds.items()}
            for net, kinds in net_rollups.items()
        },
        network_categories=dict(net_categories),
    )


def collect_entries(
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    profiles: Sequence[ClientProfile],
) -> dict[ClientId, tuple[LogEntry, ...]]:
    """Re-read the logs, keeping raw entries only for the given client profiles.

    Used by ``inspect`` after analysis has identified which clients to show, so
    only the selected clients' requests are held in memory. A merged verified-bot
    profile is matched by its member IPs rather than by the identity key.
    """
    if not profiles:
        return {}
    paths = [logs] if isinstance(logs, Path) else list(logs)
    by_key = {p.client_id: p for p in profiles if not p.member_ips}
    by_ip = {ip: p for p in profiles for ip in p.member_ips}
    buckets: dict[ClientId, list[LogEntry]] = {p.client_id: [] for p in profiles}
    for outcome in parser.parse_lines(read_many(paths)):
        entry = outcome.entry
        if entry is None:
            continue
        profile = by_key.get(strategy.key(entry)) or by_ip.get(entry.remote_host)
        if profile is not None:
            buckets[profile.client_id].append(entry)
    return {cid: tuple(entries) for cid, entries in buckets.items()}
