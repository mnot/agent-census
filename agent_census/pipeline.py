"""Orchestration: parse -> accumulate per client -> classify -> profiles.

This is the seam that turns log files into a list of :class:`ClientProfile`. It
streams: each parsed line is folded into its client's feature accumulator and
discarded, so peak memory is bounded by the number of distinct clients (plus a
compact per-client accumulator), not the number of log lines. Raw entries are
never retained here -- ``inspect`` collects them for the selected clients in a
cheap second pass via :func:`collect_entries`.
"""

from __future__ import annotations

import heapq
import itertools
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Protocol

from . import egress, uas
from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .classify.relative import (
    ReferenceCalibration,
    load_relative_tags,
    make_collector,
    tag_profile,
)
from .dataload import CrawlerSpec
from .features import DisallowedCheck, FeatureAccumulator
from .hosting import (
    asn_for_ip,
    datacenter_provider,
    datacenter_provider_for_asn,
    datacenter_subnet,
    subnet_of,
)
from .identity import ClientKeyStrategy
from .logsource import order_logs, read_many
from .maxmind import AsnResolver
from .model import (
    BotVerification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    Kind,
    LogEntry,
    RobotsVerdict,
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
_CRAWLER_CATEGORIES = (
    "search_engine",
    "social_preview",
    "archiver",
    "ai_crawler",
    "seo_marketing",
    "data_harvester",
)

# Network buckets for the kind x network cross-tab. A client's network is the
# hosting provider its IP belongs to, the shared-egress network it came through,
# or this catch-all for everything else (ISPs, mobile, unknown).
RESIDENTIAL_NETWORK = "Residential / unknown"
# Fallback provider label, and the column the report collapses the long tail into.
OTHER_HOSTING = "Other datacenters"
_NET_DATACENTER = "datacenter"
_NET_EGRESS = "egress"
_NET_RESIDENTIAL = "residential"


def _hosting_provider(rep_ip: str, as_number: str | None) -> str | None:
    """The hosting provider for a client -- by IP range, else by its AS number.

    Folded entries key on a subnet/label rather than a real IP, and a provider
    may be known only by ASN (e.g. Hetzner, whose ranges aren't bundled), so the
    AS fallback is what keeps such a client on the hosting side.
    """
    return datacenter_provider(rep_ip) or datacenter_provider_for_asn(uas.parse_asn(as_number))


def _logged_asn(entry: LogEntry) -> str | None:
    """The AS number a log line carries (MM_ASN / ClientASN / ...), or None."""
    for key, value in entry.extra.items():
        name = key.lower().split(":", 1)[-1]
        if value and ("asn" in name or "autonomous_system_number" in name):
            return value
    return None


def _vhost_of(entry: LogEntry) -> str | None:
    """The virtual host a line was served for: the logged ``%v``, else the Host header."""
    return entry.extra.get("server_name") or entry.host_header


def _excluded_by_vhost(entry: LogEntry, vhosts: Sequence[str] | None) -> bool:
    """True if a ``--vhost`` filter is set and this line matches none of its terms."""
    if not vhosts:
        return False
    served = _vhost_of(entry)
    if served is None:
        return True
    low = served.lower()
    return not any(term.lower() in low for term in vhosts)


def _asn_of(entry: LogEntry, ip: str) -> str | None:
    """The AS number for a line: what the log carries, else recovered by IP feed."""
    logged = _logged_asn(entry)
    if logged is not None:
        return logged
    recovered = asn_for_ip(ip)
    return str(recovered) if recovered is not None else None


def _declared_spec(ua: str | None) -> tuple[str, CrawlerSpec] | None:
    """First ``(token, spec)`` whose token the UA declares, across crawler kinds."""
    for category in _CRAWLER_CATEGORIES:
        known = uas.match_category(ua, category)
        if known is not None:
            return known
    return None


def _verifiable(spec: CrawlerSpec) -> bool:
    """True if a declared crawler can be DNS/range-verified (so keep it per-IP)."""
    return bool(spec.domains or spec.ranges or spec.ranges_url)


def _resolve_asn_verification(
    verification: BotVerification | None, features: ClientFeatures
) -> BotVerification | None:
    """Apply the offline ASN verification tier, below ranges/rDNS in precedence.

    A declared crawler whose logged origin AS is in its agent's ``asns`` is
    corroborated (``ASN_ASSOCIATED``); one whose logged AS is *not* in the list is
    an impersonator. Consulted only when the network tiers didn't decide (no
    ranges/rDNS, or they were inconclusive) and the log carries an AS number --
    absence of an AS number is never read as impersonation.
    """
    if verification is not None and verification.status in (
        VerificationStatus.VERIFIED,
        VerificationStatus.IMPERSONATOR,
    ):
        return verification  # a definitive ranges/rDNS verdict takes precedence
    declared = _declared_spec(features.user_agent)
    if declared is None:
        return verification
    token, spec = declared
    if not spec.asns:
        return verification
    asn = uas.parse_asn(features.as_number)
    if asn is None:
        return verification  # nothing to check against; leave it unverified
    if asn in spec.asns:
        return BotVerification(
            VerificationStatus.ASN_ASSOCIATED,
            evidence=(f"origin AS{asn} is a network that {token} crawls from",),
        )
    return BotVerification(
        VerificationStatus.IMPERSONATOR,
        evidence=(f"User-Agent claims {token}, but origin AS{asn} is not one it crawls from",),
    )


class BotVerifier(Protocol):
    """Verifies declared crawlers (implemented by :class:`agent_census.netverify.BotVerifier`)."""

    def needs(self, ua: str | None) -> bool: ...

    def verify_all(
        self, items: Sequence[tuple[ClientId, str | None]]
    ) -> dict[ClientId, BotVerification]: ...


@dataclass(frozen=True, slots=True)
class SkipStats:
    """How many lines parsed vs. were skipped, and why.

    ``excluded`` counts lines dropped on purpose by a ``--vhost`` filter -- kept
    separate from ``skipped`` (parse failures), so a deliberate filter never
    inflates the unparse rate, which is itself a diagnostic. ``out_of_window``
    counts lines dropped by a ``--since`` time filter, for the same reason (it is
    only the lines from *read* files; whole files skipped before reading are not
    counted here).
    """

    total_lines: int
    parsed: int
    skipped: int
    reasons: dict[str, int] = field(default_factory=dict)
    excluded: int = 0
    out_of_window: int = 0


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
    # Robots checked but the verdict was UNKNOWN -- too little activity to judge
    # (or no applicable rule). Counted only when robots data is present, so when
    # it is, respects + ignores + unknown == clients.
    unknown_robots: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class _RollupAcc:
    """Mutable per-kind accumulator, frozen into a :class:`KindRollup` at the end."""

    __slots__ = (
        "clients", "requests", "total_bytes", "respects", "ignores", "unknown",
        "first_seen", "last_seen",
    )  # fmt: skip

    def __init__(self) -> None:
        self.clients = self.requests = self.total_bytes = 0
        self.respects = self.ignores = self.unknown = 0
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None

    def add(
        self, features: ClientFeatures, *, respects: bool, ignores: bool, unknown: bool
    ) -> None:
        self.clients += 1
        self.requests += features.request_count
        self.total_bytes += features.total_bytes
        # Robots compliance is counted from the verdict, not a tag: respecting is
        # the quiet norm, so it carries no per-client tag, only this aggregate.
        if respects:
            self.respects += 1
        elif ignores:
            self.ignores += 1
        elif unknown:
            self.unknown += 1
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
            unknown_robots=self.unknown,
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
    # Basenames of input files skipped unread because they fell entirely before a
    # --since window (see :func:`order_logs`). Reported so a dropped file is never
    # silent: its lines are in none of the counts above precisely because it was
    # never read. Empty without --since.
    skipped_files: tuple[str, ...] = ()
    # The site analysed: the first --vhost if one was given, else the most common
    # served host (logged %v, else the Host header). None if the log carries none.
    site: str | None = None
    # Site-relative tag calibration: the reference-browser pool sizes and the
    # per-metric thresholds derived from them. None only when no analysis ran.
    reference_calibration: ReferenceCalibration | None = None


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


def analyze(  # pylint: disable=too-many-locals,too-many-statements,too-many-arguments
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
    vhosts: Sequence[str] | None = None,
    asn_resolver: AsnResolver | None = None,
    since_seconds: float | None = None,
    from_latest: bool = False,
    now: float | None = None,
) -> AnalysisResult:
    """Stream one or more log files into per-client profiles.

    Multiple files are sorted into chronological order (by each file's first
    timestamp; see :func:`order_logs`) and read as one pooled stream, so a client
    that appears across rotated logs is treated as one and timing metrics see
    requests in time order regardless of the order the files were given. Entries
    are not retained; pass the result to :func:`collect_entries` if you need raw
    request traces.

    ``since_seconds`` keeps only requests newer than that span, dropping older
    ones and skipping any log file that falls entirely before the window without
    reading it. The window is anchored at ``now`` (wall clock) by default, or at
    the newest log timestamp when ``from_latest``.

    With ``quiescent_seconds`` set, a client that has been silent for that long
    (relative to the latest log timestamp) is finalised and its live accumulator
    freed mid-stream, so peak memory tracks the active window rather than the
    whole run. Declared crawlers are kept resident so their IPs can still be
    merged. ``keep_signals=False`` drops per-client classifier signals (only
    inspect reads them).

    ``vhosts`` scopes the analysis to one or more virtual hosts: a line whose
    served vhost (logged ``%v``, else the Host header) contains none of the given
    substrings is excluded before grouping and tallied in ``SkipStats.excluded``
    -- useful when one server's log mixes several sites (e.g. a slice proxied
    through a CDN under another name).
    """
    paths = [logs] if isinstance(logs, Path) else list(logs)
    ordered, window_start = order_logs(
        paths, parser, since_seconds=since_seconds, from_latest=from_latest, now=now
    )
    kept_paths = set(ordered)
    skipped_files = tuple(p.name for p in paths if p not in kept_paths)
    paths = ordered
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
    egress_group: dict[str, str] = {}  # network name -> cross-tab column header
    # Datacenter clients sharing a /24 (or /48) and UA are lumped into one entry,
    # keyed by (subnet, UA), the same way -- an adjacent VM fleet is one actor.
    dc_acc: OrderedDict[tuple[str, str | None], FeatureAccumulator] = OrderedDict()
    dc_token: dict[tuple[str, str | None], str | None] = {}
    dc_members: dict[tuple[str, str | None], set[str]] = {}
    # A recognised ASN operator (e.g. Sberbank) collapses to ONE entry across all
    # its IPs and UAs -- the AS is the identity. Keyed by (label, None).
    asn_acc: OrderedDict[tuple[str, str | None], FeatureAccumulator] = OrderedDict()
    asn_token: dict[tuple[str, str | None], str | None] = {}
    asn_members: dict[tuple[str, str | None], set[str]] = {}
    asn_number: dict[str, str] = {}  # label -> its AS number, for classification
    # A declared crawler we can't verify per-IP folds by (token, /24-or-/48): a
    # forgeable UA only earns network-level collapse, not internet-wide.
    cr_acc: OrderedDict[tuple[str, str | None], FeatureAccumulator] = OrderedDict()
    cr_token: dict[tuple[str, str | None], str | None] = {}
    cr_members: dict[tuple[str, str | None], set[str]] = {}
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
    # Site-relative tags: sample every client's metrics into the reference-browser
    # pool as it streams past emit(), then calibrate and tag once at the end.
    rel_config = load_relative_tags()
    collector = make_collector()
    seq = itertools.count()
    total = parsed = skipped = excluded = out_of_window = 0
    client_count = singleton_count = multi_ua_ips = 0
    host_counts: Counter[str] = Counter()  # served host -> line count, for the site label
    latest_ts: float | None = None
    reasons: dict[str, int] = defaultdict(int)

    def emit(
        key: ClientId,
        acc: FeatureAccumulator,
        verification: BotVerification | None,
        member: tuple[str, ...],
        extra_tags: frozenset[str] = frozenset(),
        extra_tag_evidence: tuple[tuple[str, str], ...] = (),
        datacenter: bool | None = None,
        network: str | None = None,
        network_category: str | None = None,
        force_asn: str | None = None,
    ) -> None:
        nonlocal singleton_count
        ua_count = len(uas_by_ip.get(key.ip) or (None,))
        features = acc.finalize(ua_count_for_ip=ua_count)
        if force_asn is not None:
            features = replace(features, as_number=force_asn)
        if asn_resolver is not None:
            # The MaxMind DB wins when it has an answer -- it can be fresher than an
            # old log. Synthetic folded keys (a subnet/egress/ASN-collapsed client)
            # aren't real IPs, so the resolver returns nothing and leaves them be.
            db_asn, db_org = asn_resolver.lookup(key.ip)
            if db_asn is not None:
                features = replace(
                    features, as_number=str(db_asn), as_org=db_org or features.as_org
                )
        if not features.as_number:
            # No logged or DB AS; recover it from the IP via a crawler ASN's published
            # prefixes (so ASN recognition, attribution, and the tag work without
            # %{MM_ASN}e). Folded keys aren't real IPs.
            asn = asn_for_ip(key.ip)
            if asn is not None:
                features = replace(features, as_number=str(asn))
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
                provider = datacenter_provider_for_asn(uas.parse_asn(features.as_number))
            asn_agent = uas.match_asn_any(features.as_number)
            if provider is not None:
                network, network_category = provider, _NET_DATACENTER
            elif asn_agent is not None:
                # An ASN-recognised crawler network (e.g. Sberbank). Name it on the
                # hosting side of the cross-tab rather than letting it fall through
                # to residential; classification is the ASN classifier's job.
                network, network_category = asn_agent, _NET_DATACENTER
            elif verification is not None and verification.status is VerificationStatus.VERIFIED:
                # A verified crawler runs from its operator's own infrastructure --
                # implicitly hosted, even when that IP/ASN isn't in our provider
                # lists. Bucket it under the operator (its verified domain), in the
                # hosting group; the small ones fold into "Other datacenters" like any
                # datacenter. Classification is left untouched.
                network, network_category = _matched_domain(verification), _NET_DATACENTER
            else:
                network, network_category = RESIDENTIAL_NETWORK, _NET_RESIDENTIAL
        # The datacenter tag follows the hosting attribution: a provider (by IP
        # range or AS), a recognised crawler ASN, or a verified crawler's own
        # infrastructure all count as hosted. An explicit datacenter= wins.
        in_datacenter = (
            datacenter if datacenter is not None else network_category == _NET_DATACENTER
        )
        # An egress fold folds many independent clients (relay/VPN users) into one
        # display row past their throwaway IPs; it is not a single client. Per-client
        # behavioural signals don't apply to it -- suppress its cadence and magnitude
        # tags, and keep it out of the reference-browser pool.
        aggregate = network_category == _NET_EGRESS
        verification = _resolve_asn_verification(verification, features)
        classification = classify_client(
            features,
            compliance=compliance,
            verification=verification,
            datacenter=in_datacenter,
            aggregate=aggregate,
            unknown_threshold=unknown_threshold,
            keep_signals=keep_signals,
        )
        if extra_tags:
            classification = replace(
                classification,
                tags=classification.tags | extra_tags,
                tag_evidence=classification.tag_evidence
                + (extra_tag_evidence if keep_signals else ()),
            )
        # Sample this client into the reference pool (browsers only qualify). Done
        # for every emitted single client, so the distribution is eviction-safe and
        # not limited to the capped `kept` heap. An egress fold is excluded: it is
        # many clients in one row, and a relay-fronted browser bucket would otherwise
        # pass the browser test and inflate the duration / rate thresholds it sets.
        if not aggregate:
            collector.observe(features)
        profile = ClientProfile(
            client_id=key,
            entries=(),
            features=features,
            classification=classification,
            compliance=compliance,
            verification=verification,
            member_ips=member,
            network=network,
            is_aggregate=aggregate,
        )
        kind = classification.primary
        verdict = compliance.verdict if compliance is not None else None
        respects = verdict is RobotsVerdict.RESPECTS
        ignores = verdict is RobotsVerdict.IGNORES
        unknown_r = verdict is RobotsVerdict.UNKNOWN
        rollups[kind].add(features, respects=respects, ignores=ignores, unknown=unknown_r)
        net_rollups[network][kind].add(
            features, respects=respects, ignores=ignores, unknown=unknown_r
        )
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

    def route_regular(entry: LogEntry, declared: bool) -> None:
        """Group a non-folded request the ordinary way (resident/evictable/retired)."""
        nonlocal client_count, multi_ua_ips
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
            if quiescent_seconds is not None and not declared:
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

    for outcome in parser.parse_lines(read_many(paths)):
        total += 1
        entry = outcome.entry
        if entry is None:
            skipped += 1
            reasons[outcome.skip_reason or "unknown"] += 1
            continue
        if (
            window_start is not None
            and entry.timestamp is not None
            and entry.timestamp.timestamp() < window_start
        ):
            # Older than the --since window; a straddling file is read but trimmed
            # here (whole files before the window were skipped in order_logs).
            out_of_window += 1
            continue
        if _excluded_by_vhost(entry, vhosts):
            excluded += 1
            continue
        parsed += 1
        served = _vhost_of(entry)
        if served:
            host_counts[served] += 1
        ip, ua = entry.remote_host, entry.user_agent
        asn = _asn_of(entry, ip)
        # Egress by IP range, else by AS number (VPNs/proxies that publish no list).
        network = egress.lookup(ip) or egress.lookup_asn(uas.parse_asn(asn))
        entity = uas.match_asn_any(asn)
        crawler = _declared_spec(ua)
        if network is not None:
            # A relay/proxy egress IP is a throwaway; fold by network + UA.
            fold(egress_acc, egress_token, egress_members, (network.name, ua), entry)
            egress_tag.setdefault(network.name, network.tag)
            egress_group.setdefault(network.name, network.group or network.name)
        elif entity is not None and asn is not None:
            # A recognised ASN operator: one entry for the whole AS, IP and UA alike.
            fold(asn_acc, asn_token, asn_members, (entity, None), entry)
            asn_number[entity] = asn
        elif crawler is not None and (verifier is None or not _verifiable(crawler[1])):
            # A declared crawler we can't verify per-IP: collapse by (/24-or-/48, token).
            fold(cr_acc, cr_token, cr_members, (subnet_of(ip) or ip, crawler[0]), entry)
        elif crawler is None and (subnet := datacenter_subnet(ip)) is not None:
            # An adjacent datacenter fleet (same /24 or /48 + UA) is one actor.
            fold(dc_acc, dc_token, dc_members, (subnet, ua), entry)
        else:
            route_regular(entry, crawler is not None)

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
            extra_tag_evidence=(
                (
                    egress_tag[name],
                    f"requests folded under shared-egress network {egress_group[name]} "
                    "(privacy relay / proxy)",
                ),
            ),
            network=egress_group[name],
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
    for (label, _), acc in asn_acc.items():
        # A recognised ASN operator: one entry for the whole AS, identified by the
        # operator label, not an IP. Forcing the AS number drives classification
        # (the ASN classifier) and lets emit name the network on the hosting side.
        aid = ClientId(ip=label, user_agent=None)
        tokens[aid] = asn_token[(label, None)]
        emit(
            aid,
            acc,
            None,
            tuple(sorted(asn_members[(label, None)])),
            force_asn=asn_number[label],
        )
        client_count += 1
    for (subnet, token), acc in cr_acc.items():
        # A declared but unverifiable crawler: one entry per (subnet, token). The
        # subnet is the identity; UA variants within it have already collapsed.
        cid = ClientId(ip=subnet, user_agent=acc.user_agent)
        tokens[cid] = cr_token[(subnet, token)]
        members = cr_members[(subnet, token)]
        rep_ip = next(iter(members), "")  # any member resolves to the same provider
        # By IP range, else by AS number -- so an AS-only datacenter (Hetzner) is
        # recognised as hosting, not left residential, and gets the datacenter tag.
        provider = _hosting_provider(rep_ip, acc.as_number)
        emit(
            cid,
            acc,
            None,
            tuple(sorted(members)),
            datacenter=provider is not None,
            network=provider or RESIDENTIAL_NETWORK,
            network_category=_NET_DATACENTER if provider else _NET_RESIDENTIAL,
        )
        client_count += 1

    # Calibrate the reference pool, then fold site-relative tags into the kept
    # profiles. A cheap in-memory pass: only kept profiles are shown, and all are
    # resident now, so no second read of the log.
    calibration = collector.calibrate(rel_config.params)
    profiles = [
        tag_profile(profile, rel_config, calibration, keep_evidence=keep_signals)
        for heap in kept.values()
        for (_, _, profile) in heap
    ]
    profiles.sort(key=lambda p: p.features.request_count, reverse=True)
    if vhosts:
        site: str | None = vhosts[0]
    else:
        top = host_counts.most_common(1)
        site = top[0][0] if top else None
    return AnalysisResult(
        profiles=tuple(profiles),
        skips=SkipStats(total, parsed, skipped, dict(reasons), excluded, out_of_window),
        identity_strategy=strategy.name,
        identity_stats=IdentityStats(client_count, singleton_count, multi_ua_ips),
        rollups={kind: acc.freeze() for kind, acc in rollups.items()},
        network_rollups={
            net: {kind: acc.freeze() for kind, acc in kinds.items()}
            for net, kinds in net_rollups.items()
        },
        network_categories=dict(net_categories),
        skipped_files=skipped_files,
        site=site,
        reference_calibration=calibration,
    )


def collect_entries(
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    profiles: Sequence[ClientProfile],
    vhosts: Sequence[str] | None = None,
    since_seconds: float | None = None,
    from_latest: bool = False,
    now: float | None = None,
) -> dict[ClientId, tuple[LogEntry, ...]]:
    """Re-read the logs, keeping raw entries only for the given client profiles.

    Used by ``inspect`` after analysis has identified which clients to show, so
    only the selected clients' requests are held in memory. A merged verified-bot
    profile is matched by its member IPs rather than by the identity key. ``vhosts``
    and the ``since_seconds`` / ``from_latest`` / ``now`` time window apply the same
    filters :func:`analyze` did, so a trace never picks up lines the analysis
    excluded. Pass the same ``now`` the analysis used so the window doesn't drift.
    """
    if not profiles:
        return {}
    paths = [logs] if isinstance(logs, Path) else list(logs)
    paths, window_start = order_logs(
        paths, parser, since_seconds=since_seconds, from_latest=from_latest, now=now
    )
    by_key = {p.client_id: p for p in profiles if not p.member_ips}
    by_ip = {ip: p for p in profiles for ip in p.member_ips}
    buckets: dict[ClientId, list[LogEntry]] = {p.client_id: [] for p in profiles}
    for outcome in parser.parse_lines(read_many(paths)):
        entry = outcome.entry
        if entry is None or _excluded_by_vhost(entry, vhosts):
            continue
        if (
            window_start is not None
            and entry.timestamp is not None
            and entry.timestamp.timestamp() < window_start
        ):
            continue
        profile = by_key.get(strategy.key(entry)) or by_ip.get(entry.remote_host)
        if profile is not None:
            buckets[profile.client_id].append(entry)
    return {cid: tuple(entries) for cid, entries in buckets.items()}
