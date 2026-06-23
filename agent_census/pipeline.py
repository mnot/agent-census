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
from collections import OrderedDict, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import uas
from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .dataload import load_tokens
from .features import DisallowedCheck, FeatureAccumulator
from .identity import ClientKeyStrategy
from .model import BotVerification, ClientId, ClientProfile, LogEntry, VerificationStatus
from .parsing.base import LogParser
from .robots import RobotsRules, report_from_signals

# Default inactivity gap after which a client is considered finished and evicted.
DEFAULT_QUIESCENT_SECONDS = 24 * 60 * 60

_CRAWLER_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] | None = None


def _declares_crawler(ua: str | None) -> bool:
    """True if the UA names any known crawler (kept resident, never evicted)."""
    global _CRAWLER_TOKENS  # pylint: disable=global-statement
    if _CRAWLER_TOKENS is None:
        _CRAWLER_TOKENS = (
            load_tokens("search_engines.txt")
            + load_tokens("social_preview.txt")
            + load_tokens("ai_crawlers.txt")
            + load_tokens("seo_marketing.txt")
        )
    return uas.match_known(ua, _CRAWLER_TOKENS) is not None


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
class AnalysisResult:
    """The full output of an analysis run."""

    profiles: tuple[ClientProfile, ...]
    skips: SkipStats
    identity_strategy: str
    identity_stats: IdentityStats


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


def analyze(  # pylint: disable=too-many-locals
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    *,
    robots: RobotsRules | None = None,
    verifier: BotVerifier | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
    quiescent_seconds: float | None = None,
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
    tokens: dict[ClientId, str | None] = {}
    uas_by_ip: dict[str, set[str | None]] = {}
    ip_refs: dict[str, int] = defaultdict(int)
    profiles: list[ClientProfile] = []
    total = parsed = skipped = 0
    client_count = singleton_count = multi_ua_ips = 0
    latest_ts: float | None = None
    reasons: dict[str, int] = defaultdict(int)

    def emit(
        key: ClientId,
        acc: FeatureAccumulator,
        verification: BotVerification | None,
        member: tuple[str, ...],
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
        classification = classify_client(
            features,
            compliance=compliance,
            verification=verification,
            unknown_threshold=unknown_threshold,
            keep_signals=keep_signals,
        )
        profiles.append(
            ClientProfile(
                client_id=key,
                entries=(),
                features=features,
                classification=classification,
                compliance=compliance,
                verification=verification,
                member_ips=member,
            )
        )

    def evict(cutoff: float) -> None:
        while evictable:
            key = next(iter(evictable))
            last_seen = evictable[key].last_seen
            if last_seen is None or last_seen.timestamp() >= cutoff:
                break
            _, acc = evictable.popitem(last=False)
            emit(key, acc, None, ())
            tokens.pop(key, None)
            remaining = ip_refs.get(key.ip, 0) - 1
            if remaining <= 0:
                ip_refs.pop(key.ip, None)
                uas_by_ip.pop(key.ip, None)
            else:
                ip_refs[key.ip] = remaining

    for outcome in parser.parse_lines(read_many(paths)):
        total += 1
        entry = outcome.entry
        if entry is None:
            skipped += 1
            reasons[outcome.skip_reason or "unknown"] += 1
            continue
        parsed += 1
        key = strategy.key(entry)
        acc = resident.get(key)
        if acc is None:
            acc = evictable.get(key)
            if acc is not None:
                evictable.move_to_end(key)
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

    profiles.sort(key=lambda p: p.features.request_count, reverse=True)
    return AnalysisResult(
        profiles=tuple(profiles),
        skips=SkipStats(total, parsed, skipped, dict(reasons)),
        identity_strategy=strategy.name,
        identity_stats=IdentityStats(client_count, singleton_count, multi_ua_ips),
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
