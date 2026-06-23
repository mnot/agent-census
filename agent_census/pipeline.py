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
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import uas
from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .features import DisallowedCheck, FeatureAccumulator
from .identity import ClientKeyStrategy
from .model import BotVerification, ClientId, ClientProfile, LogEntry, VerificationStatus
from .parsing.base import LogParser
from .robots import RobotsRules, report_from_signals


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


def _identity_stats(
    accumulators: dict[ClientId, FeatureAccumulator], uas_by_ip: dict[str, set[str | None]]
) -> IdentityStats:
    singletons = sum(1 for acc in accumulators.values() if acc.count == 1)
    multi = sum(1 for agents in uas_by_ip.values() if len(agents) > 1)
    return IdentityStats(len(accumulators), singletons, multi)


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


def analyze(
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    *,
    robots: RobotsRules | None = None,
    verifier: BotVerifier | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
) -> AnalysisResult:
    """Stream one or more log files into per-client profiles.

    Multiple files are read in order as one stream and pooled, so a client that
    appears across rotated logs is treated as one. Entries are not retained;
    pass the result to :func:`collect_entries` if you need raw request traces.
    ``keep_signals=False`` drops the per-client classifier signals (which only
    inspect mode reads), saving memory on the analyze path.
    """
    paths = [logs] if isinstance(logs, Path) else list(logs)
    accumulators: dict[ClientId, FeatureAccumulator] = {}
    tokens: dict[ClientId, str | None] = {}
    uas_by_ip: dict[str, set[str | None]] = defaultdict(set)
    total = parsed = skipped = 0
    reasons: dict[str, int] = defaultdict(int)

    for outcome in parser.parse_lines(read_many(paths)):
        total += 1
        entry = outcome.entry
        if entry is None:
            skipped += 1
            reasons[outcome.skip_reason or "unknown"] += 1
            continue
        parsed += 1
        key = strategy.key(entry)
        accumulator = accumulators.get(key)
        if accumulator is None:
            token = uas.product_token(entry.user_agent) if robots is not None else None
            tokens[key] = token
            check = _disallowed_check(robots, token) if robots is not None else None
            accumulator = accumulators[key] = FeatureAccumulator(disallowed_check=check)
        accumulator.add(entry)
        uas_by_ip[entry.remote_host].add(entry.user_agent)

    skips = SkipStats(total, parsed, skipped, dict(reasons))
    identity_stats = _identity_stats(accumulators, uas_by_ip)
    ua_counts = {ip: len(agents) for ip, agents in uas_by_ip.items()}

    # DNS-verify declared crawlers as one deduped, concurrent batch.
    verifications: dict[ClientId, BotVerification] = {}
    member_ips: dict[ClientId, tuple[str, ...]] = {}
    if verifier is not None:
        candidates = [
            (key, acc.user_agent)
            for key, acc in accumulators.items()
            if verifier.needs(acc.user_agent)
        ]
        verifications = verifier.verify_all(candidates)
        # Collapse each verified bot's many IPs into one entry keyed by its domain.
        member_ips = _merge_verified(accumulators, tokens, verifications)

    profiles: list[ClientProfile] = []
    while accumulators:
        key, accumulator = accumulators.popitem()
        features = accumulator.finalize(ua_count_for_ip=ua_counts.get(key.ip, 1))
        compliance = None
        if robots is not None:
            compliance = report_from_signals(
                robots,
                tokens.get(key),
                disallowed_hits=accumulator.disallowed_hits,
                sample_disallowed=tuple(accumulator.disallowed_sample or ()),
                fetched_robots_first=accumulator.robots_fetched_first,
                fetched_robots_txt=features.fetched_robots_txt,
                request_count=features.request_count,
                median_interval=features.inter_arrival_median,
            )
        verification = verifications.get(key)
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
                member_ips=member_ips.get(key, ()),
            )
        )

    profiles.sort(key=lambda p: p.features.request_count, reverse=True)
    return AnalysisResult(
        profiles=tuple(profiles),
        skips=skips,
        identity_strategy=strategy.name,
        identity_stats=identity_stats,
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
