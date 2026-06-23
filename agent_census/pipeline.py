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
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import uas
from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .features import DisallowedCheck, FeatureAccumulator
from .identity import ClientKeyStrategy
from .model import BotVerification, ClientFeatures, ClientId, ClientProfile, LogEntry
from .parsing.base import LogParser
from .robots import RobotsRules, report_from_signals

VerifyFn = Callable[[ClientId, ClientFeatures], BotVerification | None]


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


def analyze(
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    *,
    robots: RobotsRules | None = None,
    verify_fn: VerifyFn | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
) -> AnalysisResult:
    """Stream one or more log files into per-client profiles.

    Multiple files are read in order as one stream and pooled, so a client that
    appears across rotated logs is treated as one. Entries are not retained;
    pass the result to :func:`collect_entries` if you need raw request traces.
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
        verification = verify_fn(key, features) if verify_fn else None
        classification = classify_client(
            features,
            compliance=compliance,
            verification=verification,
            unknown_threshold=unknown_threshold,
        )
        profiles.append(
            ClientProfile(
                client_id=key,
                entries=(),
                features=features,
                classification=classification,
                compliance=compliance,
                verification=verification,
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
    keys: set[ClientId],
) -> dict[ClientId, tuple[LogEntry, ...]]:
    """Re-read the logs, keeping raw entries only for the given client keys.

    Used by ``inspect`` after analysis has identified which clients to show, so
    only the selected clients' requests are held in memory.
    """
    if not keys:
        return {}
    paths = [logs] if isinstance(logs, Path) else list(logs)
    collected: dict[ClientId, list[LogEntry]] = {key: [] for key in keys}
    for outcome in parser.parse_lines(read_many(paths)):
        entry = outcome.entry
        if entry is None:
            continue
        key = strategy.key(entry)
        bucket = collected.get(key)
        if bucket is not None:
            bucket.append(entry)
    return {key: tuple(entries) for key, entries in collected.items()}
