"""Orchestration: parse -> group -> features -> classify -> profiles.

This is the seam that turns a log file into a list of :class:`ClientProfile`.
robots-compliance and bot-verification are injected as optional callables so the
pipeline stays independent of how they are obtained (local file vs network).
"""

from __future__ import annotations

import gzip
from collections import defaultdict
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .classify import DEFAULT_UNKNOWN_THRESHOLD, classify_client
from .features import extract_features
from .identity import ClientKeyStrategy
from .model import (
    BotVerification,
    ClientFeatures,
    ClientId,
    ClientProfile,
    ComplianceReport,
    LogEntry,
)
from .parsing.base import LogParser

ComplianceFn = Callable[[ClientId, Sequence[LogEntry], ClientFeatures], ComplianceReport | None]
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


def group_entries(
    parser: LogParser, lines: Iterator[str], strategy: ClientKeyStrategy
) -> tuple[dict[ClientId, list[LogEntry]], SkipStats]:
    """Parse lines and group successful entries by client identity."""
    grouped: dict[ClientId, list[LogEntry]] = defaultdict(list)
    total = parsed = skipped = 0
    reasons: dict[str, int] = defaultdict(int)
    for outcome in parser.parse_lines(lines):
        total += 1
        if outcome.entry is None:
            skipped += 1
            reasons[outcome.skip_reason or "unknown"] += 1
            continue
        parsed += 1
        grouped[strategy.key(outcome.entry)].append(outcome.entry)
    return grouped, SkipStats(total, parsed, skipped, dict(reasons))


def _ua_counts_by_ip(grouped: dict[ClientId, list[LogEntry]]) -> dict[str, int]:
    """Map each connecting IP to the number of distinct UAs seen from it."""
    uas_by_ip: dict[str, set[str | None]] = defaultdict(set)
    for entries in grouped.values():
        for entry in entries:
            uas_by_ip[entry.remote_host].add(entry.user_agent)
    return {ip: len(uas) for ip, uas in uas_by_ip.items()}


def _identity_stats(grouped: dict[ClientId, list[LogEntry]]) -> IdentityStats:
    singletons = sum(1 for entries in grouped.values() if len(entries) == 1)
    multi = sum(1 for count in _ua_counts_by_ip(grouped).values() if count > 1)
    return IdentityStats(len(grouped), singletons, multi)


def build_profiles(
    grouped: dict[ClientId, list[LogEntry]],
    *,
    keep_entries: bool = True,
    compliance_fn: ComplianceFn | None = None,
    verify_fn: VerifyFn | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
) -> list[ClientProfile]:
    """Extract features, classify, and assemble a profile for each client.

    The grouping dict is drained as it goes, so each client's entries become
    collectable once its features are computed. With ``keep_entries=False`` (the
    default for ``analyze``, which never shows raw requests) the entries are not
    retained at all, keeping only the compact features and verdict.
    """
    ua_counts = _ua_counts_by_ip(grouped)
    profiles: list[ClientProfile] = []
    while grouped:
        client_id, entries = grouped.popitem()
        features = extract_features(entries, ua_count_for_ip=ua_counts.get(client_id.ip, 1))
        compliance = compliance_fn(client_id, entries, features) if compliance_fn else None
        verification = verify_fn(client_id, features) if verify_fn else None
        classification = classify_client(
            features,
            compliance=compliance,
            verification=verification,
            unknown_threshold=unknown_threshold,
        )
        profiles.append(
            ClientProfile(
                client_id=client_id,
                entries=tuple(entries) if keep_entries else (),
                features=features,
                classification=classification,
                compliance=compliance,
                verification=verification,
            )
        )
    return profiles


def analyze(
    logs: Path | Sequence[Path],
    parser: LogParser,
    strategy: ClientKeyStrategy,
    *,
    keep_entries: bool = True,
    compliance_fn: ComplianceFn | None = None,
    verify_fn: VerifyFn | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
) -> AnalysisResult:
    """Run the full pipeline over one or more log files.

    Multiple files are read in order as a single stream and pooled before
    grouping, so a client that appears across rotated logs is treated as one.
    Pass ``keep_entries=False`` when the raw request traces are not needed (the
    ``analyze`` report) to avoid retaining every parsed entry.
    """
    paths = [logs] if isinstance(logs, Path) else list(logs)
    grouped, skips = group_entries(parser, read_many(paths), strategy)
    # Identity stats must be read before build_profiles drains the dict.
    identity_stats = _identity_stats(grouped)
    profiles = build_profiles(
        grouped,
        keep_entries=keep_entries,
        compliance_fn=compliance_fn,
        verify_fn=verify_fn,
        unknown_threshold=unknown_threshold,
    )
    profiles.sort(key=lambda p: p.features.request_count, reverse=True)
    return AnalysisResult(
        profiles=tuple(profiles),
        skips=skips,
        identity_strategy=strategy.name,
        identity_stats=identity_stats,
    )
