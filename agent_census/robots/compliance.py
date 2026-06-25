"""Score a client's requests against robots.txt.

Produces a :class:`ComplianceReport`: whether the client requested disallowed
paths, whether it fetched robots.txt before its content requests, and whether it
honored any Crawl-delay. The verdict feeds the report as a tag, not as a primary
kind -- a scanner that happens to avoid disallowed paths is still a scanner.

The scoring is split so it can be driven either from a list of entries
(:func:`evaluate`) or incrementally from the streaming feature accumulator: both
collect the same signals and hand them to :func:`report_from_signals`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from ..model import ClientFeatures, ComplianceReport, LogEntry, RobotsVerdict
from .parser import RobotsRules

_MIN_REQUESTS_FOR_RESPECT = 5


def _stamp(entry: LogEntry) -> datetime:
    assert entry.timestamp is not None
    return entry.timestamp


def _fetched_robots_first(entries: Sequence[LogEntry]) -> bool:
    """True if /robots.txt was requested no later than the first content request."""
    timed = sorted((e for e in entries if e.timestamp is not None), key=_stamp)
    first_content: int | None = None
    for idx, entry in enumerate(timed):
        if entry.path == "/robots.txt":
            return first_content is None or idx <= first_content
        if first_content is None:
            first_content = idx
    return False


def report_from_signals(
    rules: RobotsRules,
    ua_token: str | None,
    *,
    disallowed_hits: int,
    sample_disallowed: tuple[str, ...],
    fetched_robots_first: bool,
    fetched_robots_txt: bool,
    request_count: int,
    median_interval: float | None,
) -> ComplianceReport:
    """Build a compliance report from already-collected signals."""
    matched = rules.matched_group(ua_token)
    delay = rules.crawl_delay(ua_token)
    delay_ok = None if delay is None or median_interval is None else median_interval >= delay

    if disallowed_hits:
        verdict = RobotsVerdict.IGNORES
    elif rules.has_rules() and (fetched_robots_txt or request_count >= _MIN_REQUESTS_FOR_RESPECT):
        verdict = RobotsVerdict.RESPECTS
    else:
        verdict = RobotsVerdict.UNKNOWN

    return ComplianceReport(
        verdict=verdict,
        matched_group=matched,
        disallowed_hits=disallowed_hits,
        sample_disallowed=sample_disallowed,
        fetched_robots_first=fetched_robots_first,
        crawl_delay=delay,
        crawl_delay_respected=delay_ok,
        evidence=_evidence(verdict, disallowed_hits, sample_disallowed, delay, delay_ok),
    )


def evaluate(
    entries: Sequence[LogEntry],
    features: ClientFeatures,
    rules: RobotsRules,
    ua_token: str | None,
) -> ComplianceReport:
    """Build the compliance report for one client from its entries."""
    # robots.txt itself is always fetchable -- a Disallow: / rule makes the
    # stdlib report it as denied, so excluding it keeps a polite crawler that
    # only fetched robots.txt from being scored as ignoring robots.
    disallowed = [
        e.path
        for e in entries
        if e.path and e.path != "/robots.txt" and not rules.can_fetch(ua_token, e.path)
    ]
    sample = tuple(dict.fromkeys(disallowed))[:5]
    return report_from_signals(
        rules,
        ua_token,
        disallowed_hits=len(disallowed),
        sample_disallowed=sample,
        fetched_robots_first=_fetched_robots_first(entries),
        fetched_robots_txt=features.fetched_robots_txt,
        request_count=features.request_count,
        median_interval=features.inter_arrival_median,
    )


def _evidence(
    verdict: RobotsVerdict,
    hits: int,
    sample: tuple[str, ...],
    delay: float | None,
    delay_ok: bool | None,
) -> tuple[str, ...]:
    out: list[str] = []
    if hits:
        out.append(f"requested {hits} disallowed path(s), e.g. {', '.join(sample[:3])}")
    elif verdict is RobotsVerdict.RESPECTS:
        out.append("requested no disallowed paths")
    if delay is not None and delay_ok is not None:
        out.append(f"crawl-delay {delay}s {'respected' if delay_ok else 'exceeded'}")
    return tuple(out)
