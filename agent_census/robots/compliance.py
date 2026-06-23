"""Score a client's requests against robots.txt.

Produces a :class:`ComplianceReport` capturing whether the client requested
disallowed paths, whether it fetched robots.txt before its content requests, and
whether it honored any Crawl-delay. The result feeds the report as tags, not as a
primary kind — a scanner that happens to avoid disallowed paths is still a
scanner.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from .. import uas
from ..model import ClientFeatures, ClientId, ComplianceReport, LogEntry, RobotsVerdict
from ..pipeline import ComplianceFn
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


def evaluate(
    entries: Sequence[LogEntry],
    features: ClientFeatures,
    rules: RobotsRules,
    ua_token: str | None,
) -> ComplianceReport:
    """Build the compliance report for one client."""
    disallowed = [e.path for e in entries if e.path and not rules.can_fetch(ua_token, e.path)]
    sample = tuple(dict.fromkeys(disallowed))[:5]
    matched = rules.matched_group(ua_token)
    delay = rules.crawl_delay(ua_token)
    median = features.inter_arrival_median
    delay_ok = None if delay is None or median is None else median >= delay

    if disallowed:
        verdict = RobotsVerdict.IGNORES
    elif rules.has_rules() and (
        features.fetched_robots_txt or features.request_count >= _MIN_REQUESTS_FOR_RESPECT
    ):
        verdict = RobotsVerdict.RESPECTS
    else:
        verdict = RobotsVerdict.UNKNOWN

    evidence = _evidence(verdict, len(disallowed), sample, delay, delay_ok)
    return ComplianceReport(
        verdict=verdict,
        matched_group=matched,
        disallowed_hits=len(disallowed),
        sample_disallowed=sample,
        fetched_robots_first=_fetched_robots_first(entries),
        crawl_delay=delay,
        crawl_delay_respected=delay_ok,
        evidence=evidence,
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


def make_compliance_fn(rules: RobotsRules) -> ComplianceFn:
    """Build a pipeline compliance callable bound to ``rules``."""

    def compliance_fn(
        _client_id: ClientId, entries: Sequence[LogEntry], features: ClientFeatures
    ) -> ComplianceReport:
        token = uas.product_token(features.user_agent)
        return evaluate(entries, features, rules, token)

    return compliance_fn
