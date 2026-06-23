"""Render an :class:`AnalysisResult` as a Markdown report."""

from __future__ import annotations

from ..model import ClientProfile, Kind
from ..pipeline import AnalysisResult
from .aggregate import KIND_BLURB, KIND_ORDER, by_kind, robots_counts, time_range
from .format import client_label, fmt_ts, human_bytes, md_escape, truncate


def _robots_summary(group: list[ClientProfile]) -> str:
    respects, ignores = robots_counts(group)
    if not respects and not ignores:
        return "–"
    return f"{respects}✓ / {ignores}✗"


def _header(result: AnalysisResult, source: str, robots_note: str | None) -> list[str]:
    skips = result.skips
    stats = result.identity_stats
    start, end = time_range(result.profiles)
    lines = [
        "# Agent Census",
        "",
        f"- **Source:** `{source}`",
        f"- **Lines:** {skips.total_lines:,} total · {skips.parsed:,} parsed · "
        f"{skips.skipped:,} skipped",
    ]
    if skips.reasons:
        detail = "; ".join(f"{count:,} {reason}" for reason, count in sorted(skips.reasons.items()))
        lines.append(f"  - Skips: {detail}")
    lines.extend(
        [
            f"- **Time range:** {fmt_ts(start)} → {fmt_ts(end)}",
            f"- **Identity strategy:** `{result.identity_strategy}` "
            f"({stats.client_count:,} clients; {stats.singletons:,} singletons; "
            f"{stats.ips_with_multiple_uas:,} IPs with multiple UAs)",
        ]
    )
    if robots_note:
        lines.append(f"- **robots.txt:** {robots_note}")
    lines.append("")
    return lines


def _summary_table(result: AnalysisResult, groups: dict[Kind, list[ClientProfile]]) -> list[str]:
    total_requests = sum(p.features.request_count for p in result.profiles) or 1
    total_bytes = sum(p.features.total_bytes for p in result.profiles) or 1
    lines = [
        "## Summary by kind",
        "",
        "| Kind | Clients | Requests | Req % | Avg req/client | Bandwidth | BW % | robots |",
        "| --- | --: | --: | --: | --: | --: | --: | :-: |",
    ]
    any_robots = False
    for kind in KIND_ORDER:
        group = groups.get(kind)
        if not group:
            continue
        clients = len(group)
        requests = sum(p.features.request_count for p in group)
        byte_total = sum(p.features.total_bytes for p in group)
        avg = requests / clients if clients else 0
        robots = _robots_summary(group)
        any_robots = any_robots or robots != "–"
        lines.append(
            f"| {kind.value} | {clients:,} | {requests:,} | {requests / total_requests:.0%} | "
            f"{avg:,.0f} | {human_bytes(byte_total)} | {byte_total / total_bytes:.0%} | "
            f"{robots} |"
        )
    lines.append("")
    if any_robots:
        lines.append(
            "_robots: ✓ respect (requested no disallowed paths) · "
            "✗ ignore (requested disallowed paths); clients with no applicable rules are omitted._"
        )
        lines.append("")
    return lines


def _client_label(profile: ClientProfile) -> str:
    return md_escape(client_label(profile)[:80])


def _kind_section(kind: Kind, group: list[ClientProfile], top: int) -> list[str]:
    group = sorted(group, key=lambda p: p.features.request_count, reverse=True)
    requests = sum(p.features.request_count for p in group)
    byte_total = sum(p.features.total_bytes for p in group)
    lines = [
        f"## {kind.value} ({len(group):,} clients, {requests:,} requests)",
        "",
        KIND_BLURB.get(kind, ""),
        "",
        "| Client | Requests | Bandwidth | Conf. | Tags | Evidence |",
        "| --- | --: | --: | --: | --- | --- |",
    ]
    for profile in group[:top]:
        cls = profile.classification
        tags = ", ".join(sorted(cls.tags)) or "–"
        evidence = md_escape(truncate(cls.evidence[0])) if cls.evidence else "–"
        lines.append(
            f"| {_client_label(profile)} | {profile.features.request_count:,} | "
            f"{human_bytes(profile.features.total_bytes)} | {cls.confidence:.0%} | "
            f"{tags} | {evidence} |"
        )
    if len(group) > top:
        lines.append(f"| …and {len(group) - top:,} more | | | | | |")
    lines.append("")
    lines.append(f"_Total bandwidth: {human_bytes(byte_total)}_")
    lines.append("")
    return lines


def render_report(
    result: AnalysisResult, *, source: str = "stdin", top: int = 5, robots_note: str | None = None
) -> str:
    """Render the full Markdown report for an analysis run."""
    groups = by_kind(result.profiles)
    lines = _header(result, source, robots_note)
    lines += _summary_table(result, groups)
    for kind in KIND_ORDER:
        group = groups.get(kind)
        if group:
            lines += _kind_section(kind, group, top)
    return "\n".join(lines).rstrip() + "\n"
