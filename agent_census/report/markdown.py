"""Render an :class:`AnalysisResult` as a Markdown report."""

from __future__ import annotations

from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, AnalysisResult, KindRollup
from .aggregate import (
    KIND_BLURB,
    KIND_ORDER,
    ActorGroup,
    by_kind,
    group_actors,
    network_matrix,
    time_range,
    typical_conduct,
)
from .format import (
    actor_spread,
    client_id_parts,
    client_label,
    fmt_ts,
    human_bytes,
    kind_label,
    md_escape,
    ordered_tags,
    top_evidence,
    truncate,
)
from .geo import CountryFlags


def _robots_summary(rollup: KindRollup) -> str:
    respects, ignores, unknown = (
        rollup.respects_robots,
        rollup.ignores_robots,
        rollup.unknown_robots,
    )
    if not (respects or ignores or unknown):
        return "–"
    # respects + ignores + unknown == clients (when robots data is present).
    return f"{respects}✓ / {ignores}✗ / {unknown}?"


def _header(
    result: AnalysisResult, source: str, robots_note: str | None, elapsed: float | None
) -> list[str]:
    skips = result.skips
    stats = result.identity_stats
    start, end = time_range(result.rollups)
    heading = "# Agent Census" + (f" — {result.site}" if result.site else "")
    lines = [
        heading,
        "",
        f"- **Source:** `{source}`",
        f"- **Lines:** {skips.total_lines:,} total · {skips.parsed:,} parsed · "
        f"{skips.skipped:,} skipped"
        + (f" · {skips.excluded:,} excluded (--vhost)" if skips.excluded else ""),
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
    if elapsed is not None:
        lines.append("")
        lines.append(f"_Analysed in {elapsed:.1f}s._")
    lines.append("")
    return lines


def _summary_table(result: AnalysisResult) -> list[str]:
    rollups = result.rollups
    total_requests = sum(r.requests for r in rollups.values()) or 1
    total_bytes = sum(r.total_bytes for r in rollups.values()) or 1
    lines = [
        "## Summary by kind",
        "",
        "| Kind | Clients | Requests | Req % | Avg req/client | Bandwidth | BW % | robots |",
        "| --- | --: | --: | --: | --: | --: | --: | :-: |",
    ]
    any_robots = False
    for kind in KIND_ORDER:
        rollup = rollups.get(kind)
        if rollup is None or rollup.clients == 0:
            continue
        avg = rollup.requests / rollup.clients
        robots = _robots_summary(rollup)
        any_robots = any_robots or robots != "–"
        lines.append(
            f"| {kind_label(kind)} | {rollup.clients:,} | {rollup.requests:,} | "
            f"{rollup.requests / total_requests:.0%} | "
            f"{avg:,.0f} | {human_bytes(rollup.total_bytes)} | "
            f"{rollup.total_bytes / total_bytes:.0%} | {robots} |"
        )
    lines.append("")
    if any_robots:
        lines.append(
            "_robots: ✓ respect (requested no disallowed paths) · "
            "✗ ignore (requested disallowed paths) · "
            "? can't tell (fewer than 5 requests, or no applicable rule)._"
        )
        lines.append("")
    return lines


def _network_table(result: AnalysisResult) -> list[str]:
    matrix = network_matrix(result.network_rollups, result.network_categories)
    if matrix is None:
        return []
    header = "| Kind | " + " | ".join(md_escape(n) for n in matrix.networks) + " | Total |"
    separator = "| --- |" + " --: |" * (len(matrix.networks) + 1)
    lines = [
        "## Requests by kind and network",
        "",
        "Where each kind's requests originated — hosting providers, shared-egress "
        "networks (privacy relays / Tor), or residential/unknown. Cells are request "
        f"counts; the smallest hosting providers are folded into _{OTHER_HOSTING}_.",
        "",
        header,
        separator,
    ]

    def cell(value: int, *, lead: bool) -> str:
        if not value:
            return "–"
        text = f"{value:,}"
        return f"**{text}**" if lead else text  # bold each kind's leading network

    for kind in matrix.kinds:
        values = [matrix.cell(net, kind) for net in matrix.networks]
        peak = max(values, default=0)
        lead_at = values.index(peak) if peak else -1  # first network with the row max
        rendered = [cell(v, lead=i == lead_at) for i, v in enumerate(values)]
        cells = " | ".join(rendered)
        lines.append(f"| {kind_label(kind)} | {cells} | {matrix.row_totals[kind]:,} |")
    totals = " | ".join(f"{matrix.col_totals[net]:,}" for net in matrix.networks)
    lines.append(f"| **All kinds** | {totals} | {matrix.total:,} |")
    lines.append("")
    return lines


def _flag(profile: ClientProfile, flags: CountryFlags) -> str:
    """A leading ``'🇩🇪 '`` for a flagged client, else ``''``."""
    entry = flags.get(profile.client_id)
    return f"{entry[0]} " if entry else ""


def _client_label(profile: ClientProfile, flags: CountryFlags) -> str:
    return _flag(profile, flags) + md_escape(client_label(profile)[:140])


def _actor_label(actor: ActorGroup, flags: CountryFlags) -> str:
    """One-line label: the per-IP client, or a collapsed group's footprint + UA."""
    if not actor.collapsed:
        lead = actor.lead
        if len(lead.member_ips) >= 2:
            # A single entry that folded many IPs (an ASN operator, a verified bot,
            # an egress/subnet cluster): note the cluster size beside its identity.
            prefix, _, ua = client_id_parts(lead)
            label = f"{prefix} ({len(lead.member_ips):,} IPs) | {ua if ua is not None else '-'}"
            return _flag(lead, flags) + md_escape(label[:140])
        return _client_label(lead, flags)
    _, _, ua = client_id_parts(actor.lead)
    spread = actor_spread(actor.distinct_ips, actor.distinct_asns)
    return _flag(actor.lead, flags) + md_escape(f"{spread} | {ua if ua is not None else '-'}"[:140])


def _kind_section(
    kind: Kind,
    group: list[ClientProfile],
    rollup: KindRollup,
    top: int,
    flags: CountryFlags | None = None,
) -> list[str]:
    flags = flags or {}
    actors = group_actors(group)
    typical = typical_conduct(group)
    lines = [
        f"## {kind_label(kind)} ({rollup.clients:,} clients, {rollup.requests:,} requests)",
        "",
        KIND_BLURB.get(kind, ""),
        "",
    ]
    if typical:
        lines += [f"_Typically: {', '.join(ordered_tags(typical))}._", ""]
    lines += [
        "| Client | Requests | Bandwidth | Conf. | Tags | Evidence |",
        "| --- | --: | --: | --: | --- | --- |",
    ]
    shown = actors[:top]
    for actor in shown:
        cls = actor.lead.classification
        tags = ", ".join(ordered_tags(cls.tags - typical)) or "–"
        evidence = md_escape(truncate(top_evidence(actor.lead)))
        lines.append(
            f"| {_actor_label(actor, flags)} | {actor.requests:,} | "
            f"{human_bytes(actor.total_bytes)} | {cls.confidence:.0%} | "
            f"{tags} | {evidence} |"
        )
    represented = sum(len(a.members) for a in shown)
    if rollup.clients > represented:
        lines.append(f"| …and {rollup.clients - represented:,} more | | | | | |")
    lines.append("")
    if any(a.collapsed or len(a.lead.member_ips) >= 2 for a in shown):
        lines.append(
            f"_Rows showing “N IPs” fold many addresses into one actor; "
            f"run `agent-census inspect --kind {kind.value}` for the per-IP/ASN list._"
        )
    lines.append(f"_Total bandwidth: {human_bytes(rollup.total_bytes)}_")
    lines.append("")
    return lines


def render_report(
    result: AnalysisResult,
    *,
    source: str = "stdin",
    top: int = 5,
    robots_note: str | None = None,
    elapsed: float | None = None,
    country_flags: CountryFlags | None = None,
) -> str:
    """Render the full Markdown report for an analysis run."""
    flags = country_flags or {}
    groups = by_kind(result.profiles)
    lines = _header(result, source, robots_note, elapsed)
    lines += _summary_table(result)
    lines += _network_table(result)
    for kind in KIND_ORDER:
        rollup = result.rollups.get(kind)
        if rollup and rollup.clients:
            lines += _kind_section(kind, groups.get(kind, []), rollup, top, flags)
    return "\n".join(lines).rstrip() + "\n"
