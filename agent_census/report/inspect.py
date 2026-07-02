"""Render a deep trace of one client or all clients of a kind.

This is where a human checks a verdict against the raw evidence: every signal
that fired (including the runners-up that lost), the measured features, the
robots-compliance finding, and the actual requests.
"""

from __future__ import annotations

from ..model import Classification, ClientProfile, Kind
from ..pipeline import AnalysisResult
from .format import (
    client_label,
    count,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    kind_label,
    md_escape,
    ordered_tags,
    truncate,
)

# Inspecting a single IP that carries at least this many distinct clients (a
# user-agent-rotating host) prints a per-client summary instead of one full
# block each, which would otherwise be near-identical and unreadably long.
ROLLUP_MIN_CLIENTS = 5


def select_profiles(
    result: AnalysisResult,
    *,
    client: str | None,
    kind: str | None,
    network: str | None = None,
) -> list[ClientProfile]:
    """Pick the profiles to inspect by client substring, kind, and/or network.

    The filters compose (AND), so ``kind`` + ``network`` drills into one cell of
    the kind x network cross-tab. ``network`` is a case-insensitive substring of
    each client's real origin-network label (e.g. ``aws``, ``relay``,
    ``residential``) -- matched before the report's display-time folding, so it can
    select a low-volume datacentre that the cross-tab collapses into its
    ``Other datacenters`` column rather than breaking out on its own.
    """
    profiles = list(result.profiles)
    if kind is not None:
        want = kind.strip().lower().replace(" ", "_").replace("-", "_")
        profiles = [p for p in profiles if p.classification.primary.value == want]
    if network is not None:
        needle = network.lower()
        profiles = [p for p in profiles if p.network and needle in p.network.lower()]
    if client is not None:
        needle = client.lower()
        profiles = [
            p for p in profiles if needle in p.client_id.display.lower() or p.client_id.ip == client
        ]
    return profiles


def _identity_block(profile: ClientProfile) -> list[str]:
    feats = profile.features
    cls = profile.classification
    return [
        f"## {md_escape(client_label(profile))}",
        "",
        f"- **Classified:** `{kind_label(cls.primary)}` (confidence {cls.confidence:.0%})",
        f"- **IP:** {profile.client_id.ip}"
        + (f" ({len(profile.member_ips)} IPs merged)" if profile.member_ips else ""),
        f"- **Network:** {profile.network}" if profile.network else "- **Network:** –",
        f"- **User-Agent:** "
        f"{md_escape(elide_ua(feats.user_agent, is_browser=cls.primary is Kind.BROWSER) or '–')}",
        f"- **Requests:** {feats.request_count:,} · "
        f"**Bandwidth:** {human_bytes(feats.total_bytes)} · "
        f"**Span:** {human_duration(feats.duration_seconds)}",
        f"- **Seen:** {fmt_ts(feats.first_seen)} → {fmt_ts(feats.last_seen)}",
        "",
    ]


def _rationale_block(profile: ClientProfile) -> list[str]:
    cls = profile.classification
    lines = ["### Why this classification", ""]
    signals = sorted(cls.all_signals, key=lambda s: s.confidence, reverse=True)
    if not signals:
        lines.append("No classifier produced a signal — left UNKNOWN.")
    for signal in signals:
        marker = "→" if signal.kind is cls.primary else " "
        lines.append(
            f"- {marker} **{kind_label(signal.kind)}** ({signal.confidence:.0%}) "
            f"— {signal.classifier}"
        )
        for item in signal.evidence:
            lines.append(f"    - {md_escape(item)}")
    lines.append("")
    lines += _tags_evidence_block(cls)
    return lines


def _tags_evidence_block(cls: Classification) -> list[str]:
    """Every tag with the concrete measurement that earned it (the second axis of
    the verdict, alongside the kind signals above)."""
    if not cls.tags:
        return ["**Tags:** –", ""]
    evidence = dict(cls.tag_evidence)
    lines = ["**Tags**", ""]
    for tag in ordered_tags(cls.tags):
        why = evidence.get(tag)
        lines.append(f"- `{tag}` — {md_escape(why)}" if why else f"- `{tag}`")
    lines.append("")
    return lines


def _compliance_block(profile: ClientProfile) -> list[str]:
    report = profile.compliance
    if report is None:
        return []
    lines = ["### robots.txt", "", f"- **Verdict:** {report.verdict.value}"]
    if report.matched_group is not None:
        lines.append(f"- **Matched group:** `{report.matched_group}`")
    lines.append(f"- **Disallowed paths requested:** {report.disallowed_hits}")
    if report.sample_disallowed:
        lines.append(f"  - e.g. {', '.join(md_escape(p) for p in report.sample_disallowed)}")
    lines.append(f"- **Fetched robots.txt first:** {report.fetched_robots_first}")
    if report.crawl_delay is not None:
        lines.append(
            f"- **Crawl-delay:** {report.crawl_delay}s "
            f"(respected: {report.crawl_delay_respected})"
        )
    lines.append("")
    return lines


def _features_block(profile: ClientProfile) -> list[str]:
    lines = ["### Features", "", "| Metric | Value |", "| --- | --- |"]
    lines += [
        f"| {md_escape(name)} | {md_escape(value)} |"
        for name, value in feature_rows(profile.features)
    ]
    lines.append("")
    return lines


def _trace_block(profile: ClientProfile, limit: int, full: bool) -> list[str]:
    entries = sorted(profile.entries, key=lambda e: (e.timestamp is None, e.timestamp or e.line_no))
    shown = entries if full else entries[:limit]
    lines = [
        f"### Request trace ({len(shown)} of {len(entries)})",
        "",
        "| Time | Method | Path | Status | Bytes | Referer |",
        "| --- | --- | --- | --: | --: | --- |",
    ]
    for entry in shown:
        request = (entry.path + ("?" + entry.query if entry.query else "")) or entry.raw_request
        target = md_escape(request[:80])
        lines.append(
            f"| {fmt_ts(entry.timestamp)} | {entry.method or '–'} | {target or '–'} | "
            f"{entry.status if entry.status is not None else '–'} | "
            f"{entry.bytes_sent if entry.bytes_sent is not None else '–'} | "
            f"{md_escape((entry.referer or '–')[:60])} |"
        )
    if not full and len(entries) > limit:
        lines.append(f"| …{len(entries) - limit:,} more (use --full) | | | | | |")
    lines.append("")
    return lines


def _is_rotation(profiles: list[ClientProfile]) -> bool:
    """True when every selected profile is the same IP and there are enough to roll up."""
    return len(profiles) >= ROLLUP_MIN_CLIENTS and len({p.client_id.ip for p in profiles}) == 1


def _rollup_block(profiles: list[ClientProfile]) -> list[str]:
    ip = profiles[0].client_id.ip
    total_requests = sum(p.features.request_count for p in profiles)
    total_bytes = sum(p.features.total_bytes for p in profiles)
    lines = [
        f"## {ip} — {count(len(profiles), 'client')} on one IP",
        "",
        f"This IP presents {count(len(profiles), 'distinct user-agent')} (user-agent rotation). "
        "Per-client summary below; inspect one by passing a distinctive part of its "
        "user-agent to `--client`.",
        "",
        "| User-Agent | Kind | Conf. | Requests | Bandwidth | Tags |",
        "| --- | --- | --: | --: | --: | --- |",
    ]
    for profile in profiles:
        cls = profile.classification
        ua = elide_ua(profile.features.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–"
        tags = ", ".join(sorted(cls.tags)) or "–"
        lines.append(
            f"| {md_escape(truncate(ua, 70))} | {kind_label(cls.primary)} | "
            f"{cls.confidence:.0%} | "
            f"{profile.features.request_count:,} | {human_bytes(profile.features.total_bytes)} | "
            f"{tags} |"
        )
    lines.append(f"| **Total** | | | {total_requests:,} | {human_bytes(total_bytes)} | |")
    lines.append("")
    return lines


def render_inspect(selected: list[ClientProfile], *, limit: int = 20, full: bool = False) -> str:
    """Render inspection output for already-selected client profiles."""
    if not selected:
        return "_No matching clients._\n"
    selected = sorted(selected, key=lambda p: p.features.request_count, reverse=True)
    out: list[str] = ["# Client Inspection", ""]
    if _is_rotation(selected):
        out += _rollup_block(selected)
        return "\n".join(out).rstrip() + "\n"
    for profile in selected:
        out += _identity_block(profile)
        out += _rationale_block(profile)
        out += _compliance_block(profile)
        out += _features_block(profile)
        out += _trace_block(profile, limit, full)
        out.append("---")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
