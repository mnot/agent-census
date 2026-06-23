"""Render a deep trace of one client or all clients of a kind.

This is where a human checks a verdict against the raw evidence: every signal
that fired (including the runners-up that lost), the measured features, the
robots-compliance finding, and the actual requests.
"""

from __future__ import annotations

from ..model import ClientProfile
from ..pipeline import AnalysisResult
from .format import feature_rows, fmt_ts, human_bytes, human_duration, md_escape


def select_profiles(
    result: AnalysisResult, *, client: str | None, kind: str | None
) -> list[ClientProfile]:
    """Pick the profiles to inspect by client substring and/or kind."""
    profiles = list(result.profiles)
    if kind is not None:
        profiles = [p for p in profiles if p.classification.primary.value == kind]
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
        f"## {md_escape(profile.client_id.display)}",
        "",
        f"- **Classified:** `{cls.primary.value}` (confidence {cls.confidence:.0%})",
        f"- **Tags:** {', '.join(sorted(cls.tags)) or '–'}",
        f"- **IP:** {profile.client_id.ip}"
        + (f" ({len(profile.member_ips)} verified IPs)" if profile.member_ips else ""),
        f"- **User-Agent:** {md_escape(feats.user_agent or '–')}",
        f"- **Requests:** {feats.request_count:,} · "
        f"**Bandwidth:** {human_bytes(feats.total_bytes)} · "
        f"**Span:** {human_duration(feats.duration_seconds)}",
        f"- **Seen:** {fmt_ts(feats.first_seen)} → {fmt_ts(feats.last_seen)}",
        "",
    ]


def _rationale_block(profile: ClientProfile) -> list[str]:
    lines = ["### Why this classification", ""]
    signals = sorted(profile.classification.all_signals, key=lambda s: s.confidence, reverse=True)
    if not signals:
        lines.append("No classifier produced a signal — left UNKNOWN.")
        lines.append("")
        return lines
    for signal in signals:
        marker = "→" if signal.kind is profile.classification.primary else " "
        lines.append(
            f"- {marker} **{signal.kind.value}** ({signal.confidence:.0%}) — {signal.classifier}"
        )
        for item in signal.evidence:
            lines.append(f"    - {md_escape(item)}")
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


def render_inspect(selected: list[ClientProfile], *, limit: int = 20, full: bool = False) -> str:
    """Render inspection output for already-selected client profiles."""
    if not selected:
        return "_No matching clients._\n"
    selected = sorted(selected, key=lambda p: p.features.request_count, reverse=True)
    out: list[str] = ["# Client Inspection", ""]
    for profile in selected:
        out += _identity_block(profile)
        out += _rationale_block(profile)
        out += _compliance_block(profile)
        out += _features_block(profile)
        out += _trace_block(profile, limit, full)
        out.append("---")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
