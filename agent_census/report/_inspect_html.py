"""HTML rendering for ``inspect`` mode -- the per-client detail cards.

Split out of :mod:`.html` (which renders the report) so that module stays under
the repo's per-file line limit; both share the small page/tag helpers, which
live in :mod:`.html`, and the escape/badge helpers in :mod:`._htmlutil`. The
package re-exports :func:`render_inspect_html`.
"""

from __future__ import annotations

from ..model import Classification, ClientProfile, Kind
from ._htmlutil import esc as _esc
from ._htmlutil import kind_badge as _kind_badge
from .format import (
    client_label,
    count,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    ordered_tags,
    tag_title,
    truncate,
)
from .html import _page, _tags_html, tag_class
from .inspect import ROLLUP_MIN_CLIENTS


def _rationale_html(profile: ClientProfile) -> str:
    cls = profile.classification
    signals = sorted(cls.all_signals, key=lambda s: s.confidence, reverse=True)
    if signals:
        items = []
        for signal in signals:
            primary = signal.kind is cls.primary
            klass = ' class="primary-sig"' if primary else ""
            ev = "".join(f"<li>{_esc(item)}</li>" for item in signal.evidence)
            items.append(
                f"<li{klass}>{_kind_badge(signal.kind)} "
                f"<span class='muted'>{signal.confidence:.0%} · {_esc(signal.classifier)}</span>"
                f'<ul class="evlist">{ev}</ul></li>'
            )
        rationale = f"<h3>Why this classification</h3><ul>{''.join(items)}</ul>"
    else:
        rationale = (
            "<h3>Why this classification</h3>"
            "<p>No classifier produced a signal — left UNKNOWN.</p>"
        )
    return rationale + _tags_evidence_html(cls)


def _tags_evidence_html(cls: Classification) -> str:
    """Every tag with the concrete measurement that earned it — the second axis of
    the verdict, shown alongside the kind signals."""
    if not cls.tags:
        return ""
    evidence = dict(cls.tag_evidence)
    items = []
    for tag in ordered_tags(cls.tags):
        why = evidence.get(tag)
        chip = f'<span class="{tag_class(tag)}" title="{_esc(tag_title(tag))}">{_esc(tag)}</span>'
        detail = f" <span class='muted'>{_esc(why)}</span>" if why else ""
        items.append(f"<li>{chip}{detail}</li>")
    return f'<h3>Tags</h3><ul class="evlist">{"".join(items)}</ul>'


def _compliance_html(profile: ClientProfile) -> str:
    report = profile.compliance
    if report is None:
        return ""
    group = _esc(report.matched_group or "–")
    rows = [
        f"<li><strong>Verdict:</strong> {_esc(report.verdict.value)}</li>",
        f"<li><strong>Matched group:</strong> <code>{group}</code></li>",
        f"<li><strong>Disallowed requested:</strong> {report.disallowed_hits}</li>",
        f"<li><strong>Fetched robots first:</strong> {report.fetched_robots_first}</li>",
    ]
    if report.sample_disallowed:
        sample = ", ".join(_esc(p) for p in report.sample_disallowed)
        rows.append(f'<li class="mono">e.g. {sample}</li>')
    return f'<h3>robots.txt</h3><ul class="meta">{"".join(rows)}</ul>'


def _features_html(profile: ClientProfile) -> str:
    body = "".join(
        f"<tr><td>{_esc(name)}</td><td>{_esc(value)}</td></tr>"
        for name, value in feature_rows(profile.features)
    )
    return (
        "<h3>Features</h3><div class='tscroll'><table>"
        f"<tr><th>Metric</th><th>Value</th></tr>{body}</table></div>"
    )


def _trace_html(profile: ClientProfile, limit: int, full: bool) -> str:
    entries = sorted(profile.entries, key=lambda e: (e.timestamp is None, e.timestamp or e.line_no))
    shown = entries if full else entries[:limit]
    head = (
        "<tr><th>Time</th><th>Method</th><th>Path</th><th class='num'>Status</th>"
        "<th class='num'>Bytes</th><th>Referer</th></tr>"
    )
    rows = []
    for entry in shown:
        request = (entry.path + ("?" + entry.query if entry.query else "")) or entry.raw_request
        target = request[:90]
        rows.append(
            f"<tr><td>{_esc(fmt_ts(entry.timestamp))}</td><td>{_esc(entry.method or '–')}</td>"
            f'<td class="mono">{_esc(target or "–")}</td>'
            f"<td class='num'>{entry.status if entry.status is not None else '–'}</td>"
            f"<td class='num'>{entry.bytes_sent if entry.bytes_sent is not None else '–'}</td>"
            f'<td class="mono">{_esc((entry.referer or "–")[:60])}</td></tr>'
        )
    if not full and len(entries) > limit:
        rows.append(
            f'<tr><td class="muted" colspan="6">'
            f"…{len(entries) - limit:,} more (use --full)</td></tr>"
        )
    return (
        f"<h3>Request trace ({len(shown)} of {len(entries)})</h3>"
        f"<div class='tscroll'><table>{head}{''.join(rows)}</table></div>"
    )


def _profile_card(profile: ClientProfile, limit: int, full: bool) -> str:
    feats = profile.features
    cls = profile.classification
    conf = f"<span class='muted'>confidence {cls.confidence:.0%}</span>"
    ua = _esc(elide_ua(feats.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–")
    seen = f"{_esc(fmt_ts(feats.first_seen))} → {_esc(fmt_ts(feats.last_seen))}"
    header = (
        f'<h2 class="mono">{_esc(client_label(profile)[:100])}</h2>'
        f'<ul class="meta">'
        f"<li>{_kind_badge(cls.primary)} {conf}</li>"
        f"<li><strong>IP:</strong> <code>{_esc(profile.client_id.ip)}</code></li>"
        + (f"<li><strong>Network:</strong> {_esc(profile.network)}</li>" if profile.network else "")
        + f'<li><strong>User-Agent:</strong> <span class="mono">{ua}</span></li>'
        f"<li><strong>Requests:</strong> {feats.request_count:,} · "
        f"<strong>Bandwidth:</strong> {human_bytes(feats.total_bytes)} · "
        f"<strong>Span:</strong> {human_duration(feats.duration_seconds)}</li>"
        f"<li><strong>Seen:</strong> {seen}</li>"
        f"</ul>"
    )
    body = "".join(
        [
            header,
            _rationale_html(profile),
            _compliance_html(profile),
            _features_html(profile),
            _trace_html(profile, limit, full),
        ]
    )
    return f'<section class="card">{body}</section>'


def _rollup_card(profiles: list[ClientProfile]) -> str:
    ip = profiles[0].client_id.ip
    total_requests = sum(p.features.request_count for p in profiles)
    total_bytes = sum(p.features.total_bytes for p in profiles)
    head = (
        "<tr><th>User-Agent</th><th>Kind</th><th class='num'>Conf.</th>"
        "<th class='num'>Requests</th><th class='num'>Bandwidth</th><th>Tags</th></tr>"
    )
    rows = []
    for profile in profiles:
        cls = profile.classification
        ua = elide_ua(profile.features.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–"
        rows.append(
            f'<tr><td class="mono">{_esc(truncate(ua, 160))}</td>'
            f"<td>{_kind_badge(cls.primary)}</td>"
            f"<td class='num'>{cls.confidence:.0%}</td>"
            f"<td class='num'>{profile.features.request_count:,}</td>"
            f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
            f"<td>{_tags_html(cls.tags)}</td></tr>"
        )
    rows.append(
        f"<tr><td><strong>Total</strong></td><td></td><td></td>"
        f"<td class='num'>{total_requests:,}</td>"
        f"<td class='num'>{human_bytes(total_bytes)}</td><td></td></tr>"
    )
    intro = (
        f"<p>This IP presents {count(len(profiles), 'distinct user-agent')} (user-agent rotation). "
        "Per-client summary below; inspect one by passing a distinctive part of its "
        "user-agent to <code>--client</code>.</p>"
    )
    return (
        f'<section class="card"><h2 class="mono">{_esc(ip)} — '
        f"{count(len(profiles), 'client')} on one IP</h2>"
        f"{intro}<div class='tscroll'><table>{head}{''.join(rows)}</table></div></section>"
    )


def render_inspect_html(
    selected: list[ClientProfile], *, limit: int = 20, full: bool = False
) -> str:
    """Render inspection output for already-selected profiles as an HTML page."""
    if not selected:
        return _page("Client Inspection", "<h1>Client Inspection</h1><p>No matching clients.</p>")
    selected = sorted(selected, key=lambda p: p.features.request_count, reverse=True)
    if len(selected) >= ROLLUP_MIN_CLIENTS and len({p.client_id.ip for p in selected}) == 1:
        return _page("Client Inspection", f"<h1>Client Inspection</h1>{_rollup_card(selected)}")
    cards = "".join(_profile_card(p, limit, full) for p in selected)
    return _page("Client Inspection", f"<h1>Client Inspection</h1>{cards}")
