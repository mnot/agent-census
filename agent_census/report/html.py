"""Render analysis results and inspection traces as a self-contained HTML page.

The page is built from the same structured data the Markdown renderer uses, with
a small built-in template (:data:`_CSS` + :func:`_page`) so the output is one
file you can open in a browser -- no external assets, no dependencies.
"""

from __future__ import annotations

import html

from ..model import ClientProfile, Kind
from ..pipeline import AnalysisResult
from .aggregate import KIND_BLURB, KIND_ORDER, by_kind, robots_counts, time_range
from .format import (
    client_label,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    truncate,
)
from .inspect import ROLLUP_MIN_CLIENTS

_KIND_COLORS: dict[Kind, str] = {
    Kind.BROWSER: "#2563eb",
    Kind.CRAWLER: "#0891b2",
    Kind.SEARCH_ENGINE: "#16a34a",
    Kind.SOCIAL_PREVIEW: "#0ea5e9",
    Kind.AI_CRAWLER: "#7c3aed",
    Kind.SEO_MARKETING: "#ca8a04",
    Kind.IMPERSONATOR: "#b91c1c",
    Kind.SCRAPER: "#d97706",
    Kind.VULN_SCANNER: "#dc2626",
    Kind.SPOOFED_BROWSER: "#ea580c",
    Kind.SPAM_BOT: "#db2777",
    Kind.FEED_READER: "#65a30d",
    Kind.MONITOR: "#0d9488",
    Kind.UNKNOWN: "#6b7280",
}

# Tags that deserve a non-neutral colour.
_TAG_COLORS: dict[str, str] = {
    "verified": "#16a34a",  # confirmed identity -> strong green
    "respects-robots": "#14b8a6",  # well-behaved, but softer/less definitive -> teal
    "impersonator": "#dc2626",
    "ignores-robots": "#d97706",
    "fake-browser": "#ea580c",  # browser costume, no browser behaviour -> orange
    "datacenter": "#9333ea",  # origin is hosting, not an eyeball network -> purple
    "ua-rotating": "#d97706",  # many UAs from a hosting/non-browser source -> amber
    "icloud-private-relay": "#0284c7",  # privacy relay; a positive browser signal -> blue
    # 'shared-ip' is left neutral (grey): many UAs but a benign shared egress.
}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; }
h2 { font-size: 1.25rem; margin: 2.25rem 0 .5rem; }
a { color: inherit; }
.meta { list-style: none; padding: 0; margin: .5rem 0 1.5rem; color: #6b7280; font-size: .92rem; }
.meta li { margin: .15rem 0; }
.meta code { color: CanvasText; }
.warn { color: #b45309; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8884; vertical-align: top; }
th { font-weight: 600; border-bottom: 2px solid #8886; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:hover td { background: #8881; }
.badge { display: inline-block; padding: .08rem .5rem; border-radius: 999px;
  color: #fff; font-size: .8rem; font-weight: 600; white-space: nowrap; }
.tag { display: inline-block; padding: .05rem .45rem; margin: 0 .2rem .2rem 0;
  border-radius: 6px; background: #8883; font-size: .78rem; white-space: nowrap; }
.blurb { color: #6b7280; margin: .15rem 0 .6rem; }
.bar { background: #8883; border-radius: 4px; height: .7rem; min-width: 2px; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
  word-break: break-all; }
.muted { color: #6b7280; }
.evlist { margin: .25rem 0 .25rem 1rem; padding: 0; }
.evlist li { margin: .1rem 0; }
.primary-sig { font-weight: 600; }
td.copy { cursor: pointer; }
td.copy:hover { background: #8882; }
td.copy.copied { background: #16a34a55; }
details { margin: .25rem 0 1rem; }
summary { cursor: pointer; color: #6b7280; font-size: .9rem; padding: .25rem 0; }
input.filter { display: block; width: 100%; max-width: 30rem; margin: .5rem 0;
  padding: .4rem .55rem; border: 1px solid #8886; border-radius: 6px;
  background: Canvas; color: CanvasText; font: inherit; }
footer { margin-top: 3rem; color: #6b7280; font-size: .85rem; }
""".strip()

# Click a client cell to copy its id (the value for `inspect --client`).
# Uses the async clipboard API where available, with an execCommand fallback
# that works on file:// pages where the API is blocked.
_SCRIPT = """
document.addEventListener('click', function (event) {
  var cell = event.target.closest('[data-copy]');
  if (!cell) return;
  var text = cell.getAttribute('data-copy');
  var flash = function () {
    cell.classList.add('copied');
    setTimeout(function () { cell.classList.remove('copied'); }, 900);
  };
  function fallback() {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta); flash();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(flash, fallback);
  } else {
    fallback();
  }
}, false);

document.addEventListener('input', function (event) {
  var input = event.target;
  if (!input.classList || !input.classList.contains('filter')) return;
  var scope = input.closest('details') || document;
  var query = input.value.trim().toLowerCase();
  var rows = scope.querySelectorAll('tr.frow');
  for (var i = 0; i < rows.length; i++) {
    var hay = rows[i].getAttribute('data-filter') || '';
    rows[i].style.display = hay.indexOf(query) === -1 ? 'none' : '';
  }
}, false);
""".strip()


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _page(title: str, content: str) -> str:
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_CSS}</style>\n"
        f'</head>\n<body>\n<main class="container">\n{content}\n'
        "<footer>Generated by agent-census.</footer>\n</main>\n"
        f"<script>{_SCRIPT}</script>\n</body>\n</html>\n"
    )


def _kind_badge(kind: Kind) -> str:
    color = _KIND_COLORS.get(kind, "#6b7280")
    return f'<span class="badge" style="background:{color}">{_esc(kind.value)}</span>'


def _tags_html(tags: frozenset[str]) -> str:
    if not tags:
        return '<span class="muted">–</span>'
    spans = []
    for tag in sorted(tags):
        color = _TAG_COLORS.get(tag)
        style = f' style="background:{color};color:#fff"' if color else ""
        spans.append(f'<span class="tag"{style}>{_esc(tag)}</span>')
    return "".join(spans)


def _meta_list(result: AnalysisResult, source: str, robots_note: str | None) -> str:
    skips = result.skips
    stats = result.identity_stats
    start, end = time_range(result.profiles)
    items = [
        f"<strong>Source:</strong> <code>{_esc(source)}</code>",
        f"<strong>Lines:</strong> {skips.total_lines:,} total · {skips.parsed:,} parsed · "
        f"{skips.skipped:,} skipped",
        f"<strong>Time range:</strong> {_esc(fmt_ts(start))} → {_esc(fmt_ts(end))}",
        f"<strong>Identity:</strong> <code>{_esc(result.identity_strategy)}</code> "
        f"({stats.client_count:,} clients; {stats.singletons:,} singletons; "
        f"{stats.ips_with_multiple_uas:,} IPs with multiple UAs)",
    ]
    if robots_note:
        cls = "warn" if "differ" in robots_note else ""
        items.append(f'<strong>robots.txt:</strong> <span class="{cls}">{_esc(robots_note)}</span>')
    return '<ul class="meta">' + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def _share_bar(fraction: float) -> str:
    return (
        f'<div class="bar" style="width:{fraction * 100:.1f}%"></div>'
        f'<span class="muted">{fraction:.0%}</span>'
    )


def _summary_table(result: AnalysisResult, groups: dict[Kind, list[ClientProfile]]) -> str:
    total = sum(p.features.request_count for p in result.profiles) or 1
    total_bytes = sum(p.features.total_bytes for p in result.profiles) or 1
    robots_help = (
        "✓ respect: requested no disallowed paths\n"
        "✗ ignore: requested disallowed paths\n"
        "(clients with no applicable rules are omitted)"
    )
    head = (
        "<tr><th>Kind</th><th class='num'>Clients</th><th class='num'>Requests</th>"
        "<th>Req share</th><th class='num'>Avg/client</th><th class='num'>Bandwidth</th>"
        f'<th>BW share</th><th title="{_esc(robots_help)}">robots ⓘ</th></tr>'
    )
    rows = []
    for kind in KIND_ORDER:
        group = groups.get(kind)
        if not group:
            continue
        requests = sum(p.features.request_count for p in group)
        byte_total = sum(p.features.total_bytes for p in group)
        respects, ignores = robots_counts(group)
        robots = (
            f"{respects}✓ / {ignores}✗" if (respects or ignores) else '<span class="muted">–</span>'
        )
        rows.append(
            f'<tr><td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"<td class='num'>{len(group):,}</td><td class='num'>{requests:,}</td>"
            f"<td>{_share_bar(requests / total)}</td>"
            f"<td class='num'>{requests / len(group):,.0f}</td>"
            f"<td class='num'>{human_bytes(byte_total)}</td>"
            f"<td>{_share_bar(byte_total / total_bytes)}</td>"
            f"<td>{robots}</td></tr>"
        )
    return (
        f"<h2>Summary by kind</h2>\n<table>{head}{''.join(rows)}</table>\n"
        '<p class="muted">Tip: click a client below to copy its id for '
        "<code>inspect --client</code>.</p>"
    )


_SECTION_HEAD = (
    "<tr><th>Client</th><th class='num'>Requests</th><th class='num'>Bandwidth</th>"
    "<th class='num'>Conf.</th><th>Tags</th><th>Top evidence</th></tr>"
)
# Per-kind cap rendered into the HTML (visible rows + the expandable set).
_EXPAND_LIMIT = 100


def _client_row(profile: ClientProfile, *, filterable: bool = False) -> str:
    cls = profile.classification
    evidence = _esc(truncate(cls.evidence[0])) if cls.evidence else "–"
    attrs = ""
    if filterable:
        haystack = f"{profile.client_id.ip} {profile.client_id.user_agent or ''}".lower()
        attrs = f' class="frow" data-filter="{_esc(haystack)}"'
    return (
        f"<tr{attrs}>"
        f'<td class="mono copy" data-copy="{_esc(profile.client_id.ip)}" '
        f'title="Click to copy this id for: inspect --client">'
        f"{_esc(client_label(profile)[:90])}</td>"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td><td>{evidence}</td></tr>"
    )


def _kind_section(kind: Kind, group: list[ClientProfile], top: int) -> str:
    group = sorted(group, key=lambda p: p.features.request_count, reverse=True)
    requests = sum(p.features.request_count for p in group)
    title = f"{_kind_badge(kind)} {len(group):,} clients · {requests:,} requests"
    parts = [
        f'<h2 id="{kind.value}">{title}</h2>',
        f'<p class="blurb">{_esc(KIND_BLURB.get(kind, ""))}</p>',
        f"<table>{_SECTION_HEAD}{''.join(_client_row(p) for p in group[:top])}</table>",
    ]
    extra = group[top:_EXPAND_LIMIT]
    if extra:
        extra_rows = "".join(_client_row(p, filterable=True) for p in extra)
        parts.append(
            "<details><summary>"
            f"Show {len(extra):,} more</summary>"
            '<input class="filter" type="search" '
            'placeholder="filter these by IP or User-Agent…" aria-label="filter clients">'
            f"<table>{_SECTION_HEAD}{extra_rows}</table>"
            "</details>"
        )
    remaining = len(group) - _EXPAND_LIMIT
    if remaining > 0:
        parts.append(
            f'<p class="muted">…and {remaining:,} more — '
            f"<code>agent-census inspect --kind {kind.value}</code></p>"
        )
    return "\n".join(parts)


def render_report_html(
    result: AnalysisResult, *, source: str = "stdin", top: int = 5, robots_note: str | None = None
) -> str:
    """Render the full analysis report as a standalone HTML page."""
    groups = by_kind(result.profiles)
    parts = [
        "<h1>Agent Census</h1>",
        _meta_list(result, source, robots_note),
        _summary_table(result, groups),
    ]
    for kind in KIND_ORDER:
        group = groups.get(kind)
        if group:
            parts.append(_kind_section(kind, group, top))
    return _page("Agent Census", "\n".join(parts))


# --- inspect mode ----------------------------------------------------------


def _rationale_html(profile: ClientProfile) -> str:
    signals = sorted(profile.classification.all_signals, key=lambda s: s.confidence, reverse=True)
    if not signals:
        return "<p>No classifier produced a signal — left UNKNOWN.</p>"
    items = []
    for signal in signals:
        primary = signal.kind is profile.classification.primary
        klass = ' class="primary-sig"' if primary else ""
        ev = "".join(f"<li>{_esc(item)}</li>" for item in signal.evidence)
        items.append(
            f"<li{klass}>{_kind_badge(signal.kind)} "
            f"<span class='muted'>{signal.confidence:.0%} · {_esc(signal.classifier)}</span>"
            f'<ul class="evlist">{ev}</ul></li>'
        )
    return f"<h3>Why this classification</h3><ul>{''.join(items)}</ul>"


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
    return f"<h3>Features</h3><table><tr><th>Metric</th><th>Value</th></tr>{body}</table>"


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
        f"<table>{head}{''.join(rows)}</table>"
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
        f"<li><strong>Tags:</strong> {_tags_html(cls.tags)}</li>"
        f"<li><strong>IP:</strong> <code>{_esc(profile.client_id.ip)}</code></li>"
        f'<li><strong>User-Agent:</strong> <span class="mono">{ua}</span></li>'
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
            f'<tr><td class="mono">{_esc(truncate(ua, 80))}</td>'
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
        f"<p>This IP presents {len(profiles):,} distinct user-agents (user-agent rotation). "
        "Per-client summary below; inspect one by passing a distinctive part of its "
        "user-agent to <code>--client</code>.</p>"
    )
    return (
        f'<section class="card"><h2 class="mono">{_esc(ip)} — '
        f"{len(profiles):,} clients on one IP</h2>"
        f"{intro}<table>{head}{''.join(rows)}</table></section>"
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
