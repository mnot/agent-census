"""Render analysis results and inspection traces as a self-contained HTML page.

The page is built from the same structured data the Markdown renderer uses, with
a small built-in template (:data:`_CSS` + :func:`_page`) so the output is one
file you can open in a browser -- no external assets, no dependencies.
"""

from __future__ import annotations

import html
import json

from .. import __version__
from ..model import Classification, ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, AnalysisResult, KindRollup
from ._netscript import NET_SCRIPT
from .aggregate import (
    BREAKOUT_MIN_SHARE,
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
    as_display,
    client_id_parts,
    client_label,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    kind_label,
    ordered_tags,
    tag_title,
    top_evidence,
    truncate,
)
from .geo import CountryFlags
from .inspect import ROLLUP_MIN_CLIENTS

# Kind badge fills. White-text badges, so each fill is held at >=4.5:1 against
# white (deepened along OKLCH lightness from its original hue where needed);
# the hue family -- the actual signal -- is preserved.
_KIND_COLORS: dict[Kind, str] = {
    Kind.BROWSER: "#2563eb",
    Kind.APP: "#6062ed",
    Kind.CRAWLER: "#007d9e",
    Kind.SEARCH_ENGINE: "#00862e",
    Kind.ARCHIVER: "#047857",
    Kind.SOCIAL_PREVIEW: "#0079bb",
    Kind.AI_CRAWLER: "#7c3aed",
    Kind.SEO_MARKETING: "#a36600",
    Kind.DATA_HARVESTER: "#a16207",
    Kind.IMPERSONATOR: "#b91c1c",
    Kind.SCRAPER: "#b85900",
    Kind.VULN_SCANNER: "#dc2626",
    Kind.SPOOFED_BROWSER: "#d14000",
    Kind.SPAM_BOT: "#d92476",
    Kind.FEED_READER: "#478200",
    Kind.MONITOR: "#008277",
    Kind.AUTOMATION: "#78716c",
    Kind.UNKNOWN: "#6b7280",
}

# Tags that deserve a non-neutral colour.
# Signal-tag fills. White text again, so each colour is held at >=4.5:1 against
# white; hues match their kind-badge counterparts (e.g. 'verified' shares the
# search-engine green, 'vpn' the monitor teal) so the wheel stays coherent.
_TAG_COLORS: dict[str, str] = {
    "verified": "#00862e",  # confirmed identity -> strong green
    "asn-associated": "#008459",  # origin AS corroborates the declared crawler -> green
    "unverified": "#b45309",  # declared crawler we had info for but couldn't confirm -> amber
    "impersonator": "#dc2626",
    "ignores-robots": "#b85900",
    "probe-paths": "#dc2626",  # requested known-vulnerable paths -> red
    "traversal": "#dc2626",  # path-traversal / injection markers -> red
    "encoding-evasion": "#b91c1c",  # deliberate encoding evasion -> deep red
    "404-storm": "#b85900",
    "ancient-browser-ua": "#dc2626",  # years-stale browser version -> almost certainly spoofed
    "impossible-browser-ua": "#dc2626",  # version newer than exists -> forged UA
    "datacenter": "#9333ea",  # origin is hosting, not an eyeball network -> purple
    "ua-rotating": "#b85900",  # many UAs from a hosting/non-browser source -> amber
    "forged-referer": "#dc2626",  # Referer faked to mimic navigation -> red
    "icloud-private-relay": "#0079bc",  # privacy relay; a positive browser signal -> blue
    "tor-exit": "#6d28d9",  # Tor exit node; anonymised egress -> violet
    "vpn": "#008277",  # consumer VPN egress -> teal
    "corporate-proxy": "#7c3aed",  # SASE / corporate egress -> violet
    # 'shared-ip' is left neutral (grey): many UAs but a benign shared egress.
}

# Hover descriptions for the cross-tab column headers. The egress buckets group
# several networks, so spell out their members; the catch-all columns get a note.
_NETWORK_HELP: dict[str, str] = {
    "Privacy proxies": "Anonymising relays that front real users' own browsers "
    "(iCloud Private Relay, Tor exit nodes). The source IP is not an identity.",
    "VPNs": "Consumer VPN exit pools (e.g. NordVPN) — many users behind a shared address pool.",
    "Corporate proxies": "Enterprise security gateways / SASE fronting a company's users "
    "(Zscaler, Netskope).",
    OTHER_HOSTING: "Hosting providers too small for their own column, folded together.",
    RESIDENTIAL_NETWORK: "Consumer ISP, mobile, and otherwise unrecognised networks.",
}


def _network_title(name: str, category: str) -> str:
    """Hover description for a cross-tab column header."""
    if name in _NETWORK_HELP:
        return _NETWORK_HELP[name]
    if category == "datacenter":
        return f"{name}: a datacenter / cloud hosting network."
    return ""


_CSS = """
:root {
  color-scheme: light dark;
  /* Muted secondary text. Mixed from the system ink/paper so it tracks the OS
     theme and clears 4.5:1 in both light and dark (a fixed grey did not). */
  --muted: color-mix(in srgb, CanvasText 58%, Canvas);
  /* Warning ink: a deep amber on light paper, a brighter amber on dark so the
     calibration / robots notices stay legible either way. */
  --warn: light-dark(#b45309, #d97706);
  /* Cross-tab heat (blue). Light-blue reads under dark text on paper; a deeper
     blue reads under light text in dark mode. Set as an "R G B" triple so the
     table script can vary only the alpha. */
  --heat: 96 165 250;
}
@media (prefers-color-scheme: dark) { :root { --heat: 37 99 235; } }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; }
h2 { font-size: 1.25rem; margin: 2.25rem 0 .5rem; }
a { color: inherit; }
.meta { list-style: none; padding: 0; margin: .5rem 0 1.5rem; color: var(--muted); font-size: .92rem; }
.meta li { margin: .15rem 0; }
.meta code { color: CanvasText; }
.warn { color: var(--warn); }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .92rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8884; vertical-align: top; }
th { font-weight: 600; border-bottom: 2px solid #8886; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.netdiv { border-left: 2px solid #8887; }
th.netoff { background: #8881; }
tr.netall td { border-top: 2px solid #8887; }
.netctl { font-size: .9rem; color: var(--muted); margin: .25rem 0 .6rem; }
.netctl select { font: inherit; margin-left: .35rem; }
tr:hover td { background: #8881; }
.badge { display: inline-block; padding: .08rem .5rem; border-radius: 999px;
  color: #fff; font-size: .8rem; font-weight: 600; white-space: nowrap; }
.tag { display: inline-block; padding: .05rem .45rem; margin: 0 .2rem .2rem 0;
  border-radius: 6px; background: #8883; font-size: .78rem; white-space: nowrap; cursor: help; }
.flag { cursor: help; font-style: normal; }
.blurb { color: var(--muted); margin: .15rem 0 .6rem; }
.bar { background: #8883; border-radius: 4px; height: .7rem; min-width: 2px; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
  word-break: break-all; }
td.cid { max-width: 26rem; }
.cid-id { font-weight: 600; }
.cid-as { color: var(--muted); font-size: .8rem; word-break: break-word; margin: 1px 0; }
.cid-ua { color: var(--muted); font-size: .82rem; margin-top: 1px;
  display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3;
  -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
.muted { color: var(--muted); }
.evlist { margin: .25rem 0 .25rem 1rem; padding: 0; }
.evlist li { margin: .1rem 0; }
.primary-sig { font-weight: 600; }
td.copy { cursor: pointer; }
td.copy:hover { background: #8882; }
td.copy.copied { background: #16a34a55; }
details { margin: .25rem 0 1rem; }
summary { cursor: pointer; color: var(--muted); font-size: .9rem; padding: .25rem 0; }
tr.asum { cursor: pointer; }
tr.asum .tri { display: inline-block; margin-right: .5rem; color: #2563eb;
  font-size: 1rem; line-height: 1; vertical-align: middle; transition: transform .12s; }
tbody.actor.open tr.asum .tri { transform: rotate(90deg); }
.actor-ua { color: var(--muted); font-size: .82rem; margin-left: .5rem; }
tbody.actor .amem { display: none; }
tbody.actor.open .amem { display: table-row; }
tr.amem td.cid { padding-left: 1.6rem; }
tr.amem .cid-as { color: var(--muted); font-size: .82rem; }
input.filter { display: block; width: 100%; max-width: 30rem; margin: .5rem 0;
  padding: .4rem .55rem; border: 1px solid #8886; border-radius: 6px;
  background: Canvas; color: CanvasText; font: inherit;
  position: sticky; top: .5rem; z-index: 1; }
footer { margin-top: 3rem; color: var(--muted); font-size: .85rem; }
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

document.addEventListener('click', function (event) {
  if (event.target.closest('[data-copy]')) return;  // a copy cell, not a toggle
  var row = event.target.closest('tr.asum');
  if (!row) return;
  var body = row.parentNode;
  if (body && body.classList.contains('actor')) body.classList.toggle('open');
}, false);

document.addEventListener('click', function (event) {
  // Opening an exclusive accordion (shared name=) closes whichever one was open,
  // possibly above the click -- the page collapses and the reader loses their
  // place. Pin the clicked summary: note its viewport offset, then correct the
  // scroll once the DOM has settled so it stays put.
  var summary = event.target.closest('summary');
  if (!summary) return;
  var details = summary.parentElement;
  if (!details || !details.hasAttribute('name') || details.open) return;
  var before = summary.getBoundingClientRect().top;
  requestAnimationFrame(function () {
    window.scrollBy(0, summary.getBoundingClientRect().top - before);
  });
}, false);

document.addEventListener('input', function (event) {
  var input = event.target;
  if (!input.classList || !input.classList.contains('filter')) return;
  var query = input.value.trim().toLowerCase();
  var on = query.length > 0;
  // While filtering, force every "Show more" disclosure open so hidden matches
  // surface, and suspend the exclusive-accordion name= so all stay open at once;
  // restore both (name re-applied, disclosures re-collapsed) when cleared.
  var details = document.querySelectorAll('details');
  for (var d = 0; d < details.length; d++) {
    var det = details[d], from = on ? 'name' : 'data-name', to = on ? 'data-name' : 'name';
    if (det.hasAttribute(from)) { det.setAttribute(to, det.getAttribute(from)); det.removeAttribute(from); }
    det.open = on;
  }
  // Toggle every client row across every kind against the one query.
  var rows = document.querySelectorAll('tr.frow');
  for (var i = 0; i < rows.length; i++) {
    var hay = rows[i].getAttribute('data-filter') || '';
    rows[i].style.display = hay.indexOf(query) === -1 ? 'none' : '';
  }
  // Collapse a section (header and all) or an emptied disclosure when no client
  // row in it survives the filter; restore when cleared.
  var boxes = document.querySelectorAll('section.kind, details');
  for (var b = 0; b < boxes.length; b++) {
    var live = boxes[b].querySelectorAll('tr.frow:not([style*="none"])');
    boxes[b].style.display = (!on || live.length) ? '' : 'none';
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
        '<footer>Generated by <a href="https://pypi.org/project/agent-census">'
        f"agent-census</a> {_esc(__version__)}.</footer>\n</main>\n"
        f"<script>{_SCRIPT}</script>\n</body>\n</html>\n"
    )


def _kind_badge(kind: Kind) -> str:
    color = _KIND_COLORS.get(kind, "#6b7280")
    return f'<span class="badge" style="background:{color}">{_esc(kind_label(kind))}</span>'


def _tags_html(tags: frozenset[str]) -> str:
    if not tags:
        return '<span class="muted">–</span>'
    spans = []
    for tag in ordered_tags(tags):
        color = _TAG_COLORS.get(tag)
        style = f' style="background:{color};color:#fff"' if color else ""
        description = tag_title(tag)
        title = f' title="{_esc(description)}"' if description else ""
        spans.append(f'<span class="tag"{style}{title}>{_esc(tag)}</span>')
    return "".join(spans)


def _meta_list(
    result: AnalysisResult, source: str, robots_note: str | None, elapsed: float | None
) -> str:
    skips = result.skips
    stats = result.identity_stats
    start, end = time_range(result.rollups)
    items = [
        f"<strong>Source:</strong> <code>{_esc(source)}</code>",
        f"<strong>Lines:</strong> {skips.total_lines:,} total · {skips.parsed:,} parsed · "
        f"{skips.skipped:,} skipped"
        + (f" · {skips.excluded:,} excluded (--vhost)" if skips.excluded else ""),
        f"<strong>Time range:</strong> {_esc(fmt_ts(start))} → {_esc(fmt_ts(end))}",
        f"<strong>Identity:</strong> <code>{_esc(result.identity_strategy)}</code> "
        f"({stats.client_count:,} clients; {stats.singletons:,} singletons; "
        f"{stats.ips_with_multiple_uas:,} IPs with multiple UAs)",
    ]
    if robots_note:
        cls = "warn" if "differ" in robots_note else ""
        items.append(f'<strong>robots.txt:</strong> <span class="{cls}">{_esc(robots_note)}</span>')
    calibration = result.reference_calibration
    if calibration is not None and (warning := calibration.warning()):
        items.append(f'<strong>Calibration:</strong> <span class="warn">{_esc(warning)}</span>')
    if elapsed is not None:
        items.append(f"<em>Analysed in {elapsed:.1f}s</em>")
    return '<ul class="meta">' + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def _share_bar(fraction: float) -> str:
    return (
        f'<div class="bar" style="width:{fraction * 100:.1f}%"></div>'
        f'<span class="muted">{fraction:.0%}</span>'
    )


def _summary_table(result: AnalysisResult) -> str:
    rollups = result.rollups
    total = sum(r.requests for r in rollups.values()) or 1
    total_bytes = sum(r.total_bytes for r in rollups.values()) or 1
    robots_help = (
        "✓ respect: requested no disallowed paths\n"
        "✗ ignore: requested disallowed paths\n"
        "? can't tell: fewer than 5 requests, or no applicable rule"
    )
    head = (
        "<tr><th>Kind</th><th class='num'>Clients</th><th class='num'>Requests</th>"
        "<th>Req share</th><th class='num'>Avg/client</th><th class='num'>Bandwidth</th>"
        f'<th>BW share</th><th title="{_esc(robots_help)}">robots ⓘ</th></tr>'
    )
    rows = []
    for kind in KIND_ORDER:
        rollup = rollups.get(kind)
        if rollup is None or rollup.clients == 0:
            continue
        respects, ignores, unk = (
            rollup.respects_robots,
            rollup.ignores_robots,
            rollup.unknown_robots,
        )
        robots = (
            f"{respects}✓ / {ignores}✗ / {unk}?"
            if (respects or ignores or unk)
            else '<span class="muted">–</span>'
        )
        rows.append(
            f'<tr><td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"<td class='num'>{rollup.clients:,}</td><td class='num'>{rollup.requests:,}</td>"
            f"<td>{_share_bar(rollup.requests / total)}</td>"
            f"<td class='num'>{rollup.requests / rollup.clients:,.0f}</td>"
            f"<td class='num'>{human_bytes(rollup.total_bytes)}</td>"
            f"<td>{_share_bar(rollup.total_bytes / total_bytes)}</td>"
            f"<td>{robots}</td></tr>"
        )
    return (
        f"<h2>Summary by kind</h2>\n<table>{head}{''.join(rows)}</table>\n"
        '<p class="muted">Tip: click a client below to copy its id for '
        "<code>inspect --client</code>.</p>"
    )


# Client-side: recompute the network cross-tab when the toggle changes. Each body
# cell carries data-v (its raw count); the script reformats text, shades a pale-blue
# heat by share of the row (counts / % of kind) or column (% of network) max, and
# bolds that group's leader. The Total column and All-kinds row stay raw counts.
def _num(value: int) -> str:
    return f"{value:,}" if value else "–"


def _network_table(result: AnalysisResult, *, breakout_min_share: float) -> str:
    matrix = network_matrix(
        result.network_rollups,
        result.network_categories,
        min_breakout_share=breakout_min_share,
    )
    if matrix is None:
        return ""
    nets = matrix.networks
    # The first non-hosting column gets the thick hosted|off-network rule; the
    # Total column gets one too. Non-hosting headers carry a faint grey wash.
    first_off = next((i for i, n in enumerate(nets) if not matrix.is_hosting(n)), None)

    def div(i: int) -> str:
        return " netdiv" if i == first_off else ""

    def title(net: str) -> str:
        desc = _network_title(net, matrix.categories.get(net, ""))
        return f' title="{_esc(desc)}"' if desc else ""

    def hd(i: int, net: str) -> str:
        cls = f"num{div(i)}" + ("" if matrix.is_hosting(net) else " netoff")
        hid = " id='netotherhd'" if net == OTHER_HOSTING else ""
        return f"<th class='{cls}'{hid}{title(net)}>{_esc(net)}</th>"

    head = (
        "<tr><th>Kind</th>"
        + "".join(hd(i, n) for i, n in enumerate(nets))
        + "<th class='num netdiv'>Total</th></tr>"
    )

    # The Total column and All-kinds row carry their own (red) heat, keyed to the
    # biggest per-kind and per-network total -- a different axis from the blue cells.
    peak_row = max(matrix.row_totals.values(), default=0)
    peak_col = max(matrix.col_totals.values(), default=0)

    def red(value: int, peak: int) -> str:
        if value <= 0 or peak <= 0:
            return ""
        return f' style="background:rgba(220,38,38,{value / peak * 0.8:.3f})"'

    def cell_extra(net: str, kind: Kind) -> str:
        # Tag the Other-datacentre cells so the break-out control can rewrite them.
        if net != OTHER_HOSTING:
            return ""
        return f" othercol' data-kind='{kind.value}' data-agg='{matrix.cell(net, kind)}"

    rows = []
    for kind in matrix.kinds:
        cells = "".join(
            f"<td class='num mxcell{div(i)}{cell_extra(n, kind)}' data-v='{matrix.cell(n, kind)}'>"
            f"{_num(matrix.cell(n, kind))}</td>"
            for i, n in enumerate(nets)
        )
        rows.append(
            f'<tr><td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"{cells}<td class='num netdiv'{red(matrix.row_totals[kind], peak_row)}>"
            f"{matrix.row_totals[kind]:,}</td></tr>"
        )

    def total_cell(i: int, net: str) -> str:
        col = matrix.col_totals[net]
        # Only the swappable Other column needs its aggregate stashed for restore.
        tag = f" othertot' data-agg='{col}" if net == OTHER_HOSTING else ""
        return f"<td class='num{div(i)}{tag}'{red(col, peak_col)}>{col:,}</td>"

    totals = "".join(total_cell(i, n) for i, n in enumerate(nets))
    rows.append(
        "<tr class='netall'><td><strong>All kinds</strong></td>"
        f"{totals}<td class='num netdiv' style=\"background:rgba(220,38,38,0.8)\">"
        f"{matrix.total:,}</td></tr>"
    )
    breakout = ""
    if matrix.collapsed:
        data = {name: {k.value: v for k, v in counts.items()} for name, counts in matrix.collapsed}
        blob = json.dumps(data, separators=(",", ":")).replace("<", "\\u003c")
        opts = "".join(
            f"<option value='{_esc(name)}'>{_esc(name)} ({sum(counts.values()):,})</option>"
            for name, counts in matrix.collapsed
        )
        breakout = (
            " <label>Break out <select id='netbreakout'>"
            f"<option value=''>{_esc(OTHER_HOSTING)} (all)</option>{opts}"
            "</select></label>"
            f"<script type='application/json' id='netbreakdata'>{blob}</script>"
        )
    control = (
        "<div class='netctl'><label>Show <select id='netmode'>"
        "<option value='count'>counts</option>"
        "<option value='row'>% of kind</option>"
        "<option value='col'>% of network</option>"
        "</select></label>" + breakout + "</div>"
    )
    return (
        "<h2>Requests by kind and network</h2>\n"
        + control
        + f"<table id='nettab'>{head}{''.join(rows)}</table>\n"
        + '<p class="muted">Counts default; the toggle switches to row or column shares '
        "(the Total column keeps the raw count). Cell shading tracks the same axis — "
        "across each kind, or down each network. Hosting reads left of the thick rule, "
        f"off-network (relays / Tor / residential) to its right; smallest hosters fold into "
        f"“{_esc(OTHER_HOSTING)}”"
        + (
            ", and the break-out control swaps that column to show one of them on its own."
            if matrix.collapsed
            else "."
        )
        + "</p>"
        + NET_SCRIPT
    )


_SECTION_HEAD = (
    "<tr><th>Client</th><th class='num'>Requests</th><th class='num'>Bandwidth</th>"
    "<th class='num'>Conf.</th><th>Tags</th><th>Top evidence</th></tr>"
)
# Per-kind cap rendered into the HTML (visible rows + the expandable set).
_EXPAND_LIMIT = 500


def _flag_html(entry: tuple[str, str] | None) -> str:
    """A leading ``'🇩🇪 '`` flag span (country name as the tooltip), or ``''``."""
    if not entry:
        return ""
    emoji, name = entry
    return f'<span class="flag" title="{_esc(name)}">{emoji}</span> '


def _client_cell(profile: ClientProfile, flag: str = "") -> str:
    """Stacked identity cell: IP/network on top, AS org, then the UA (2-line clamp)."""
    prefix, org, ua = client_id_parts(profile)
    org_line = f'<div class="cid-as">{_esc(org)}</div>' if org else ""
    return (
        f'<td class="cid copy" data-copy="{_esc(profile.client_id.ip)}" '
        f'title="Click to copy this id for: inspect --client">'
        f'<div class="mono cid-id">{flag}{_esc(prefix)}</div>'
        f"{org_line}"
        f'<div class="mono cid-ua">{_esc(ua or "–")}</div></td>'
    )


def _client_row(
    profile: ClientProfile,
    *,
    flag: str = "",
    filterable: bool = False,
    suppress: frozenset[str] = frozenset(),
) -> str:
    cls = profile.classification
    evidence = _esc(truncate(top_evidence(profile)))
    attrs = ""
    if filterable:
        _, org, _ = client_id_parts(profile)  # include the shown AS name in the filter
        haystack = " ".join(
            (
                profile.client_id.ip,
                profile.client_id.user_agent or "",
                org or "",
                *ordered_tags(cls.tags - suppress),  # the tags shown in the Tags column
            )
        ).lower()
        attrs = f' class="frow" data-filter="{_esc(haystack)}"'
    return (
        f"<tr{attrs}>{_client_cell(profile, flag)}"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags - suppress)}</td><td>{evidence}</td></tr>"
    )


def _member_tr(profile: ClientProfile, flag: str = "") -> str:
    """A collapsed member as a real table row: IP/AS in Client, its own req/bytes."""
    prefix, _, _ = client_id_parts(profile)
    asn = as_display(profile.features.as_org, profile.features.as_number)
    asn_html = f" <span class='cid-as'>{_esc(asn)}</span>" if asn != "–" else ""
    return (
        f"<tr class='amem'><td class='cid copy' data-copy='{_esc(profile.client_id.ip)}' "
        "title='Click to copy this id for: inspect --client'>"
        f"{flag}<span class='mono'>{_esc(prefix)}</span>{asn_html}</td>"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        "<td></td><td></td><td></td></tr>"
    )


def _ip_member_tr(ip: str, flag: str = "") -> str:
    """A clustered member IP as a row (address only; folded entries keep no per-IP stats)."""
    return (
        f"<tr class='amem'><td class='cid copy' data-copy='{_esc(ip)}' "
        "title='Click to copy this id for: inspect --client'>"
        f"{flag}<span class='mono'>{_esc(ip)}</span></td>"
        "<td></td><td></td><td></td><td></td><td></td></tr>"
    )


def _folded_tbody(
    profile: ClientProfile,
    *,
    flag: str = "",
    flags: CountryFlags | None = None,
    filterable: bool = False,
    suppress: frozenset[str] = frozenset(),
) -> str:
    """A single entry that folded many IPs into one (an ASN operator, a verified
    bot, an egress/subnet cluster): a collapsible summary over its clustered IPs."""
    cls = profile.classification
    prefix, org, ua = client_id_parts(profile)
    members = profile.member_ips
    org_html = f" <span class='cid-as'>{_esc(org)}</span>" if org else ""
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            (prefix, ua or "", org or "", *members, *ordered_tags(cls.tags - suppress))
        ).lower()
        row_attrs = f"class='asum frow' data-filter=\"{_esc(haystack)}\""
    summary = (
        f"<tr {row_attrs}><td class='cid'><span class='tri'>▶</span>"
        f"{flag}<span class='mono'>{_esc(prefix)}</span>{org_html}"
        f"<span class='muted'> · {len(members):,} IPs</span>"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags - suppress)}</td>"
        f"<td>{_esc(truncate(top_evidence(profile)))}</td></tr>"
    )
    cf = flags or CountryFlags()
    rows = "".join(_ip_member_tr(ip, _flag_html(cf.for_ip(ip))) for ip in members)
    return f"<tbody class='actor'>{summary}{rows}</tbody>"


def _actor_tbody(
    actor: ActorGroup,
    *,
    flags: CountryFlags | None = None,
    filterable: bool = False,
    suppress: frozenset[str] = frozenset(),
) -> str:
    """One actor as a ``<tbody>``: a lone client, or a collapsible summary + members.

    The members are ordinary rows sharing the table's Requests/Bandwidth columns,
    hidden until the summary row is clicked (toggled by the page script). ``suppress``
    drops the kind's baseline conduct tags (shown in the header instead).
    """
    cf = flags or CountryFlags()
    flag = _flag_html(cf.for_actor(actor.lead.client_id))
    if not actor.collapsed:
        if len(actor.lead.member_ips) >= 2:
            return _folded_tbody(
                actor.lead, flag=flag, flags=cf, filterable=filterable, suppress=suppress
            )
        return (
            f"<tbody>"
            f"{_client_row(actor.lead, flag=flag, filterable=filterable, suppress=suppress)}"
            f"</tbody>"
        )
    cls = actor.lead.classification
    _, _, ua = client_id_parts(actor.lead)
    shared = actor.shared_asn
    spread = actor_spread(actor.distinct_ips, 0 if shared else actor.distinct_asns)
    # One AS across the fold -> name it (greyed, like the per-client AS) instead of "1 ASNs".
    asn_html = f" <span class='cid-as'>{_esc(as_display(*shared))}</span>" if shared else ""
    evidence = _esc(truncate(top_evidence(actor.lead)))
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            (
                *(
                    f"{m.client_id.ip} {m.client_id.user_agent or ''} {m.features.as_org or ''}"
                    for m in actor.members
                ),
                *ordered_tags(cls.tags - suppress),  # the tags shown in the Tags column
            )
        ).lower()
        row_attrs = f"class='asum frow' data-filter=\"{_esc(haystack)}\""
    summary = (
        f"<tr {row_attrs}>"
        f"<td class='cid'><span class='tri'>▶</span>{flag}{_esc(spread)}{asn_html}"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{actor.requests:,}</td>"
        f"<td class='num'>{human_bytes(actor.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags - suppress)}</td><td>{evidence}</td></tr>"
    )
    members = "".join(_member_tr(m, _flag_html(cf.for_member(m.client_id))) for m in actor.members)
    return f"<tbody class='actor'>{summary}{members}</tbody>"


def _kind_section(
    kind: Kind,
    group: list[ClientProfile],
    rollup: KindRollup,
    top: int,
    flags: CountryFlags | None = None,
) -> str:
    flags = flags or CountryFlags()
    actors = group_actors(group)
    typical = typical_conduct(group)
    title = f"{_kind_badge(kind)} {rollup.clients:,} clients · {rollup.requests:,} requests"
    parts = [
        f'<h2 id="{kind.value}">{title}</h2>',
        f'<p class="blurb">{_esc(KIND_BLURB.get(kind, ""))}</p>',
    ]
    if typical:
        chips = "".join(f'<span class="tag">{_esc(t)}</span>' for t in ordered_tags(typical))
        parts.append(f'<p class="muted">Typically: {chips}</p>')
    shown = "".join(
        _actor_tbody(a, flags=flags, filterable=True, suppress=typical) for a in actors[:top]
    )
    parts.append(f"<table><thead>{_SECTION_HEAD}</thead>{shown}</table>")
    extra = actors[top:_EXPAND_LIMIT]
    if extra:
        extra_rows = "".join(
            _actor_tbody(a, flags=flags, filterable=True, suppress=typical) for a in extra
        )
        parts.append(
            # Shared name -> native exclusive accordion: opening one closes the rest.
            # The page filter (above all sections) suspends the name while active.
            '<details name="kind-extra"><summary>'
            "Show more</summary>"
            f"<table><thead>{_SECTION_HEAD}</thead>{extra_rows}</table>"
            "</details>"
        )
    # rollup.clients is the exact total; only the highest-volume ones are detailed.
    represented = sum(len(a.members) for a in actors[:_EXPAND_LIMIT])
    remaining = rollup.clients - represented
    if remaining > 0:
        parts.append(
            f'<p class="muted">…and {remaining:,} more — '
            f"<code>agent-census inspect --kind {kind.value}</code></p>"
        )
    body = "\n".join(parts)
    return f'<section class="kind">{body}</section>'


def render_report_html(
    result: AnalysisResult,
    *,
    source: str = "stdin",
    top: int = 5,
    robots_note: str | None = None,
    elapsed: float | None = None,
    country_flags: CountryFlags | None = None,
    breakout_min_share: float = BREAKOUT_MIN_SHARE,
) -> str:
    """Render the full analysis report as a standalone HTML page."""
    flags = country_flags or CountryFlags()
    groups = by_kind(result.profiles)
    heading = "Agent Census" + (f" — {result.site}" if result.site else "")
    parts = [
        f"<h1>{_esc(heading)}</h1>",
        _meta_list(result, source, robots_note, elapsed),
        _summary_table(result),
        _network_table(result, breakout_min_share=breakout_min_share),
        '<input class="filter" type="search" '
        'placeholder="filter all clients by IP, User-Agent, AS name, or tag…" '
        'aria-label="filter clients">',
    ]
    for kind in KIND_ORDER:
        rollup = result.rollups.get(kind)
        if rollup and rollup.clients:
            parts.append(_kind_section(kind, groups.get(kind, []), rollup, top, flags))
    return _page(heading, "\n".join(parts))


# --- inspect mode ----------------------------------------------------------


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
        chip = f'<span class="tag" title="{_esc(tag_title(tag))}">{_esc(tag)}</span>'
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
