"""Render analysis results and inspection traces as a self-contained HTML page.

The page is built from the same structured data the Markdown renderer uses, with
a small built-in template (:data:`_CSS` + :func:`_page`) so the output is one
file you can open in a browser -- no external assets, no dependencies.
"""

from __future__ import annotations

import html
from functools import lru_cache

from ..dataload import load_egress_networks
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
    top_evidence,
    truncate,
)
from .inspect import ROLLUP_MIN_CLIENTS

_KIND_COLORS: dict[Kind, str] = {
    Kind.BROWSER: "#2563eb",
    Kind.CRAWLER: "#0891b2",
    Kind.SEARCH_ENGINE: "#16a34a",
    Kind.ARCHIVER: "#047857",
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
    "impersonator": "#dc2626",
    "ignores-robots": "#d97706",
    "probing": "#dc2626",  # requested attack paths -> red
    "404-storm": "#d97706",
    "ancient-ua": "#dc2626",  # years-stale browser version -> almost certainly spoofed
    "datacenter": "#9333ea",  # origin is hosting, not an eyeball network -> purple
    "ua-rotating": "#d97706",  # many UAs from a hosting/non-browser source -> amber
    "forged-referer": "#dc2626",  # Referer faked to mimic navigation -> red
    "icloud-private-relay": "#0284c7",  # privacy relay; a positive browser signal -> blue
    "tor-exit": "#6d28d9",  # Tor exit node; anonymised egress -> violet
    # 'shared-ip' is left neutral (grey): many UAs but a benign shared egress.
}

# Hover descriptions for the tags (rendered as a native title= tooltip). Egress
# network tags are described from the data file, so new networks get tooltips
# without touching this table.
_TAG_HELP: dict[str, str] = {
    "datacenter": "Source IP is in a known datacenter / cloud hosting range, "
    "not a consumer or ISP network.",
    "bursty": "Irregular, bursty request timing — human-like, not clockwork.",
    "steady": "Moderately regular request timing.",
    "loads-assets": "After fetching pages it pulled their sub-resources (CSS/JS/images) — "
    "the browser fingerprint.",
    "no-assets": "Fetched HTML pages but never their sub-resources — not rendering them "
    "like a browser.",
    "follows-links": "Often arrives at a page via a Referer it fetched earlier — on-site "
    "navigation.",
    "cold": "Requests pages cold, without following on-site links.",
    "browser-ua": "User-Agent matches a real browser profile (Mozilla + a layout engine).",
    "generic-ua": "User-Agent is a generic HTTP library/tool (curl, python-requests…), not a "
    "named agent.",
    "bot-ua": "User-Agent self-identifies as a bot/crawler.",
    "post-heavy": "Most requests are POSTs — form/submission traffic, e.g. comment or login spam.",
    "has-cache": "Received 304 Not Modified responses — makes conditional requests "
    "and holds a real cache, the mark of a browser or a polite poller.",
    "uses-HEAD": "Issues HEAD requests for more than an incidental share of its traffic "
    "— browsers fetch with GET, so this points to a monitor, link-checker, or other bot.",
    "current-ua": "Claims a browser version current for when it was active — consistent "
    "with a real, auto-updating browser.",
    "stale-ua": "Claims a browser version well behind the release cadence for its active "
    "period; unusual for an auto-updating browser.",
    "ancient-ua": "Claims a browser version years out of date. Chromium and Firefox "
    "auto-update, so this is almost always a frozen, spoofed User-Agent.",
    "checked-robots": "Requested /robots.txt at some point.",
    "no-user-agent": "Sent no User-Agent header.",
    "ua-rotating": "Many distinct User-Agents from one IP, paired with a hosting origin "
    "or non-browser behaviour — likely UA rotation to evade limits.",
    "shared-ip": "Many distinct User-Agents from one IP but behaving normally — a shared "
    "egress such as NAT, VPN, proxy, or carrier gateway.",
    "ignores-robots": "Requested paths disallowed by the applicable robots.txt group.",
    "verified": "Reverse/forward DNS or a published IP range confirmed the declared "
    "crawler identity.",
    "declares-known-bot": "User-Agent names a known crawler (identity verified separately).",
    "asn-attributed": "Recognised by its origin AS number, configured as a known crawler "
    "network, rather than by its User-Agent.",
    "probing": "Requested known-vulnerable paths or used directory-traversal patterns.",
    "exotic-method": "Used uncommon HTTP methods (PUT/DELETE/PROPFIND/CONNECT…) — typical of "
    "scanners and WebDAV probes, not browsers.",
    "404-storm": "A high share of 404s spread across many distinct paths — scanning for "
    "content, or a broken integration.",
    "metronomic": "Near-constant intervals between requests — clockwork timing characteristic "
    "of automation, not a human.",
    "forged-referer": "Sends a Referer equal to the requested URL — fabricated "
    "navigation, not something a real browser produces.",
    "fetches-non-feeds": "A feed reader that also requested non-feed resources.",
}


@lru_cache(maxsize=None)
def _egress_tag_help() -> dict[str, str]:
    return {
        net.tag: f"{net.name}: a shared-egress network (privacy relay / proxy). "
        "Its requests are folded into one entry per User-Agent."
        for net in load_egress_networks()
        if net.tag
    }


def _tag_title(tag: str) -> str:
    """Hover description for a tag, or '' if none is known."""
    return _TAG_HELP.get(tag) or _egress_tag_help().get(tag, "")


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
.netdiv { border-left: 2px solid #8887; }
th.netoff { background: #8881; }
tr.netall td { border-top: 2px solid #8887; }
.netctl { font-size: .9rem; color: #6b7280; margin: .25rem 0 .6rem; }
.netctl select { font: inherit; margin-left: .35rem; }
tr:hover td { background: #8881; }
.badge { display: inline-block; padding: .08rem .5rem; border-radius: 999px;
  color: #fff; font-size: .8rem; font-weight: 600; white-space: nowrap; }
.tag { display: inline-block; padding: .05rem .45rem; margin: 0 .2rem .2rem 0;
  border-radius: 6px; background: #8883; font-size: .78rem; white-space: nowrap; cursor: help; }
.blurb { color: #6b7280; margin: .15rem 0 .6rem; }
.bar { background: #8883; border-radius: 4px; height: .7rem; min-width: 2px; }
.card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.1rem; margin: 1rem 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem;
  word-break: break-all; }
td.cid { max-width: 26rem; }
.cid-id { font-weight: 600; }
.cid-as { color: #6b7280; font-size: .8rem; word-break: break-word; margin: 1px 0; }
.cid-ua { color: #6b7280; font-size: .82rem; margin-top: 1px;
  display: -webkit-box; -webkit-line-clamp: 3; line-clamp: 3;
  -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
.muted { color: #6b7280; }
.evlist { margin: .25rem 0 .25rem 1rem; padding: 0; }
.evlist li { margin: .1rem 0; }
.primary-sig { font-weight: 600; }
td.copy { cursor: pointer; }
td.copy:hover { background: #8882; }
td.copy.copied { background: #16a34a55; }
details { margin: .25rem 0 1rem; }
summary { cursor: pointer; color: #6b7280; font-size: .9rem; padding: .25rem 0; }
tr.asum { cursor: pointer; }
tr.asum .tri { display: inline-block; margin-right: .5rem; color: #2563eb;
  font-size: 1rem; line-height: 1; vertical-align: middle; transition: transform .12s; }
tbody.actor.open tr.asum .tri { transform: rotate(90deg); }
.actor-ua { color: #6b7280; font-size: .82rem; margin-left: .5rem; }
tbody.actor .amem { display: none; }
tbody.actor.open .amem { display: table-row; }
tr.amem td.cid { padding-left: 1.6rem; }
tr.amem .cid-as { color: #6b7280; font-size: .82rem; }
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
    return f'<span class="badge" style="background:{color}">{_esc(kind_label(kind))}</span>'


def _tags_html(tags: frozenset[str]) -> str:
    if not tags:
        return '<span class="muted">–</span>'
    spans = []
    for tag in ordered_tags(tags):
        color = _TAG_COLORS.get(tag)
        style = f' style="background:{color};color:#fff"' if color else ""
        description = _tag_title(tag)
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
_NET_SCRIPT = """
<script>
(function(){
  var tab=document.getElementById('nettab'); if(!tab) return;
  var sel=document.getElementById('netmode'); if(!sel) return;
  var cells=[].slice.call(tab.querySelectorAll('td.mxcell'));
  var byRow={}, byCol={};
  cells.forEach(function(c){
    var r=c.parentNode.rowIndex, col=c.cellIndex; c._v=+c.getAttribute('data-v');
    (byRow[r]=byRow[r]||[]).push(c);
    (byCol[col]=byCol[col]||[]).push(c);
  });
  function paint(mode){
    var groups=(mode==='col')?byCol:byRow;
    cells.forEach(function(c){c.style.background='';c.style.fontWeight='';});
    Object.keys(groups).forEach(function(k){
      var g=groups[k], tot=0, mx=0;
      g.forEach(function(c){tot+=c._v; if(c._v>mx)mx=c._v;});
      g.forEach(function(c){
        var v=c._v;
        c.textContent = (mode==='count') ? (v?v.toLocaleString():'\\u2013')
                                         : ((v&&tot)?Math.round(v/tot*100)+'%':'\\u2013');
        if(v>0&&mx>0) c.style.background='rgba(96,165,250,'+(v/mx*0.8).toFixed(3)+')';
        if(v>0&&v===mx) c.style.fontWeight='500';
      });
    });
  }
  sel.addEventListener('change',function(){paint(sel.value);});
  paint('count');
})();
</script>
""".strip()


def _num(value: int) -> str:
    return f"{value:,}" if value else "–"


def _network_table(result: AnalysisResult) -> str:
    matrix = network_matrix(result.network_rollups, result.network_categories)
    if matrix is None:
        return ""
    nets = matrix.networks
    # The first non-hosting column gets the thick hosted|off-network rule; the
    # Total column gets one too. Non-hosting headers carry a faint grey wash.
    first_off = next((i for i, n in enumerate(nets) if not matrix.is_hosting(n)), None)

    def div(i: int) -> str:
        return " netdiv" if i == first_off else ""

    head = (
        "<tr><th>Kind</th>"
        + "".join(
            f"<th class='num{div(i)}{'' if matrix.is_hosting(n) else ' netoff'}'>{_esc(n)}</th>"
            for i, n in enumerate(nets)
        )
        + "<th class='num netdiv'>Total</th></tr>"
    )

    rows = []
    for kind in matrix.kinds:
        cells = "".join(
            f"<td class='num mxcell{div(i)}' data-v='{matrix.cell(n, kind)}'>"
            f"{_num(matrix.cell(n, kind))}</td>"
            for i, n in enumerate(nets)
        )
        rows.append(
            f'<tr><td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"{cells}<td class='num netdiv'>{matrix.row_totals[kind]:,}</td></tr>"
        )
    totals = "".join(
        f"<td class='num{div(i)}'>{matrix.col_totals[n]:,}</td>" for i, n in enumerate(nets)
    )
    rows.append(
        "<tr class='netall'><td><strong>All kinds</strong></td>"
        f"{totals}<td class='num netdiv'>{matrix.total:,}</td></tr>"
    )
    control = (
        "<div class='netctl'><label>Show <select id='netmode'>"
        "<option value='count'>counts</option>"
        "<option value='row'>% of kind</option>"
        "<option value='col'>% of network</option>"
        "</select></label></div>"
    )
    return (
        "<h2>Requests by kind and network</h2>\n"
        + control
        + f"<table id='nettab'>{head}{''.join(rows)}</table>\n"
        + '<p class="muted">Counts default; the toggle switches to row or column shares '
        "(the Total column keeps the raw count). Cell shading tracks the same axis — "
        "across each kind, or down each network. Hosting reads left of the thick rule, "
        f"off-network (relays / Tor / residential) to its right; smallest hosters fold into "
        f"“{_esc(OTHER_HOSTING)}”.</p>" + _NET_SCRIPT
    )


_SECTION_HEAD = (
    "<tr><th>Client</th><th class='num'>Requests</th><th class='num'>Bandwidth</th>"
    "<th class='num'>Conf.</th><th>Tags</th><th>Top evidence</th></tr>"
)
# Per-kind cap rendered into the HTML (visible rows + the expandable set).
_EXPAND_LIMIT = 500


def _client_cell(profile: ClientProfile) -> str:
    """Stacked identity cell: IP/network on top, AS org, then the UA (2-line clamp)."""
    prefix, org, ua = client_id_parts(profile)
    org_line = f'<div class="cid-as">{_esc(org)}</div>' if org else ""
    return (
        f'<td class="cid copy" data-copy="{_esc(profile.client_id.ip)}" '
        f'title="Click to copy this id for: inspect --client">'
        f'<div class="mono cid-id">{_esc(prefix)}</div>'
        f"{org_line}"
        f'<div class="mono cid-ua">{_esc(ua or "–")}</div></td>'
    )


def _client_row(profile: ClientProfile, *, filterable: bool = False) -> str:
    cls = profile.classification
    evidence = _esc(truncate(top_evidence(profile)))
    attrs = ""
    if filterable:
        _, org, _ = client_id_parts(profile)  # include the shown AS name in the filter
        haystack = " ".join(
            (profile.client_id.ip, profile.client_id.user_agent or "", org or "")
        ).lower()
        attrs = f' class="frow" data-filter="{_esc(haystack)}"'
    return (
        f"<tr{attrs}>{_client_cell(profile)}"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td><td>{evidence}</td></tr>"
    )


def _member_tr(profile: ClientProfile) -> str:
    """A collapsed member as a real table row: IP/AS in Client, its own req/bytes."""
    prefix, _, _ = client_id_parts(profile)
    asn = as_display(profile.features.as_org, profile.features.as_number)
    asn_html = f" <span class='cid-as'>{_esc(asn)}</span>" if asn != "–" else ""
    return (
        f"<tr class='amem'><td class='cid copy' data-copy='{_esc(profile.client_id.ip)}' "
        "title='Click to copy this id for: inspect --client'>"
        f"<span class='mono'>{_esc(prefix)}</span>{asn_html}</td>"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        "<td></td><td></td><td></td></tr>"
    )


def _ip_member_tr(ip: str) -> str:
    """A clustered member IP as a row (address only; folded entries keep no per-IP stats)."""
    return (
        f"<tr class='amem'><td class='cid copy' data-copy='{_esc(ip)}' "
        "title='Click to copy this id for: inspect --client'>"
        f"<span class='mono'>{_esc(ip)}</span></td>"
        "<td></td><td></td><td></td><td></td><td></td></tr>"
    )


def _folded_tbody(profile: ClientProfile, *, filterable: bool = False) -> str:
    """A single entry that folded many IPs into one (an ASN operator, a verified
    bot, an egress/subnet cluster): a collapsible summary over its clustered IPs."""
    cls = profile.classification
    prefix, org, ua = client_id_parts(profile)
    members = profile.member_ips
    org_html = f" <span class='cid-as'>{_esc(org)}</span>" if org else ""
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join((prefix, ua or "", org or "", *members)).lower()
        row_attrs = f"class='asum frow' data-filter=\"{_esc(haystack)}\""
    summary = (
        f"<tr {row_attrs}><td class='cid'><span class='tri'>▶</span>"
        f"<span class='mono'>{_esc(prefix)}</span>{org_html}"
        f"<span class='muted'> · {len(members):,} IPs</span>"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td>"
        f"<td>{_esc(truncate(top_evidence(profile)))}</td></tr>"
    )
    rows = "".join(_ip_member_tr(ip) for ip in members)
    return f"<tbody class='actor'>{summary}{rows}</tbody>"


def _actor_tbody(actor: ActorGroup, *, filterable: bool = False) -> str:
    """One actor as a ``<tbody>``: a lone client, or a collapsible summary + members.

    The members are ordinary rows sharing the table's Requests/Bandwidth columns,
    hidden until the summary row is clicked (toggled by the page script).
    """
    if not actor.collapsed:
        if len(actor.lead.member_ips) >= 2:
            return _folded_tbody(actor.lead, filterable=filterable)
        return f"<tbody>{_client_row(actor.lead, filterable=filterable)}</tbody>"
    cls = actor.lead.classification
    _, _, ua = client_id_parts(actor.lead)
    spread = actor_spread(actor.distinct_ips, actor.distinct_asns)
    evidence = _esc(truncate(top_evidence(actor.lead)))
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            f"{m.client_id.ip} {m.client_id.user_agent or ''} {m.features.as_org or ''}"
            for m in actor.members
        ).lower()
        row_attrs = f"class='asum frow' data-filter=\"{_esc(haystack)}\""
    summary = (
        f"<tr {row_attrs}>"
        f"<td class='cid'><span class='tri'>▶</span>{_esc(spread)}"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{actor.requests:,}</td>"
        f"<td class='num'>{human_bytes(actor.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td><td>{evidence}</td></tr>"
    )
    members = "".join(_member_tr(m) for m in actor.members)
    return f"<tbody class='actor'>{summary}{members}</tbody>"


def _kind_section(kind: Kind, group: list[ClientProfile], rollup: KindRollup, top: int) -> str:
    actors = group_actors(group)
    title = f"{_kind_badge(kind)} {rollup.clients:,} clients · {rollup.requests:,} requests"
    parts = [
        f'<h2 id="{kind.value}">{title}</h2>',
        f'<p class="blurb">{_esc(KIND_BLURB.get(kind, ""))}</p>',
        f"<table><thead>{_SECTION_HEAD}</thead>"
        f"{''.join(_actor_tbody(a) for a in actors[:top])}</table>",
    ]
    extra = actors[top:_EXPAND_LIMIT]
    if extra:
        extra_rows = "".join(_actor_tbody(a, filterable=True) for a in extra)
        parts.append(
            # Shared name -> native exclusive accordion: opening one closes the rest.
            '<details name="kind-extra"><summary>'
            "Show more</summary>"
            '<input class="filter" type="search" '
            'placeholder="filter these by IP, User-Agent, or AS name…" '
            'aria-label="filter clients">'
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
    return "\n".join(parts)


def render_report_html(
    result: AnalysisResult,
    *,
    source: str = "stdin",
    top: int = 5,
    robots_note: str | None = None,
    elapsed: float | None = None,
) -> str:
    """Render the full analysis report as a standalone HTML page."""
    groups = by_kind(result.profiles)
    parts = [
        "<h1>Agent Census</h1>",
        _meta_list(result, source, robots_note, elapsed),
        _summary_table(result),
        _network_table(result),
    ]
    for kind in KIND_ORDER:
        rollup = result.rollups.get(kind)
        if rollup and rollup.clients:
            parts.append(_kind_section(kind, groups.get(kind, []), rollup, top))
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
