"""Render analysis results and inspection traces as a self-contained HTML page.

The page is built from the same structured data the Markdown renderer uses, with
a small built-in template (:func:`_page`, styled and scripted from the CSS/JS in
:mod:`._assets`) so the output is one file you can open in a browser -- no
external assets, no dependencies.
"""

from __future__ import annotations

import html

from .. import __version__
from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, AnalysisResult, KindRollup
from ._assets import CSS, SCRIPT
from ._netscript import NET_SCRIPT
from ._sparkline import Window as _Window
from ._sparkline import aggregate_buckets as _aggregate_buckets
from ._sparkline import axis_span as _axis_span
from ._sparkline import client_spark_peak as _client_spark_peak
from ._sparkline import kind_sparklines as _kind_sparklines
from ._sparkline import member_pattern as _member_pattern
from ._sparkline import pattern_cell as _pattern_cell
from ._sparkline import pattern_cell_for as _pattern_cell_for
from .aggregate import (
    BREAKOUT_MIN_SHARE,
    KIND_BLURB,
    KIND_ORDER,
    ActorGroup,
    NetworkMatrix,
    by_kind,
    group_actors,
    network_matrix,
    time_range,
)
from .format import (
    actor_spread,
    as_display,
    client_id_parts,
    count,
    fmt_ts,
    human_bytes,
    kind_label,
    ordered_tags,
    tag_title,
    top_evidence,
)
from .geo import CountryFlags

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
    OTHER_HOSTING: (
        "Hosting providers too small for their own column, plus any datacentre "
        "columns still scrolled off to the right — scroll right to reveal them."
    ),
    RESIDENTIAL_NETWORK: "Consumer ISP, mobile, and otherwise unrecognised networks.",
}


def _network_title(name: str, category: str) -> str:
    """Hover description for a cross-tab column header."""
    if name in _NETWORK_HELP:
        return _NETWORK_HELP[name]
    if category == "datacenter":
        return f"{name}: a datacenter / cloud hosting network."
    return ""


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _page(title: str, content: str) -> str:
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{CSS}</style>\n"
        f'</head>\n<body>\n<main class="container">\n{content}\n'
        '<footer>Generated by <a href="https://pypi.org/project/agent-census">'
        f"agent-census</a> {_esc(__version__)}.</footer>\n</main>\n"
        f"<script>{SCRIPT}</script>\n</body>\n</html>\n"
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
        + (f" · {skips.excluded:,} excluded (--vhost)" if skips.excluded else "")
        + (f" · {skips.out_of_window:,} before --since" if skips.out_of_window else ""),
        f"<strong>Time range:</strong> {_esc(fmt_ts(start))} → {_esc(fmt_ts(end))}",
        f"<strong>Identity:</strong> <code>{_esc(result.identity_strategy)}</code> "
        f"({count(stats.client_count, 'client')}; {count(stats.singletons, 'singleton')}; "
        f"{count(stats.ips_with_multiple_uas, 'IP')} with multiple UAs)",
    ]
    if result.skipped_files:
        items.insert(
            2,
            f"<strong>Skipped:</strong> {count(len(result.skipped_files), 'file')} "
            "entirely before --since",
        )
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


# Stacked robots-compliance bar: respect (green) / violate (red) / can't-tell
# (grey). Only the wrapper carries a tooltip — the full three-way breakdown —
# so a hover anywhere on the bar shows every count, even on a thin slice.
_ROBOTS_SEGMENTS = (
    ("respects_robots", "#34a853", "respect"),
    ("ignores_robots", "#e2574c", "violate"),
    ("unknown_robots", "#d0d4da", "can't tell"),
)


def _robots_bar(respects: int, ignores: int, unk: int) -> str:
    total = respects + ignores + unk
    if total == 0:
        return '<span class="muted">–</span>'
    counts = {"respects_robots": respects, "ignores_robots": ignores, "unknown_robots": unk}
    segments = []
    for key, color, _label in _ROBOTS_SEGMENTS:
        seg_count = counts[key]
        if seg_count == 0:
            continue
        pct = seg_count / total * 100
        segments.append(f'<span style="width:{pct:.3f}%;background:{color}"></span>')
    summary = f"{respects:,} respect / {ignores:,} violate / {unk:,} can't tell"
    return f'<div class="rbar" title="{_esc(summary)}">{"".join(segments)}</div>'


def _summary_table(result: AnalysisResult, patterns: dict[Kind, str], window: _Window) -> str:
    # `patterns`: per-kind cadence glyph, on the shared sparkline axis (see
    # `kind_sparklines`). Its "Requests over <span>" header matches the per-client table.
    rollups = result.rollups
    total = sum(r.requests for r in rollups.values()) or 1
    total_bytes = sum(r.total_bytes for r in rollups.values()) or 1
    robots_help = (
        "Share of clients by robots.txt compliance — hover a bar for counts.\n"
        "green respect: requested no disallowed paths\n"
        "red violate: requested disallowed paths\n"
        "grey can't tell: fewer than 5 requests, or no applicable rule"
    )
    head = (
        "<tr><th>Kind</th><th class='num'>Clients</th><th class='num'>Requests</th>"
        f"<th>Req share</th><th class='reqpat'>Requests over {_axis_span(window)}</th>"
        "<th class='num'>Bandwidth</th><th>BW share</th>"
        f'<th title="{_esc(robots_help)}">robots.txt compliance ⓘ</th></tr>'
    )
    rows = []
    for kind in KIND_ORDER:
        rollup = rollups.get(kind)
        if rollup is None or rollup.clients == 0:
            continue
        robots = _robots_bar(
            rollup.respects_robots,
            rollup.ignores_robots,
            rollup.unknown_robots,
        )
        rows.append(
            f'<tr><td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"<td class='num'>{rollup.clients:,}</td><td class='num'>{rollup.requests:,}</td>"
            f"<td>{_share_bar(rollup.requests / total)}</td>"
            f"<td class='reqpat'>{patterns.get(kind, '')}</td>"
            f"<td class='num'>{human_bytes(rollup.total_bytes)}</td>"
            f"<td>{_share_bar(rollup.total_bytes / total_bytes)}</td>"
            f"<td>{robots}</td></tr>"
        )
    return (
        f"<h2>Summary by kind</h2>\n"
        f"<div class='tscroll'><table>{head}{''.join(rows)}</table></div>\n"
        '<p class="hint">Click a kind to show only it; click a client below '
        "to copy its id for <code>inspect --client</code>.</p>"
    )


# Client-side: recompute the network cross-tab when the toggle changes. Each body
# cell carries data-v (its raw count); the script reformats text, shades a pale-blue
# heat by share of the row (counts / % of kind) or column (% of network) max, and
# bolds that group's leader. The Total column and All-kinds row stay raw counts.
def _num(value: int) -> str:
    return f"{value:,}" if value else "–"


def _net_col_index(
    matrix: NetworkMatrix | None, network_rollups: dict[str, dict[Kind, KindRollup]]
) -> dict[str, int]:
    """Map each raw origin-network name to the cross-tab column index it lands in.

    A named column maps to itself; every datacentre folded into ``OTHER_HOSTING``
    (and the literal ``OTHER_HOSTING`` fallback) maps to that column. This is the
    same collapse :func:`network_matrix` applies, so a client row's column matches
    the cell the reader clicks. Used to tag client rows for the network filter.
    """
    if matrix is None:
        return {}
    index = {net: i for i, net in enumerate(matrix.networks)}
    out: dict[str, int] = {}
    for net in network_rollups:
        col = net if net in index else OTHER_HOSTING
        if col in index:
            out[net] = index[col]
    return out


def _netcol_attr(profiles: list[ClientProfile], net_col: dict[str, int]) -> str:
    """``data-netcol`` listing the column indices an actor's members occupy.

    An actor group folds clients that differ only by IP/ASN, so its members can
    span several networks; the network filter shows the row if *any* member is in
    the chosen column.
    """
    if not net_col:
        return ""
    idxs = sorted({net_col[p.network] for p in profiles if p.network in net_col})
    return f' data-netcol="{" ".join(str(i) for i in idxs)}"' if idxs else ""


def _network_table(matrix: NetworkMatrix | None) -> str:
    if matrix is None:
        return ""
    nets = matrix.networks
    has_other = OTHER_HOSTING in nets
    # The first non-hosting column gets the thick hosted|off-network rule. Non-hosting
    # headers carry a faint grey wash.
    first_off = next((i for i, n in enumerate(nets) if not matrix.is_hosting(n)), None)

    def div(i: int) -> str:
        return " netdiv" if i == first_off else ""

    def title(net: str) -> str:
        desc = _network_title(net, matrix.categories.get(net, ""))
        return f' title="{_esc(desc)}"' if desc else ""

    def is_dc(net: str) -> bool:
        return matrix.is_hosting(net) and net != OTHER_HOSTING

    # Column roles. Named datacentres scroll horizontally (class ``dcs``); the pinned
    # "Other datacenters", the off-network columns and Total stay put (``stick-r``),
    # as does Kind on the left (``stick-l``). Other reads as part of the datacentre
    # group, so the heavy group rule sits after it (the ``netdiv`` before off-network).
    def role(net: str) -> str:
        return " dcs" if is_dc(net) else " stick-r"

    def hd(i: int, net: str) -> str:
        cls = f"num vh{div(i)}{role(net)}" + ("" if matrix.is_hosting(net) else " netoff")
        hid = " id='netotherhd'" if net == OTHER_HOSTING else ""
        cue = "<b class='othercue' aria-hidden='true'></b>" if net == OTHER_HOSTING else ""
        return (
            f"<th class='{cls}'{hid}{title(net)} data-net='{i}'>"
            f"<span>{_esc(net)}</span>{cue}</th>"
        )

    head = (
        "<tr><th class='stick-l'>Kind</th>"
        + "".join(hd(i, n) for i, n in enumerate(nets))
        + "<th class='num netdiv stick-r'>Total</th></tr>"
    )

    # The Total column and All-kinds row carry their own (red) heat, keyed to the
    # biggest per-kind and per-network total -- a different axis from the blue cells.
    peak_row = max(matrix.row_totals.values(), default=0)
    peak_col = max(matrix.col_totals.values(), default=0)

    def heat(value: int, peak: int) -> str:
        # Red magnitude heat as a background-IMAGE (over the cell's opaque base) so a
        # pinned cell stays solid above the datacentre columns scrolling behind it.
        if value <= 0 or peak <= 0:
            return ""
        alpha = value / peak * 0.8
        return (
            ' style="background-image:linear-gradient('
            f'rgba(220,38,38,{alpha:.3f}),rgba(220,38,38,{alpha:.3f}))"'
        )

    def cell_cls(i: int, net: str) -> str:
        return f"num mxcell{div(i)}{role(net)}" + (" othercol" if net == OTHER_HOSTING else "")

    def cell_attrs(net: str, kind: Kind) -> str:
        # The pinned Other body cells fold in whatever datacentre columns are scrolled
        # out of view; data-agg is the static folded tail those are added onto.
        if net != OTHER_HOSTING:
            return ""
        return f" data-kind='{kind.value}' data-agg='{matrix.cell(net, kind)}'"

    rows = []
    for kind in matrix.kinds:
        cells = "".join(
            f"<td class='{cell_cls(i, n)}' data-v='{matrix.cell(n, kind)}' "
            f"data-net='{i}'{cell_attrs(n, kind)}>{_num(matrix.cell(n, kind))}</td>"
            for i, n in enumerate(nets)
        )
        rows.append(
            f'<tr><td class="stick-l"><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
            f"{cells}<td class='num netdiv stick-r'{heat(matrix.row_totals[kind], peak_row)}>"
            f"{matrix.row_totals[kind]:,}</td></tr>"
        )

    def total_cell(i: int, net: str) -> str:
        col = matrix.col_totals[net]
        cls = f"num{div(i)}{role(net)}" + (" othertot" if net == OTHER_HOSTING else "")
        # The pinned Other total grows as datacentres scroll out of view; stash its
        # aggregate (folded tail) and the peak so the script can re-tally and re-heat.
        agg = f" data-agg='{col}' data-peak='{peak_col}'" if net == OTHER_HOSTING else ""
        # data-v lets the script fold scrolled-out datacentre totals into the live
        # Other total too (these cells aren't mxcell, so paint() leaves them alone).
        return (
            f"<td class='{cls}'{heat(col, peak_col)} data-net='{i}' "
            f"data-v='{col}'{agg}>{col:,}</td>"
        )

    totals = "".join(total_cell(i, n) for i, n in enumerate(nets))
    rows.append(
        "<tr class='netall'><td class='stick-l'><strong>All kinds</strong></td>"
        f"{totals}<td class='num netdiv stick-r'"
        ' style="background-image:linear-gradient(rgba(220,38,38,0.8),rgba(220,38,38,0.8))">'
        f"{matrix.total:,}</td></tr>"
    )
    # Phone fallback: a picker for the single network column shown when the matrix
    # folds (see the .netcolctl media query). Defaults to the busiest network.
    colpick = ""
    if len(nets) > 1:
        default_i = max(range(len(nets)), key=lambda i: matrix.col_totals[nets[i]])
        col_opts = "".join(
            f"<option value='{i}'{' selected' if i == default_i else ''}>"
            f"{_esc(net)} ({matrix.col_totals[net]:,})</option>"
            for i, net in enumerate(nets)
        )
        colpick = (
            f" <label class='netcolctl'>Column <select id='netcol'>{col_opts}</select></label>"
        )
    control = (
        "<div class='netctl'><label>Show <select id='netmode'>"
        "<option value='count'>counts</option>"
        "<option value='row'>% of kind</option>"
        "<option value='col'>% of network</option>"
        "</select></label>" + colpick + "</div>"
    )
    # The spatial guidance only makes sense with every column visible (desktop);
    # on a phone the table folds to one network, so swap in a note about the picker.
    spatial = (
        "Hosting reads left of the thick rule, off-network "
        "(relays / Tor / residential) to its right."
        + (
            " The named datacentres scroll horizontally; the smallest fold into the "
            f"pinned “{_esc(OTHER_HOSTING)}” column, which tallies whatever is scrolled "
            "out of view."
            if has_other
            else ""
        )
    )
    narrow = (
        " <span class='netnarrow'>On a narrow screen the table folds to one network — "
        "choose which with the Column control above.</span>"
        if len(nets) > 1
        else ""
    )
    # Up-front affordance cue (italic/grey); the caption below carries the finer points.
    hint = (
        '<p class="hint">Click a cell to filter the report to that kind and network — '
        "use “Show all” (by the filter box) to clear.</p>"
    )
    caption = (
        '<p class="muted">A Total-column number filters by kind only; an All-kinds '
        f"number by network only; “{_esc(OTHER_HOSTING)}” covers the folded small "
        "datacentres. Counts default; the toggle switches to row or column shares "
        "(the Total column keeps the raw count). Cell shading tracks the same axis — "
        "across each kind, or down each network. "
        f"<span class='netwide'>{spatial}</span>{narrow}</p>"
    )
    return (
        "<h2>Requests by kind and network</h2>\n"
        + hint
        + control
        + f"<div class='tscroll'><table id='nettab'>{head}{''.join(rows)}</table></div>\n"
        + caption
        + NET_SCRIPT
    )


def _section_head(window: _Window) -> str:
    """The client-table header row. The request-pattern column reads "Requests over
    <span>", naming the span its shared x-axis covers (every sparkline in the report
    is drawn against it), with the exact start -> end on hover."""
    return (
        "<tr><th>Client</th><th class='num'>Requests</th><th class='num'>Bandwidth</th>"
        f"<th class='num'>Conf.</th><th>Tags</th>"
        f"<th class='reqpat'>Requests over {_axis_span(window)}</th></tr>"
    )


# Per-kind cap rendered into the HTML (visible rows + the expandable set).
_EXPAND_LIMIT = 200


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
    net_col: dict[str, int] | None = None,
    window: _Window = None,
    peak: int | None = None,
) -> str:
    cls = profile.classification
    pattern = _pattern_cell_for(profile, window, peak)
    attrs = ""
    if filterable:
        _, org, _ = client_id_parts(profile)  # include the shown AS name in the filter
        haystack = " ".join(
            (
                profile.client_id.ip,
                profile.client_id.user_agent or "",
                org or "",
                *ordered_tags(cls.tags),  # the tags shown in the Tags column
            )
        ).lower()
        attrs = (
            f' class="frow" data-filter="{_esc(haystack)}"{_netcol_attr([profile], net_col or {})}'
        )
    return (
        f"<tr{attrs}>{_client_cell(profile, flag)}"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td><td class='reqpat'>{pattern}</td></tr>"
    )


def _disclosure(label: str) -> str:
    """The ``▶`` toggle that reveals an actor's hidden member rows. A real button,
    so it is reachable by Tab and fires on Enter / Space; the click bubbles to the
    row handler (mouse behaviour unchanged), which flips ``aria-expanded``. The
    label names what expands, since the glyph alone says nothing to a screen reader."""
    return (
        f'<button type="button" class="tri" aria-expanded="false" '
        f'aria-label="{_esc(label)}">▶</button>'
    )


def _member_tr(
    profile: ClientProfile, flag: str = "", window: _Window = None, peak: int | None = None
) -> str:
    """A collapsed member as a real table row: IP/AS in Client, its own req/bytes,
    and -- on the shared axis -- its own request-pattern sparkline."""
    prefix, _, _ = client_id_parts(profile)
    asn = as_display(profile.features.as_org, profile.features.as_number)
    asn_html = f" <span class='cid-as'>{_esc(asn)}</span>" if asn != "–" else ""
    return (
        f"<tr class='amem'><td class='cid copy' data-copy='{_esc(profile.client_id.ip)}' "
        "title='Click to copy this id for: inspect --client'>"
        f"{flag}<span class='mono'>{_esc(prefix)}</span>{asn_html}</td>"
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td></td><td></td><td class='reqpat'>{_member_pattern(profile, window, peak)}</td></tr>"
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
    net_col: dict[str, int] | None = None,
    window: _Window = None,
    peak: int | None = None,
) -> str:
    """A single entry that folded many IPs into one (an ASN operator, a verified
    bot, an egress/subnet cluster): a collapsible summary over its clustered IPs.

    The summary sparkline is the *combined* cadence of every folded IP -- the
    features merged their per-minute counts -- so a coordinated crawl across many
    addresses reads as one rhythm. The clustered IP rows keep no per-IP timing."""
    cls = profile.classification
    prefix, org, ua = client_id_parts(profile)
    members = profile.member_ips
    pattern = _pattern_cell_for(profile, window, peak)
    org_html = f" <span class='cid-as'>{_esc(org)}</span>" if org else ""
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            (prefix, ua or "", org or "", *members, *ordered_tags(cls.tags))
        ).lower()
        row_attrs = (
            f"class='asum frow' data-filter=\"{_esc(haystack)}\""
            f"{_netcol_attr([profile], net_col or {})}"
        )
    toggle = _disclosure(f"Show {count(len(members), 'member IP')} of {prefix}")
    summary = (
        f"<tr {row_attrs}><td class='cid'>{toggle}"
        f"{flag}<span class='mono'>{_esc(prefix)}</span>{org_html}"
        f"<span class='muted'> · {count(len(members), 'IP')}</span>"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{profile.features.request_count:,}</td>"
        f"<td class='num'>{human_bytes(profile.features.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td>"
        f"<td class='reqpat'>{pattern}</td></tr>"
    )
    cf = flags or CountryFlags()
    rows = "".join(_ip_member_tr(ip, _flag_html(cf.for_ip(ip))) for ip in members)
    return f"<tbody class='actor'>{summary}{rows}</tbody>"


def _actor_tbody(
    actor: ActorGroup,
    *,
    flags: CountryFlags | None = None,
    filterable: bool = False,
    net_col: dict[str, int] | None = None,
    window: _Window = None,
    peak: int | None = None,
) -> str:
    """One actor as a ``<tbody>``: a lone client, or a collapsible summary + members.

    The members are ordinary rows sharing the table's Requests/Bandwidth columns,
    hidden until the summary row is clicked (toggled by the page script). The
    summary sparkline sums the members' projected cadences, so a rotation across
    grouped IPs (each firing in its own slice) shows as continuous coverage even
    though no single member spans the window.
    """
    cf = flags or CountryFlags()
    net_col = net_col or {}
    flag = _flag_html(cf.for_actor(actor.lead.client_id))
    if not actor.collapsed:
        if len(actor.lead.member_ips) >= 2:
            return _folded_tbody(
                actor.lead,
                flag=flag,
                flags=cf,
                filterable=filterable,
                net_col=net_col,
                window=window,
                peak=peak,
            )
        row = _client_row(
            actor.lead, flag=flag, filterable=filterable, net_col=net_col, window=window, peak=peak
        )
        return f"<tbody>{row}</tbody>"
    cls = actor.lead.classification
    _, _, ua = client_id_parts(actor.lead)
    shared = actor.shared_asn
    spread = actor_spread(actor.distinct_ips, 0 if shared else actor.distinct_asns)
    # One AS across the fold -> name it (greyed, like the per-client AS) instead of "1 ASNs".
    asn_html = f" <span class='cid-as'>{_esc(as_display(*shared))}</span>" if shared else ""
    pattern = _pattern_cell(
        _aggregate_buckets(actor.members, window), top_evidence(actor.lead), actor.requests, peak
    )
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            (
                *(
                    f"{m.client_id.ip} {m.client_id.user_agent or ''} {m.features.as_org or ''}"
                    for m in actor.members
                ),
                *ordered_tags(cls.tags),  # the tags shown in the Tags column
            )
        ).lower()
        row_attrs = (
            f"class='asum frow' data-filter=\"{_esc(haystack)}\""
            f"{_netcol_attr(list(actor.members), net_col)}"
        )
    toggle = _disclosure(f"Show {count(len(actor.members), 'grouped client')}")
    summary = (
        f"<tr {row_attrs}>"
        f"<td class='cid'>{toggle}{flag}{_esc(spread)}{asn_html}"
        f'<span class="actor-ua mono">{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{actor.requests:,}</td>"
        f"<td class='num'>{human_bytes(actor.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(cls.tags)}</td><td class='reqpat'>{pattern}</td></tr>"
    )
    members = "".join(
        _member_tr(m, _flag_html(cf.for_member(m.client_id)), window, peak) for m in actor.members
    )
    return f"<tbody class='actor'>{summary}{members}</tbody>"


def _kind_section(
    kind: Kind,
    group: list[ClientProfile],
    rollup: KindRollup,
    top: int,
    flags: CountryFlags | None = None,
    net_col: dict[str, int] | None = None,
    window: _Window = None,
    peak: int | None = None,
) -> str:
    flags = flags or CountryFlags()
    net_col = net_col or {}
    actors = group_actors(group)
    footprint = f"{count(rollup.clients, 'client')} · {count(rollup.requests, 'request')}"
    title = f"{_kind_badge(kind)} {footprint}"
    parts = [
        # Heading + blurb in one box so they stick together at the top while the
        # reader scrolls this kind's clients (see .kindhead in the stylesheet).
        '<div class="kindhead">'
        f'<h2 id="{kind.value}">{title}</h2>'
        f'<p class="blurb">{_esc(KIND_BLURB.get(kind, ""))}</p>'
        "</div>",
    ]
    shown = "".join(
        _actor_tbody(a, flags=flags, filterable=True, net_col=net_col, window=window, peak=peak)
        for a in actors[:top]
    )
    parts.append(
        f"<div class='tscroll'><table><thead>{_section_head(window)}</thead>{shown}</table></div>"
    )
    extra = actors[top:_EXPAND_LIMIT]
    if extra:
        extra_rows = "".join(
            _actor_tbody(a, flags=flags, filterable=True, net_col=net_col, window=window, peak=peak)
            for a in extra
        )
        parts.append(
            # Shared name -> native exclusive accordion: opening one closes the rest.
            # The page filter (above all sections) suspends the name while active.
            '<details name="kind-extra"><summary>'
            "Show more</summary>"
            f"<div class='tscroll'><table><thead>{_section_head(window)}</thead>"
            f"{extra_rows}</table></div>"
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
    # data-kind lets the filter script isolate this section when its kind is picked.
    return f'<section class="kind" data-kind="{kind.value}">{body}</section>'


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
    matrix = network_matrix(
        result.network_rollups,
        result.network_categories,
        min_breakout_share=breakout_min_share,
    )
    net_col = _net_col_index(matrix, result.network_rollups)
    # The report-wide span every request-pattern sparkline shares as its x-axis.
    start, end = time_range(result.rollups)
    window = (start, end) if start is not None and end is not None else None
    # One peak shared across the client tables' sparklines, so their heights compare.
    # Cover every actor a section renders -- actors[:top] shown plus the
    # actors[top:_EXPAND_LIMIT] tail -- so a spiky low-ranked row (a high --top can
    # render past _EXPAND_LIMIT) can't exceed the peak and overflow its glyph.
    spark_peak = _client_spark_peak(groups, window, max(top, _EXPAND_LIMIT))
    heading = "Agent Census" + (f" — {result.site}" if result.site else "")
    parts = [
        f"<h1>{_esc(heading)}</h1>",
        _meta_list(result, source, robots_note, elapsed),
        _summary_table(result, _kind_sparklines(result.rollups, window, KIND_ORDER), window),
        _network_table(matrix),
        # Search box + active-filter pills + "Show all" pinned together: clicking a
        # table can isolate a kind / network and scroll far down, so these controls
        # must stay in view for the reader to see and clear the active filters.
        # The pills and button are filled / shown by the page script.
        '<div class="filterbar">'
        '<input id="clientfilter" class="filter" type="search" '
        'placeholder="filter all clients by IP, User-Agent, AS name, or tag…" '
        'aria-label="filter clients">'
        '<span class="activefilters">'
        '<span id="kindfilter" class="fchip" role="button" tabindex="0" '
        'title="Clear kind filter" hidden></span>'
        '<span id="netfilter" class="fchip" role="button" tabindex="0" '
        'title="Clear network filter" hidden></span>'
        '<button id="clearfilters" type="button" class="clearfilters" hidden>'
        "Show all</button>"
        "</span>"
        "</div>",
        # Filled and shown by the filter script when a query hides every client.
        '<p id="nomatch" class="muted" role="status" hidden></p>',
    ]
    for kind in KIND_ORDER:
        rollup = result.rollups.get(kind)
        if rollup and rollup.clients:
            parts.append(
                _kind_section(
                    kind, groups.get(kind, []), rollup, top, flags, net_col, window, spark_peak
                )
            )
    return _page(heading, "\n".join(parts))
