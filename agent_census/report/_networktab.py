"""The kind x network cross-tab: the client-attribution table at the top of
the report (counts, row/column shares, the pinned "Other" fold-in) plus the
``data-netcol`` plumbing that lets a client row answer the network filter.

Kept out of :mod:`html` for the same reason as :mod:`_assets` / :mod:`_netscript`
-- that module stays under the repo's per-file line limit.
"""

from __future__ import annotations

from ..model import ClientProfile, Kind
from ..pipeline import OTHER_HOSTING, RESIDENTIAL_NETWORK, KindRollup
from ._htmlutil import esc as _esc
from ._htmlutil import kind_badge as _kind_badge
from ._netscript import NET_SCRIPT
from .aggregate import NetworkMatrix, clusters_present

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


def _num(value: int) -> str:
    return f"{value:,}" if value else "–"


def net_col_index(
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


def netcol_attr(profiles: list[ClientProfile], net_col: dict[str, int]) -> str:
    """``data-netcol`` listing the column indices an actor's members occupy.

    An actor group folds clients that differ only by IP/ASN, so its members can
    span several networks; the network filter shows the row if *any* member is in
    the chosen column.
    """
    if not net_col:
        return ""
    idxs = sorted({net_col[p.network] for p in profiles if p.network in net_col})
    return f' data-netcol="{" ".join(str(i) for i in idxs)}"' if idxs else ""


def network_table(matrix: NetworkMatrix | None) -> str:
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
        "<tr><th class='band'></th><th class='stick-l'>Kind</th>"
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

    # A band cell rides on *every* row (not a rowspan): the heat/pin script keys
    # columns by cellIndex, so the leftmost column must be uniform across rows. The
    # rotated label shows only on each band's first row; the rest are empty.
    present = set(matrix.kinds)
    rows = []
    for ci, (cluster, members) in enumerate(clusters_present(lambda k: k in present)):
        for offset, kind in enumerate(members):
            cells = "".join(
                f"<td class='{cell_cls(i, n)}' data-v='{matrix.cell(n, kind)}' "
                f"data-net='{i}'{cell_attrs(n, kind)}>{_num(matrix.cell(n, kind))}</td>"
                for i, n in enumerate(nets)
            )
            band = (
                f"<th class='band' scope='rowgroup'><span>{_esc(cluster.label)}</span></th>"
                if offset == 0
                else "<td class='band'></td>"
            )
            tr = "<tr class='bandstart'>" if (offset == 0 and ci > 0) else "<tr>"
            rows.append(
                f'{tr}{band}<td class="stick-l">'
                f'<a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
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
        "<tr class='netall'><td class='band'></td>"
        "<td class='stick-l'><strong>All kinds</strong></td>"
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
