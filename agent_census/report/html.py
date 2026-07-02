"""Render analysis results and inspection traces as a self-contained HTML page.

The page is built from the same structured data the Markdown renderer uses, with
a small built-in template (:func:`_page`, styled and scripted from the CSS/JS in
:mod:`._assets`) so the output is one file you can open in a browser -- no
external assets, no dependencies.
"""

from __future__ import annotations

from .. import __version__
from ..model import ClientProfile, Kind
from ..pipeline import AnalysisResult, KindRollup
from ._assets import CSS, SCRIPT
from ._htmlutil import esc as _esc
from ._htmlutil import kind_badge as _kind_badge
from ._networktab import net_col_index as _net_col_index
from ._networktab import netcol_attr as _netcol_attr
from ._networktab import network_table as _network_table
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
    by_kind,
    clusters_present,
    group_actors,
    network_matrix,
    time_range,
)
from .format import (
    actor_spread,
    agent_identity,
    as_display,
    client_id_parts,
    count,
    fmt_ts,
    full_ua,
    human_bytes,
    ordered_tags,
    tag_title,
    top_evidence,
)
from .geo import CountryFlags

# Tag colour tokens. Each tag maps to a style token, realised as a CSS class
# (.tag--<token>) in the report stylesheet; an unmapped tag falls through to the
# neutral grey .tag default. The tokens encode four overlaid systems:
#   * identity trust     -- green (confirmed) -> yellow (doubt) -> red (forged)
#   * behaviour/botness  -- cool human -> warm bot -> orange notable -> red hostile
#   * relative outlier   -- violet: a magnitude claim vs. this site's real browsers,
#                            not itself evidence of automation (unlike bot's
#                            structural signals) or of misconduct (unlike notable)
#   * origin / egress    -- cool context band
# Red is the shared terminal for either a forged identity or hostile conduct.
# Loud terminals are white-text solids; the quiet middle bands are colour-mix
# tints (see _assets.py) that adapt to the reader's light/dark scheme.
_TAG_TOKENS: dict[str, str] = {
    # Identity -- who is it, and is the declared identity genuine? dns/ip/wba are
    # three independent channels, each its own verified/unverified/violation triad
    # (see ChannelVerdict and WbaStatus) -- surfaced separately so a reader can see
    # which specific channel confirmed or disagreed, rather than one merged tag.
    "dns-verified": "trust",
    "ip-verified": "trust",
    "wba-verified": "trust",  # cryptographic identity -- as strong as the network channels
    "wba": "trust-soft",  # a signature is present, not yet checked against the key
    "wba-expired": "doubt",  # valid signature, but past its freshness window
    "wba-unverified": "doubt",  # signature present but couldn't be checked
    "dns-unverified": "doubt",
    "ip-unverified": "doubt",
    "wba-violation": "danger-deep",  # cryptographic forgery -- the strongest hostile signal
    "wba-replay": "danger-deep",  # a captured signature replayed from elsewhere
    "wba-mixed": "doubt",  # some of this client's signed requests verified, some didn't
    "wba-nonce-reuse": "doubt",  # same-origin nonce reuse -- a milder note, not a replay
    "dns-violation": "danger",  # network-origin mismatch -- drives the impersonator kind
    "ip-violation": "danger",
    "asn-associated": "trust-soft",
    "asn-attributed": "trust-soft",
    "user-triggered": "trust-soft",
    # 'stale-browser-ua' is the mild-doubt middle rung of the UA-age ramp
    # (current -> human, ancient/impossible -> danger); yellow keeps that
    # authenticity axis escalating rather than dropping to neutral grey.
    "stale-browser-ua": "doubt",
    # Behaviour / botness -- how machine-like the client behaves, up to hostile.
    "current-browser-ua": "human",
    "loads-assets": "human",
    "follows-links": "human",
    "has-cache": "human",
    "bursty": "human",
    "no-assets": "bot",
    "cold": "bot",
    "lacks-cache": "bot",
    "metronomic": "bot",
    "generic-ua": "bot",
    "bot-ua": "bot",
    "headless-browser": "bot",
    "uses-HEAD": "bot",
    "404-storm": "notable",
    "ignores-robots": "notable",
    "post-heavy": "notable",
    "exotic-method": "notable",
    "ua-rotating": "notable",
    "high-rate": "outlier",
    "high-bytes": "outlier",
    "wide-breadth": "outlier",
    "long-session": "outlier",
    "no-user-agent": "notable",
    "probe-paths": "danger",
    "ancient-browser-ua": "danger",  # forged identity -> shared red terminal
    "forged-referer": "danger",
    "traversal": "danger-deep",
    "encoding-evasion": "danger-deep",
    "impossible-browser-ua": "danger-deep",  # forged identity, deepest red
    # Origin / egress -- where from. Egress tag strings are defined in the data
    # file (data/networks/egress_networks.toml); a genuinely new egress tag stays
    # grey until listed here, as with the previous colour map.
    "datacenter": "origin",
    "icloud-private-relay": "egress",
    "tor-exit": "egress",
    "vpn": "egress",
    "corporate-proxy": "egress",
    "shared-ip": "egress",
}


def tag_class(tag: str) -> str:
    """CSS class for a tag chip: the neutral ``tag`` plus its colour token, if any."""
    token = _TAG_TOKENS.get(tag)
    return f"tag tag--{token}" if token else "tag"


# One representative label per colour token, grouped the same way _TAG_TOKENS'
# header comment describes the four overlaid systems -- so the key explains what
# the colour means rather than listing every tag that uses it.
_TAG_KEY_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Identity",
        [
            ("trust", "confirmed by a verification channel"),
            ("trust-soft", "supporting signal, not a full verification"),
            ("doubt", "unverified or stale"),
            ("danger", "declared identity contradicted"),
            ("danger-deep", "forged: cryptographic or UA proof of impersonation"),
        ],
    ),
    (
        "Behaviour",
        [
            ("human", "browser-like"),
            ("bot", "structural evidence of automation, e.g. no asset loads"),
            ("notable", "conduct a legitimate client wouldn't normally show"),
        ],
    ),
    (
        "Relative to this site",
        [
            ("outlier", "well beyond this site's real browsers on one metric"),
        ],
    ),
    (
        "Origin",
        [
            ("origin", "datacentre-hosted"),
            ("egress", "privacy relay, VPN, or proxy egress"),
        ],
    ),
]


def _tag_key() -> str:
    """Collapsible legend explaining the tag chips' colour tokens."""
    groups = []
    for title, entries in _TAG_KEY_GROUPS:
        chips = "".join(
            f'<span class="tag tag--{token}">{_esc(label)}</span>' for token, label in entries
        )
        groups.append(f'<div class="tagkey-group"><h3>{_esc(title)}</h3>{chips}</div>')
    return (
        '<details class="tagkey">'
        "<summary>Tag colour key</summary>"
        f'<div class="tagkey-groups">{"".join(groups)}</div>'
        "</details>"
    )


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


def _tags_html(tags: frozenset[str]) -> str:
    if not tags:
        return '<span class="muted">–</span>'
    spans = []
    for tag in ordered_tags(tags):
        description = tag_title(tag)
        title = f' title="{_esc(description)}"' if description else ""
        spans.append(f'<span class="{tag_class(tag)}"{title}>{_esc(tag)}</span>')
    return " ".join(spans)


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
        "<tr><th class='band'></th><th>Kind</th>"
        "<th class='num'>Clients</th><th class='num'>Requests</th>"
        f"<th>Req share</th><th class='reqpat'>Requests over {_axis_span(window)}</th>"
        "<th class='num'>Bandwidth</th><th>BW share</th>"
        f'<th title="{_esc(robots_help)}">robots.txt compliance ⓘ</th></tr>'
    )
    rows = []
    for ci, (cluster, members) in enumerate(
        clusters_present(lambda k: (r := rollups.get(k)) is not None and r.clients > 0)
    ):
        # The band label carries the cluster's share of total requests, so a reader
        # sees each category's weight without summing its rows (e.g. "Human-like —
        # 40%").
        cluster_share = sum(rollups[k].requests for k in members) / total
        for offset, kind in enumerate(members):
            rollup = rollups[kind]
            robots = _robots_bar(
                rollup.respects_robots,
                rollup.ignores_robots,
                rollup.unknown_robots,
            )
            # One rowspanned label per band, so its tall vertical text is distributed
            # over the band's whole height and vertical-centred -- not dumped on the
            # first row, which the earlier per-row construction stretched to the full
            # label height. Safe here because #kindtab uses SEPARATE borders (the
            # collapsed-border row-rule bleed a spanned cell used to cause doesn't
            # happen); the cross-tab keeps its per-row band cell because its heat/pin
            # script needs a uniform leftmost column. A thick rule separates bands.
            band = (
                f"<th class='band' rowspan='{len(members)}' scope='rowgroup'>"
                f"<span>{_esc(cluster.label)} "
                f"<b class='bandpct'>{cluster_share:.0%}</b></span></th>"
                if offset == 0
                else ""
            )
            tr = "<tr class='bandstart'>" if (offset == 0 and ci > 0) else "<tr>"
            rows.append(
                f'{tr}{band}<td><a href="#{kind.value}">{_kind_badge(kind)}</a></td>'
                f"<td class='num'>{rollup.clients:,}</td><td class='num'>{rollup.requests:,}</td>"
                f"<td>{_share_bar(rollup.requests / total)}</td>"
                f"<td class='reqpat'>{patterns.get(kind, '')}</td>"
                f"<td class='num'>{human_bytes(rollup.total_bytes)}</td>"
                f"<td>{_share_bar(rollup.total_bytes / total_bytes)}</td>"
                f"<td>{robots}</td></tr>"
            )
    return (
        f"<h2>Summary by kind</h2>\n"
        f"<div class='tscroll'><table id='kindtab'>{head}{''.join(rows)}</table></div>\n"
        '<p class="hint">Click a kind to show only it; click a client below '
        "to copy its id for <code>inspect --client</code>.</p>"
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
    raw = full_ua(profile)
    ua_title = f' title="{_esc(raw)}"' if raw else ""
    return (
        f'<td class="cid copy" data-copy="{_esc(profile.client_id.ip)}" '
        f'title="Click to copy this id for: inspect --client">'
        f'<div class="mono cid-id">{flag}{_esc(prefix)}</div>'
        f"{org_line}"
        f'<div class="mono cid-ua"{ua_title}>{_esc(ua or "–")}</div></td>'
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
                agent_identity(profile) or "",
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
    identity = agent_identity(profile)
    if filterable:
        haystack = " ".join(
            (prefix, ua or "", org or "", identity or "", *members, *ordered_tags(cls.tags))
        ).lower()
        row_attrs = (
            f"class='asum frow' data-filter=\"{_esc(haystack)}\""
            f"{_netcol_attr([profile], net_col or {})}"
        )
    else:
        row_attrs = "class='asum'"
    raw = full_ua(profile)
    ua_title = f' title="{_esc(raw)}"' if raw else ""
    toggle = _disclosure(f"Show {count(len(members), 'member IP')} of {prefix}")
    # For a known agent, lead with its own identity and demote the network detail
    # to a line below, matching the grouped-actor header. The fold's own prefix is
    # often the identity already (an ASN operator label, say) -- drop it from the
    # demoted line rather than repeat it verbatim.
    prefix_html = f"<span class='mono'>{_esc(prefix)}</span>" if prefix != identity else ""
    net_line = f"{prefix_html}{org_html}<span class='muted'> · {count(len(members), 'IP')}</span>"
    id_html = (
        f"<span class='cid-id mono'>{_esc(identity)}</span><div class='cid-as'>{net_line}</div>"
        if identity
        else net_line
    )
    summary = (
        f"<tr {row_attrs}><td class='cid'>{toggle}"
        f"{flag}{id_html}"
        f'<span class="actor-ua mono"{ua_title}>{_esc(ua or "–")}</span></td>'
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
    tags = cls.tags | actor.observational_tags
    _, _, ua = client_id_parts(actor.lead)
    shared = actor.shared_asn
    spread = actor_spread(actor.distinct_ips, 0 if shared else actor.distinct_asns)
    # One AS across the fold -> name it (greyed, like the per-client AS) instead of "1 ASNs".
    asn_html = f" <span class='cid-as'>{_esc(as_display(*shared))}</span>" if shared else ""
    pattern = _pattern_cell(
        _aggregate_buckets(actor.members, window),
        top_evidence(actor.lead),
        actor.requests,
        peak,
        window,
    )
    # For a known agent, lead with its own identity -- a declared name, a Web
    # Bot Auth operator, or else an rDNS-confirmed host -- and demote the
    # IP/ASN spread to a line below it (like the network's own AS org).
    # Otherwise the spread is the only identity we have, so it stays the
    # header line as before.
    identity = agent_identity(actor.lead)
    row_attrs = "class='asum'"
    if filterable:
        haystack = " ".join(
            (
                *(
                    f"{m.client_id.ip} {m.client_id.user_agent or ''} {m.features.as_org or ''}"
                    for m in actor.members
                ),
                identity or "",
                *ordered_tags(tags),  # the tags shown in the Tags column
            )
        ).lower()
        row_attrs = (
            f"class='asum frow' data-filter=\"{_esc(haystack)}\""
            f"{_netcol_attr(list(actor.members), net_col)}"
        )
    raw = full_ua(actor.lead)
    ua_title = f' title="{_esc(raw)}"' if raw else ""
    toggle = _disclosure(f"Show {count(len(actor.members), 'grouped client')}")
    net_line = f"{_esc(spread)}{asn_html}"
    id_html = (
        f"<span class='cid-id mono'>{_esc(identity)}</span><div class='cid-as'>{net_line}</div>"
        if identity
        else net_line
    )
    summary = (
        f"<tr {row_attrs}>"
        f"<td class='cid'>{toggle}{flag}{id_html}"
        f'<span class="actor-ua mono"{ua_title}>{_esc(ua or "–")}</span></td>'
        f"<td class='num'>{actor.requests:,}</td>"
        f"<td class='num'>{human_bytes(actor.total_bytes)}</td>"
        f"<td class='num'>{cls.confidence:.0%}</td>"
        f"<td>{_tags_html(tags)}</td><td class='reqpat'>{pattern}</td></tr>"
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
        f'<p class="blurb">{_esc(KIND_BLURB[kind])}</p>'
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
        # Search box + tag key + active-filter pills + "Show all" pinned together:
        # clicking a table can isolate a kind / network and scroll far down, so
        # these controls must stay in view for the reader to see and clear the
        # active filters, and to look up a tag's colour without scrolling back up.
        # The pills and button are filled / shown by the page script.
        '<div class="filterbar">'
        '<div class="filterrow">'
        '<input id="clientfilter" class="filter" type="search" '
        'placeholder="filter all clients by IP, User-Agent, AS name, or tag…" '
        'aria-label="filter clients">'
        f"{_tag_key()}"
        "</div>"
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
