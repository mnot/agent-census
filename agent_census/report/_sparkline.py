"""Per-client request-pattern sparklines for the HTML report.

A small cadence glyph per client: request volume over time, drawn as an inline
SVG bar chart (no JS, no external assets). Every row shares one x-axis -- the
report-wide window -- so *when* a client was active is comparable down the
column. Bar height is request count per slice, square-rooted against one peak
shared across the whole client table -- so *how much* a client did is comparable
too: a taller glyph is more traffic, while the sqrt keeps a quiet row legible.

The source histogram (``ClientFeatures.request_buckets``) is measured over each
client's own ``[first_seen, last_seen]`` span -- it has to be, because the
pipeline finalises and evicts idle clients mid-stream, before the global window
is known. :func:`project_buckets` re-bins that local histogram onto the shared
axis at render time, once the window is in hand.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence
from datetime import datetime

from ..model import ClientProfile, Kind
from ..pipeline import CADENCE_BIN_SECONDS, KindRollup
from .aggregate import group_actors
from .format import count, fmt_ts, human_duration, top_evidence, truncate

_BUCKETS = 40  # time slices across the report-wide window
_W = 200  # px; the caption below wraps to this width
_H = 26
_MIN_REQUESTS = 20  # fewer than this is a handful of dots, not a pattern

# Earliest first-seen and latest last-seen across the report, or None when no
# request carried a timestamp; the axis every sparkline is drawn against.
Window = tuple[datetime, datetime] | None


def project_buckets(profile: ClientProfile, window: Window) -> list[int]:
    """Re-bin a client's local-span histogram onto the report-wide time axis.

    Placing the client's own buckets into its slice of the global window is what
    makes every sparkline share one scale. A short-lived client compresses into a
    narrow band; one that spans the whole capture fills the width. A client whose
    whole span fits in one minute has no span-local histogram (request_buckets is
    empty -- features._request_buckets); rather than leave its glyph blank, place its
    whole volume as a single spike at its point in time -- the same way the per-kind
    rollup cadence handles a sub-minute burst, so the two stay consistent."""
    features = profile.features
    buckets = features.request_buckets
    first = features.first_seen
    last = features.last_seen
    out = [0] * _BUCKETS
    if window is None or first is None:
        return out
    w0 = window[0].timestamp()
    full = window[1].timestamp() - w0
    if full <= 0:
        return out
    c0 = first.timestamp()
    span = last.timestamp() - c0 if last is not None else 0.0
    if buckets and span > 0:
        nbins = len(buckets)
        for i, hits in enumerate(buckets):
            if not hits:
                continue
            # Bucket i is the local slice [i, i + 1) / nbins; place it by its midpoint,
            # so a client spanning the whole window maps back onto the global grid 1:1.
            local_t = c0 + ((i + 0.5) / nbins) * span
            idx = int((local_t - w0) / full * _BUCKETS)
            out[min(_BUCKETS - 1, max(0, idx))] += hits
    else:
        # Sub-minute burst: no shape to spread, so place the whole volume in the one
        # slice the client was active in. A tall spike is truthful -- the client had a
        # high instantaneous rate -- and the shared peak keeps it comparable.
        idx = int((c0 - w0) / full * _BUCKETS)
        out[min(_BUCKETS - 1, max(0, idx))] += features.request_count
    return out


def aggregate_buckets(profiles: Iterable[ClientProfile], window: Window) -> list[int]:
    """Element-wise sum of members' projections -- the combined cadence of an
    actor group, on the same shared axis. Surfaces coordination a single member's
    glyph hides (IPs that each fire in a different slice = a rotation)."""
    total = [0] * _BUCKETS
    for profile in profiles:
        for i, hits in enumerate(project_buckets(profile, window)):
            total[i] += hits
    return total


def client_spark_peak(
    groups: dict[Kind, list[ClientProfile]], window: Window, limit: int
) -> int | None:
    """The single busiest projected time-slice across every request-pattern sparkline
    the client tables will draw -- the shared peak that makes their heights comparable,
    so a taller glyph reliably means more traffic (the per-kind summary keeps its own,
    coarser peak).

    A collapsed actor draws the *aggregate* of its members; a standalone or folded one
    draws its lead's own projection -- so those are the series to scale against. Member
    rows never exceed their group's aggregate, so they need no separate look. Only the
    rendered actors (the first ``limit`` per kind) count; the capped tail isn't drawn."""
    peak = 0
    for group in groups.values():
        for actor in group_actors(group)[:limit]:
            series = (
                aggregate_buckets(actor.members, window)
                if actor.collapsed
                else project_buckets(actor.lead, window)
            )
            if series:
                peak = max(peak, *series)
    return peak or None


def _bucket_title(start: datetime, end: datetime, hits: int) -> str:
    """Hover text for one bar: its real slice of the axis and its real (un-sqrt'd)
    count. Minute resolution, not seconds -- the re-binning that placed ``hits``
    here already blurs placement by a fraction of a slice, so seconds would claim
    precision the data doesn't have.

    Shows the UTC offset once, like :func:`axis_span`'s ``fmt_ts`` does -- ``start``
    and ``end`` always share it (``end`` is derived from ``start`` by addition, which
    preserves tzinfo), but log lines carry their *own* recorded offset rather than a
    normalized one, so a window spanning a DST change can have a different offset at
    each end. Naming it here keeps a bucket near the far end of such a window from
    reading as same-offset-as-the-log-line-there when it isn't."""
    fmt = "%Y-%m-%d %H:%M"
    end_str = end.strftime("%H:%M") if start.date() == end.date() else end.strftime(fmt)
    return f"{start.strftime(fmt)}–{end_str} {start.strftime('%z')}: {count(hits, 'request')}"


def sparkline_svg(
    buckets: list[int], peak: int | None = None, sqrt: bool = False, window: Window = None
) -> str:
    """Inline SVG bar sparkline for an already-projected bucket list. Empty string
    when there is nothing to draw.

    ``peak`` overrides the per-row scale: pass a shared maximum to make a set of
    sparklines height-comparable, so a taller glyph means more traffic. Both the
    per-kind summary and the per-client table pass one (each its own shared peak --
    one across kinds, one across clients). It defaults to this row's own peak only
    when a caller draws a glyph in isolation (e.g. a unit test).

    ``sqrt`` draws each bar at the square root of its share of ``peak`` instead of
    a linear share. Whether ``peak`` is shared (the per-kind summary) or this row's
    own (the per-client glyphs), it keeps a quiet slice legible (its bars lift off
    the floor) while preserving the ordering -- a busier slice is still taller -- at
    the cost of exaggerating small differences.

    ``window`` -- when given -- adds a native ``<title>`` to each bar naming its
    real time slice and its real request count (unaffected by ``sqrt``), so hovering
    a bar shows the number the bar's height only gestures at."""
    if peak is None:
        peak = max(buckets, default=0)
    if peak <= 0:
        return ""
    gap = 1.0
    bw = (_W - (_BUCKETS - 1) * gap) / _BUCKETS
    w0, step = (
        (window[0], (window[1] - window[0]) / _BUCKETS) if window is not None else (None, None)
    )
    bars = []
    for i, hits in enumerate(buckets):
        frac = hits / peak
        height = round((frac**0.5 if sqrt else frac) * (_H - 2))
        if height <= 0:
            continue
        x_pos = i * (bw + gap)
        title = ""
        if w0 is not None and step is not None:
            start = w0 + step * i
            text = html.escape(_bucket_title(start, start + step, hits), quote=True)
            title = f"<title>{text}</title>"
        bars.append(
            f"<rect x='{x_pos:.1f}' y='{_H - height:.1f}' "
            f"width='{bw:.2f}' height='{height}'>{title}</rect>"
        )
    return (
        f"<svg class='spark' viewBox='0 0 {_W} {_H}' "
        f"width='{_W}' height='{_H}' role='img' "
        f"aria-label='Request volume over time'>"
        f"<line class='sparkbase' x1='0' y1='{_H - 0.5}' "
        f"x2='{_W}' y2='{_H - 0.5}'/>{''.join(bars)}</svg>"
    )


def pattern_cell(
    buckets: list[int],
    evidence: str,
    request_count: int,
    peak: int | None = None,
    window: Window = None,
) -> str:
    """The 'Request pattern' cell: the cadence sparkline over a caption naming why
    the client landed in this kind. Below the volume floor, the caption alone.

    ``peak`` is the client table's shared maximum, so the glyph's height is
    comparable to every other row's (sqrt-scaled, to keep quiet rows legible)."""
    cap = f"<div class='spark-cap'>{html.escape(truncate(evidence), quote=True)}</div>"
    if request_count >= _MIN_REQUESTS and any(buckets):
        return sparkline_svg(buckets, peak=peak, sqrt=True, window=window) + cap
    return cap


def pattern_cell_for(profile: ClientProfile, window: Window, peak: int | None = None) -> str:
    """The 'Request pattern' cell for a standalone or folded client: its own
    projected cadence over its top-evidence caption. (An actor-group summary draws
    its cell from an *aggregate* of members, so it calls the parts directly.)"""
    return pattern_cell(
        project_buckets(profile, window),
        top_evidence(profile),
        profile.features.request_count,
        peak,
        window,
    )


def member_pattern(profile: ClientProfile, window: Window, peak: int | None = None) -> str:
    """A grouped member's own sparkline (no caption) for its expanded row, or ''
    when it has too few requests to show a shape. Shares the table-wide ``peak``."""
    if profile.features.request_count < _MIN_REQUESTS:
        return ""
    return sparkline_svg(project_buckets(profile, window), peak=peak, sqrt=True, window=window)


def axis_span(window: Window) -> str:
    """The "<duration>" label naming the shared x-axis -- the span every sparkline
    is drawn against -- with the exact start -> end on hover. Both the per-client
    header and the per-kind summary header read against it."""
    detail = "time"
    title = ""
    if window is not None:
        detail = human_duration((window[1] - window[0]).total_seconds())
        full = f"shared sparkline axis: {fmt_ts(window[0])} → {fmt_ts(window[1])}"
        title = f' title="{html.escape(full, quote=True)}"'
    return f"<span class='muted'{title}>{html.escape(detail, quote=True)}</span>"


def rebin_cadence(cadence: dict[int, int], window: Window) -> list[int]:
    """Re-bin a rollup's absolute-time cadence histogram onto the report-wide axis.

    The rollup accumulates each kind's activity on a fixed ``CADENCE_BIN_SECONDS``
    grid as clients are seen -- eviction- and cap-safe, so it covers the whole kind,
    not just the retained profiles, and (unlike a sum of per-client
    :func:`project_buckets`) it also carries sub-minute bursts, which have no
    per-client histogram to project. Each grid bin is placed by its midpoint; the grid
    is finer than the rendered window, so the re-bin only blurs placement by a fraction
    of a slice."""
    out = [0] * _BUCKETS
    if not cadence or window is None:
        return out
    w0 = window[0].timestamp()
    full = window[1].timestamp() - w0
    if full <= 0:
        return out
    for grid_bin, hits in cadence.items():
        midpoint = (grid_bin + 0.5) * CADENCE_BIN_SECONDS
        idx = int((midpoint - w0) / full * _BUCKETS)
        out[min(_BUCKETS - 1, max(0, idx))] += hits
    return out


def kind_sparklines(
    rollups: dict[Kind, KindRollup], window: Window, kinds: Sequence[Kind]
) -> dict[Kind, str]:
    """A cadence glyph per kind for the summary table, each re-binned from the kind's
    eviction-safe rollup cadence onto the shared axis -- so the glyph covers all of
    the kind's timestamped traffic, tracking the request count beside it, not just the
    retained profiles the per-kind cap kept. All scaled to one peak across kinds
    (sqrt, so a busier kind reads taller while quiet kinds stay legible) -- a coarser
    cousin of the per-client table's own shared peak, on a different scale (per-kind
    totals, not single clients)."""
    buckets = {
        kind: rebin_cadence(rollups[kind].cadence, window) if kind in rollups else [0] * _BUCKETS
        for kind in kinds
    }
    peak = max((max(b, default=0) for b in buckets.values()), default=0)
    return {
        kind: sparkline_svg(b, peak=peak, sqrt=True, window=window) for kind, b in buckets.items()
    }
