"""Per-client request-pattern sparklines for the HTML report.

A small cadence glyph per client: request volume over time, drawn as an inline
SVG bar chart (no JS, no external assets). Every row shares one x-axis -- the
report-wide window -- so *when* a client was active is comparable down the
column. Bar height is request count per slice, normalised per row; the Requests
column already carries absolute volume, so the glyph is there to show shape
(bursty vs. metronomic), not magnitude.

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
from .format import fmt_ts, human_duration, top_evidence, truncate

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
    narrow band; one that spans the whole capture fills the width."""
    buckets = profile.features.request_buckets
    first = profile.features.first_seen
    last = profile.features.last_seen
    out = [0] * _BUCKETS
    if not buckets or first is None or last is None or window is None:
        return out
    w0 = window[0].timestamp()
    full = window[1].timestamp() - w0
    if full <= 0:
        return out
    c0 = first.timestamp()
    span = last.timestamp() - c0
    nbins = len(buckets)
    for i, hits in enumerate(buckets):
        if not hits:
            continue
        # Bucket i is the local slice [i, i + 1) / nbins; place it by its midpoint,
        # so a client spanning the whole window maps back onto the global grid 1:1.
        local_t = c0 + ((i + 0.5) / nbins) * span
        idx = int((local_t - w0) / full * _BUCKETS)
        out[min(_BUCKETS - 1, max(0, idx))] += hits
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


def sparkline_svg(buckets: list[int], peak: int | None = None, sqrt: bool = False) -> str:
    """Inline SVG bar sparkline for an already-projected bucket list. Empty string
    when there is nothing to draw.

    ``peak`` overrides the per-row scale: pass a shared maximum to make a set of
    sparklines height-comparable, so a taller glyph means more traffic (used by
    the per-kind summary). Defaults to this row's own peak -- the per-client
    glyphs scale individually, showing shape rather than magnitude.

    ``sqrt`` draws each bar at the square root of its share of ``peak`` instead of
    a linear share. Under one shared peak that keeps a quiet kind legible (its bars
    lift off the floor) while preserving the ordering -- a busier slice is still
    taller -- at the cost of exaggerating small differences."""
    if peak is None:
        peak = max(buckets, default=0)
    if peak <= 0:
        return ""
    gap = 1.0
    bw = (_W - (_BUCKETS - 1) * gap) / _BUCKETS
    bars = []
    for i, hits in enumerate(buckets):
        frac = hits / peak
        height = round((frac**0.5 if sqrt else frac) * (_H - 2))
        if height <= 0:
            continue
        x_pos = i * (bw + gap)
        bars.append(
            f"<rect x='{x_pos:.1f}' y='{_H - height:.1f}' " f"width='{bw:.2f}' height='{height}'/>"
        )
    return (
        f"<svg class='spark' viewBox='0 0 {_W} {_H}' "
        f"width='{_W}' height='{_H}' role='img' "
        f"aria-label='Request volume over time'>"
        f"<line class='sparkbase' x1='0' y1='{_H - 0.5}' "
        f"x2='{_W}' y2='{_H - 0.5}'/>{''.join(bars)}</svg>"
    )


def pattern_cell(buckets: list[int], evidence: str, request_count: int) -> str:
    """The 'Request pattern' cell: the cadence sparkline over a caption naming why
    the client landed in this kind. Below the volume floor, the caption alone."""
    cap = f"<div class='spark-cap'>{html.escape(truncate(evidence), quote=True)}</div>"
    if request_count >= _MIN_REQUESTS and any(buckets):
        return sparkline_svg(buckets) + cap
    return cap


def pattern_cell_for(profile: ClientProfile, window: Window) -> str:
    """The 'Request pattern' cell for a standalone or folded client: its own
    projected cadence over its top-evidence caption. (An actor-group summary draws
    its cell from an *aggregate* of members, so it calls the parts directly.)"""
    return pattern_cell(
        project_buckets(profile, window),
        top_evidence(profile),
        profile.features.request_count,
    )


def member_pattern(profile: ClientProfile, window: Window) -> str:
    """A grouped member's own sparkline (no caption) for its expanded row, or ''
    when it has too few requests to show a shape."""
    if profile.features.request_count < _MIN_REQUESTS:
        return ""
    return sparkline_svg(project_buckets(profile, window))


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


def kind_sparklines(
    groups: dict[Kind, list[ClientProfile]], window: Window, kinds: Sequence[Kind]
) -> dict[Kind, str]:
    """A cadence glyph per kind for the summary table, each summed from the kind's
    retained clients onto the shared axis. All scaled to one peak across kinds (sqrt,
    so a busier kind reads taller while quiet kinds stay legible) -- unlike the
    per-client glyphs, which scale individually to show shape, not magnitude. The
    cap on retained per-kind profiles means a capped tail is not reflected."""
    buckets = {kind: aggregate_buckets(groups.get(kind, []), window) for kind in kinds}
    peak = max((max(b, default=0) for b in buckets.values()), default=0)
    return {kind: sparkline_svg(b, peak=peak, sqrt=True) for kind, b in buckets.items()}
