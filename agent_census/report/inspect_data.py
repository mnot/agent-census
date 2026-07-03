"""Per-client inspect data for the report overlay.

The HTML report can link each client row to an in-page inspect view. Rather than
render a full HTML page per client (which would re-inline the report's whole
stylesheet N times), analysis writes one small JSON file per *actor group* into a
``data/`` directory and the report's viewer script composes it client-side.

Each file holds display-ready strings built by the same :mod:`.format` helpers the
Markdown/HTML renderers use -- so the browser viewer stays dumb templating and the
values never drift from the rest of the report. A handful of shared visual
primitives (the kind badge, tag chips) are emitted as pre-rendered fragments so
the viewer needn't re-implement the kind/tag colour maps.

The trace here is the *bounded* first-N sample captured during the streaming pass
(``pipeline.analyze(inspect_trace=…)``), not a full re-read: peak memory stays
bounded however busy a client is. ``total`` is the true request count, so the view
can honestly say "showing N of M".
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from ..features import _is_static, _referer_path
from ..model import ClientProfile, Kind
from ._htmlutil import esc as _esc
from ._htmlutil import kind_badge as _kind_badge
from .aggregate import ActorGroup, by_kind, group_actors
from .format import (
    client_label,
    elide_ua,
    feature_rows,
    fmt_ts,
    human_bytes,
    human_duration,
    ordered_tags,
    tag_title,
)
from .html import _EXPAND_LIMIT, tag_class


def _tag_chip(tag: str) -> str:
    """The report's tag chip as a self-contained fragment (colour from tag_class)."""
    description = tag_title(tag)
    title = f' title="{_esc(description)}"' if description else ""
    return f'<span class="{tag_class(tag)}"{title}>{_esc(tag)}</span>'


def _signals_view(profile: ClientProfile) -> list[dict[str, object]]:
    cls = profile.classification
    signals = sorted(cls.all_signals, key=lambda s: s.confidence, reverse=True)
    return [
        {
            "primary": signal.kind is cls.primary,
            "badge": _kind_badge(signal.kind),
            "confidence": f"{signal.confidence:.0%}",
            "classifier": signal.classifier,
            "evidence": list(signal.evidence),
        }
        for signal in signals
    ]


def _tags_view(profile: ClientProfile) -> list[dict[str, object]]:
    cls = profile.classification
    evidence = dict(cls.tag_evidence)
    return [{"chip": _tag_chip(tag), "why": evidence.get(tag)} for tag in ordered_tags(cls.tags)]


def _compliance_view(profile: ClientProfile) -> dict[str, object] | None:
    report = profile.compliance
    if report is None:
        return None
    return {
        "verdict": report.verdict.value,
        "matched_group": report.matched_group or "–",
        "disallowed_hits": report.disallowed_hits,
        "fetched_robots_first": report.fetched_robots_first,
        "sample": list(report.sample_disallowed),
    }


def _rel_time(base: datetime, ts: datetime) -> str:
    """A compact ``+elapsed`` from ``base`` -- less visual noise than a column of
    near-identical absolute timestamps."""
    delta = (ts - base).total_seconds()
    if delta < 0:  # out-of-order line; fall back to absolute rather than "-2s"
        return fmt_ts(ts)
    if delta < 10:
        return f"+{delta:.1f}s"
    if delta < 60:
        return f"+{delta:.0f}s"
    minutes, seconds = divmod(int(delta), 60)
    if minutes < 60:
        return f"+{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"+{hours}h{minutes:02d}m"


def _referer_host(referer: str | None) -> str | None:
    """The lowercased host of a Referer, or ``None`` for an absent/blank one."""
    if not referer or referer == "-":
        return None
    return (urlsplit(referer).hostname or "").lower() or None


def _bare_host(value: str | None) -> str | None:
    """The lowercased hostname of a ``host[:port]`` (or ``[ipv6]:port``) value, port
    and brackets stripped -- for comparing a request's Host / the site to a referer
    host. ``None`` when blank."""
    if not value:
        return None
    return (urlsplit("//" + value).hostname or "").lower() or None


def _referer_display(referer: str | None, host: str | None, site: str | None) -> str:
    """A Referer for display: same-site referers drop the scheme and authority and
    show just the path, since the host repeats the client's own site. Off-site ones
    keep the full URL. Same-site means the referer host matches the request's Host
    header or the analysed site's host."""
    if not referer or referer == "-":
        return "–"
    ref_host = _referer_host(referer)
    known = {h for h in (_bare_host(host), _bare_host(site)) if h}
    if ref_host and ref_host in known:
        parts = urlsplit(referer)
        shown = parts.path or "/"
        if parts.query:
            shown += "?" + parts.query
        return shown[:60]
    return referer[:60]


def _trace_view(
    profile: ClientProfile, *, limit: int, site: str | None = None
) -> dict[str, object]:
    entries = sorted(profile.entries, key=lambda e: (e.timestamp is None, e.timestamp or e.line_no))
    shown = entries[:limit]
    first_ts = next((e.timestamp for e in shown if e.timestamp is not None), None)
    # Page-relative offsets and asset nesting only make sense for one client's own
    # sequential requests. A folded entry (a verified-bot merge, an egress/subnet/ASN
    # cluster) interleaves several IPs into one trace, so a "page" and its "assets"
    # could come from different clients -- there, keep a flat list: offsets from the
    # first request, nothing nested.
    folded = bool(profile.member_ips) or profile.is_aggregate
    # Each offset is measured from the current *page* -- the last non-asset request.
    # So an asset reads as its delay after the page that pulled it, and a navigation
    # as the gap since the previous page. ``base`` starts at the first request and
    # resets at every page. (A static sub-resource whose Referer is the page above it
    # nests under it; only assets nest, so a following navigation stays top-level.)
    base = first_ts
    parent_path: str | None = None
    rows: list[dict[str, object]] = []
    for entry in shown:
        request = (entry.path + ("?" + entry.query if entry.query else "")) or entry.raw_request
        is_asset = _is_static(entry.path)
        ref = entry.referer
        child = bool(
            not folded
            and is_asset
            and parent_path
            and ref
            and ref != "-"
            and _referer_path(ref) == parent_path
        )
        ts = entry.timestamp
        when = _rel_time(base, ts) if (ts is not None and base is not None) else "–"
        if not folded and not is_asset:
            parent_path = entry.path or None
            if ts is not None:
                base = ts  # following assets, and the next page's gap, measure from here
        rows.append(
            {
                "time": when,
                "method": entry.method or "–",
                "path": request[:90] or "–",
                "status": entry.status,
                "bytes": entry.bytes_sent,
                "referer": _referer_display(entry.referer, entry.host_header, site),
                "child": child,
            }
        )
    return {
        # The true total, so the view can say "N of M"; a capped sample shows fewer.
        "total": profile.features.request_count,
        "shown": len(rows),
        # The absolute first-request time, shown once above the table so the offset
        # column can stay narrow.
        "first_time": fmt_ts(first_ts),
        "rows": rows,
    }


def build_member_view(
    profile: ClientProfile, *, limit: int, site: str | None = None
) -> dict[str, object]:
    """One client's inspect view as display-ready JSON (the same values the
    Markdown renderer prints, so the two never drift). ``site`` is the analysed
    site's host, used to shorten same-site referers in the trace."""
    cls = profile.classification
    feats = profile.features
    return {
        "label": client_label(profile),
        "kind_badge": _kind_badge(cls.primary),
        "confidence": f"{cls.confidence:.0%}",
        "ip": profile.client_id.ip,
        "network": profile.network,
        "user_agent": elide_ua(feats.user_agent, is_browser=cls.primary is Kind.BROWSER) or "–",
        "requests": f"{feats.request_count:,}",
        "bandwidth": human_bytes(feats.total_bytes),
        "span": human_duration(feats.duration_seconds),
        "seen": f"{fmt_ts(feats.first_seen)} → {fmt_ts(feats.last_seen)}",
        "signals": _signals_view(profile),
        "tags": _tags_view(profile),
        "compliance": _compliance_view(profile),
        "features": [list(row) for row in feature_rows(feats)],
        "trace": _trace_view(profile, limit=limit, site=site),
    }


def build_group_view(
    group: ActorGroup, *, limit: int, site: str | None = None
) -> dict[str, object]:
    """An actor group as JSON: one card per member, biggest first.

    Members of a group share a User-Agent (that is the folding key), differing only
    by IP/ASN -- one actor spread across addresses -- so each gets a full card, the
    way ``inspect --actor`` shows them. (A same-IP User-Agent rotation is not one
    group here: each UA is its own row/file.)
    """
    members = sorted(group.members, key=lambda p: p.features.request_count, reverse=True)
    return {
        "slug": group.slug,
        "kind_badge": _kind_badge(group.lead.classification.primary),
        "count": len(members),
        "members": [build_member_view(m, limit=limit, site=site) for m in members],
    }


def _infer_site_host(profiles: Sequence[ClientProfile]) -> str | None:
    """Guess the analysed site's host from the sampled traces, for shortening
    same-site referers when the log itself carries no host (no ``%v`` / Host).

    A site's own access log is dominated by same-site navigation, so the most
    common Referer host across the retained traces is almost always the site
    itself. To avoid crowning an off-site host on a small or referral-heavy sample
    (which would invert the shortening -- off-site referers shown as bare paths),
    only accept a host that is an outright majority of the hosted referers; when no
    host dominates, return ``None`` and leave referers full. For an authoritative
    answer, log ``%v`` (server name) so ``result.site`` is set and this isn't used.
    """
    hosts: Counter[str] = Counter()
    for profile in profiles:
        for entry in profile.entries:
            host = _referer_host(entry.referer)
            if host:
                hosts[host] += 1
    if not hosts:
        return None
    top, count = hosts.most_common(1)[0]
    return top if count * 2 > sum(hosts.values()) else None


def rendered_groups(profiles: Sequence[ClientProfile], *, top: int) -> list[ActorGroup]:
    """Exactly the actor groups the HTML report renders as rows, per kind -- the
    only ones a row can link to. Mirrors ``_kind_section``: the ``top`` shown plus
    the ``_EXPAND_LIMIT`` "Show more" tail (whichever reaches further)."""
    cap = max(top, _EXPAND_LIMIT)
    groups: list[ActorGroup] = []
    for kind_profiles in by_kind(tuple(profiles)).values():
        groups.extend(group_actors(kind_profiles)[:cap])
    return groups


def write_inspect_bundle(
    profiles: Sequence[ClientProfile],
    data_dir: Path,
    *,
    limit: int,
    top: int,
    site: str | None = None,
) -> int:
    """Write one ``<slug>.json`` per rendered actor group into ``data_dir``.

    Returns the number of files written. The slugs match the ``data-inspect``
    attributes the report emits, so every linkable row resolves to a file. The
    report references this directory by a fixed relative name (``inspect/``), so
    ``data_dir`` is named after the report (``<report-stem>.inspect``), so it belongs
    to this report alone: existing ``*.json`` in it are cleared first, pruning files
    from clients that have since vanished (or an earlier, larger run). ``site`` is the
    analysed site's host, used to shorten same-site referers; when unset (the log
    carries no host) it is inferred from the traces.
    """
    site = site or _infer_site_host(profiles)
    data_dir.mkdir(parents=True, exist_ok=True)
    for stale in data_dir.glob("*.json"):
        stale.unlink()
    written = 0
    for group in rendered_groups(profiles, top=top):
        view = build_group_view(group, limit=limit, site=site)
        path = data_dir / f"{group.slug}.json"
        path.write_text(json.dumps(view, ensure_ascii=False), encoding="utf-8")
        written += 1
    return written
