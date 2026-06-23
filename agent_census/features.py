"""Per-client feature extraction.

Turns one client's log entries into a :class:`ClientFeatures` of pure descriptive
metrics. There are no judgments here: classifiers turn these numbers into labels.
Keeping that wall clean is what lets each classifier be a small, independently
testable function.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Sequence
from datetime import datetime

from . import uas
from .dataload import load_list
from .model import ClientFeatures, LogEntry

# Static sub-resource extensions — the things a browser pulls in after a page.
_STATIC_EXT = frozenset("""css js mjs png jpg jpeg gif svg webp avif ico bmp woff woff2 ttf eot otf
    map mp4 webm mp3 ogg wav pdf""".split())
_PAGE_EXT = frozenset("html htm xhtml php asp aspx jsp shtml cfm".split())

# Path markers for directory traversal / injection attempts.
_TRAVERSAL_MARKERS = ("../", "..%2f", "%2e%2e", "..\\", "%00", "/etc/passwd", "/proc/self")

_EXOTIC_METHODS = frozenset("PUT DELETE PROPFIND PROPPATCH CONNECT TRACE PATCH MKCOL".split())

_COLOAD_WINDOW_SECONDS = 10.0


def _extension(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def _is_static(path: str) -> bool:
    return _extension(path) in _STATIC_EXT


def _is_page(entry: LogEntry) -> bool:
    if entry.status != 200 or _is_static(entry.path):
        return False
    ext = _extension(entry.path)
    return entry.path.endswith("/") or ext == "" or ext in _PAGE_EXT


def _referer_path(referer: str) -> str:
    after = referer.split("://", 1)[-1]
    slash = after.find("/")
    if slash == -1:
        return "/"
    return after[slash:].split("?", 1)[0]


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _matches_vuln(path: str, patterns: Sequence[str]) -> bool:
    low = path.lower()
    return any(p.lower() in low for p in patterns)


def _timing(times: list[datetime]) -> dict[str, float | None]:
    """Inter-arrival statistics (seconds) from sorted timestamps."""
    if len(times) < 2:
        return {"mean": None, "median": None, "p95": None, "min": None, "cv": None}
    intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    intervals.sort()
    mean = statistics.fmean(intervals)
    idx = min(len(intervals) - 1, int(round(0.95 * (len(intervals) - 1))))
    cv = (statistics.pstdev(intervals) / mean) if mean > 0 else None
    return {
        "mean": mean,
        "median": statistics.median(intervals),
        "p95": intervals[idx],
        "min": intervals[0],
        "cv": cv,
    }


def _peak_rpm(times: list[datetime]) -> int:
    if not times:
        return 0
    buckets: Counter[int] = Counter(int(t.timestamp() // 60) for t in times)
    return max(buckets.values())


def _coload_ratio(ordered: list[LogEntry]) -> float:
    """Fraction of page responses followed by a static sub-resource shortly after."""
    pages = [e for e in ordered if _is_page(e)]
    if not pages:
        return 0.0
    timed = [(e.timestamp, e) for e in ordered if e.timestamp is not None]
    followed = 0
    for page in pages:
        if page.timestamp is None:
            continue
        deadline = page.timestamp.timestamp() + _COLOAD_WINDOW_SECONDS
        for stamp, entry in timed:
            if stamp is None or entry is page:
                continue
            ts = stamp.timestamp()
            if page.timestamp.timestamp() <= ts <= deadline and _is_static(entry.path):
                followed += 1
                break
    return _ratio(followed, len(pages))


def _top_segment(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else ""


def _breadth_ratio(ordered: list[LogEntry]) -> float:
    """Fraction of consecutive hops that jump to a different top-level subtree."""
    tops = [_top_segment(e.path) for e in ordered]
    if len(tops) < 2:
        return 0.0
    changes = sum(1 for a, b in zip(tops, tops[1:]) if a != b)
    return _ratio(changes, len(tops) - 1)


def _referer_following(entries: Sequence[LogEntry], fetched: set[str]) -> float:
    with_ref = [e for e in entries if e.referer]
    if not with_ref:
        return 0.0
    on_site = sum(1 for e in with_ref if _referer_path(e.referer or "") in fetched)
    return _ratio(on_site, len(with_ref))


def extract_features(entries: Sequence[LogEntry], *, ua_count_for_ip: int = 1) -> ClientFeatures:
    """Compute the feature vector for one client's entries."""
    count = len(entries)
    if count == 0:
        return ClientFeatures()

    def _stamp(entry: LogEntry) -> datetime:
        assert entry.timestamp is not None
        return entry.timestamp

    timed = sorted((e for e in entries if e.timestamp is not None), key=_stamp)
    ordered = [*timed, *(e for e in entries if e.timestamp is None)]
    times = [_stamp(e) for e in timed]

    total_bytes = sum(e.bytes_sent or 0 for e in entries)
    statuses = [e.status for e in entries if e.status is not None]
    status_counts: Counter[int] = Counter(statuses)
    with_status = len(statuses)
    class_counts = Counter(s // 100 for s in statuses)
    paths_404 = {e.path for e in entries if e.status == 404}

    vuln_patterns = load_list("vuln_paths.txt")
    vuln_paths = [e.path for e in entries if _matches_vuln(e.path, vuln_patterns)]
    sample_vuln = tuple(dict.fromkeys(vuln_paths))[:5]
    traversal = sum(
        1
        for e in entries
        if any(m in (e.path + (e.query or "")).lower() for m in _TRAVERSAL_MARKERS)
    )

    timing = _timing(times)
    methods: Counter[str] = Counter(e.method for e in entries if e.method)
    fetched_paths = {e.path for e in entries}

    user_agent = next((e.user_agent for e in entries if e.user_agent), None)
    duration = (times[-1] - times[0]).total_seconds() if len(times) >= 2 else 0.0

    return ClientFeatures(
        request_count=count,
        total_bytes=total_bytes,
        mean_bytes=total_bytes / count,
        first_seen=times[0] if times else None,
        last_seen=times[-1] if times else None,
        duration_seconds=duration,
        status_counts=dict(status_counts),
        ratio_2xx=_ratio(class_counts.get(2, 0), with_status),
        ratio_3xx=_ratio(class_counts.get(3, 0), with_status),
        ratio_4xx=_ratio(class_counts.get(4, 0), with_status),
        ratio_5xx=_ratio(class_counts.get(5, 0), with_status),
        ratio_404=_ratio(status_counts.get(404, 0), with_status),
        distinct_404_paths=len(paths_404),
        vuln_path_hits=len(vuln_paths),
        vuln_path_ratio=_ratio(len(vuln_paths), count),
        sample_vuln_paths=sample_vuln,
        traversal_hits=traversal,
        inter_arrival_mean=timing["mean"],
        inter_arrival_median=timing["median"],
        inter_arrival_p95=timing["p95"],
        inter_arrival_min=timing["min"],
        peak_requests_per_minute=_peak_rpm(times),
        rate_regularity=timing["cv"],
        distinct_paths=len(fetched_paths),
        coverage=_ratio(len(fetched_paths), count),
        breadth_ratio=_breadth_ratio(ordered),
        referer_following_ratio=_referer_following(entries, fetched_paths),
        asset_coload_ratio=_coload_ratio(ordered),
        static_ratio=_ratio(sum(1 for e in entries if _is_static(e.path)), count),
        method_counts=dict(methods),
        get_ratio=_ratio(methods.get("GET", 0), count),
        head_ratio=_ratio(methods.get("HEAD", 0), count),
        post_ratio=_ratio(methods.get("POST", 0), count),
        exotic_method_count=sum(v for m, v in methods.items() if m in _EXOTIC_METHODS),
        fetched_robots_txt=any(e.path == "/robots.txt" for e in entries),
        user_agent=user_agent,
        ua_looks_like_browser=uas.looks_like_browser(user_agent),
        ua_declares_bot=uas.declares_bot(user_agent),
        ua_empty=uas.is_empty(user_agent),
        ua_count_for_ip=ua_count_for_ip,
    )
