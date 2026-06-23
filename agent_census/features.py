"""Per-client feature extraction.

Turns a client's requests into a :class:`ClientFeatures` of pure descriptive
metrics. There are no judgments here: classifiers turn these numbers into labels.

To stay memory-bounded on large logs, features are computed by a streaming
:class:`FeatureAccumulator` that folds one entry in at a time and never retains
the entries themselves -- only counters, a few small sets, and a compact array
of timestamps. :func:`extract_features` is a convenience wrapper that feeds a
whole list (timestamp-sorted) into one accumulator.
"""

from __future__ import annotations

import statistics
from array import array
from collections import Counter, deque
from collections.abc import Callable, Sequence
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

# Loaded once, shared by every accumulator (not stored per instance).
_VULN_PATTERNS = tuple(p.lower() for p in load_list("vuln_paths.txt"))

# Predicate the robots stage injects to flag a path the client may not fetch.
DisallowedCheck = Callable[[str], bool]


def _extension(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def _is_static(path: str) -> bool:
    return _extension(path) in _STATIC_EXT


def _is_page(status: int | None, path: str) -> bool:
    if status != 200 or _is_static(path):
        return False
    ext = _extension(path)
    return path.endswith("/") or ext == "" or ext in _PAGE_EXT


def _referer_path(referer: str) -> str:
    after = referer.split("://", 1)[-1]
    slash = after.find("/")
    if slash == -1:
        return "/"
    return after[slash:].split("?", 1)[0]


def _top_segment(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else ""


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _timing(times: Sequence[float]) -> dict[str, float | None]:
    """Inter-arrival statistics (seconds) from epoch timestamps."""
    if len(times) < 2:
        return {"mean": None, "median": None, "p95": None, "min": None, "cv": None}
    ordered = sorted(times)
    intervals = sorted(b - a for a, b in zip(ordered, ordered[1:]))
    mean = statistics.fmean(intervals)
    idx = min(len(intervals) - 1, round(0.95 * (len(intervals) - 1)))
    cv = (statistics.pstdev(intervals) / mean) if mean > 0 else None
    return {
        "mean": mean,
        "median": statistics.median(intervals),
        "p95": intervals[idx],
        "min": intervals[0],
        "cv": cv,
    }


def _peak_rpm(times: Sequence[float]) -> int:
    if not times:
        return 0
    buckets: Counter[int] = Counter(int(t // 60) for t in times)
    return max(buckets.values())


class FeatureAccumulator:
    """Folds a client's entries into feature metrics without retaining them.

    Real logs have a long tail of one-off clients, so the per-instance cost has
    to be tiny: ``__slots__`` avoids a per-client ``__dict__``, and the heavier
    containers (path sets, the timing array, the co-load deque, sample lists)
    are allocated lazily -- a client with a single request pays for almost none
    of them. Order-dependent metrics are computed in add order (request order
    for an access log). A ``disallowed_check`` lets this same pass score robots.
    """

    __slots__ = (
        "_disallowed_check", "count", "total_bytes", "status_counts", "count_404",
        "paths_404", "vuln_hits", "vuln_sample", "traversal_hits", "methods",
        "distinct_paths", "static_count", "fetched_robots", "user_agent", "first_seen",
        "last_seen", "_times", "_has_prev", "_prev_top", "breadth_changes",
        "breadth_pairs", "ref_total", "ref_onsite", "pages_total", "pages_satisfied",
        "_pending_pages", "disallowed_hits", "disallowed_sample", "robots_fetched_first",
        "_content_seen",
    )  # fmt: skip

    def __init__(self, *, disallowed_check: DisallowedCheck | None = None) -> None:
        self._disallowed_check = disallowed_check
        self.count = 0
        self.total_bytes = 0
        self.count_404 = 0
        self.vuln_hits = 0
        self.traversal_hits = 0
        self.static_count = 0
        self.fetched_robots = False
        self.user_agent: str | None = None
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self._has_prev = False
        self._prev_top = ""
        self.breadth_changes = 0
        self.breadth_pairs = 0
        self.ref_total = 0
        self.ref_onsite = 0
        self.pages_total = 0
        self.pages_satisfied = 0
        self.disallowed_hits = 0
        self.robots_fetched_first = False
        self._content_seen = False
        # Lazily allocated; None until first needed.
        self.status_counts: dict[int, int] | None = None
        self.paths_404: set[str] | None = None
        self.vuln_sample: list[str] | None = None
        self.methods: dict[str, int] | None = None
        self.distinct_paths: set[str] | None = None
        self._times: array[float] | None = None
        self._pending_pages: deque[float] | None = None
        self.disallowed_sample: list[str] | None = None

    def add(self, entry: LogEntry) -> None:
        path = entry.path
        self.count += 1
        self.total_bytes += entry.bytes_sent or 0
        if self.user_agent is None and entry.user_agent:
            self.user_agent = entry.user_agent

        if entry.status is not None:
            if self.status_counts is None:
                self.status_counts = {}
            self.status_counts[entry.status] = self.status_counts.get(entry.status, 0) + 1
            if entry.status == 404:
                self.count_404 += 1
                if self.paths_404 is None:
                    self.paths_404 = set()
                self.paths_404.add(path)

        low = path.lower()
        if any(pattern in low for pattern in _VULN_PATTERNS):
            self.vuln_hits += 1
            if self.vuln_sample is None:
                self.vuln_sample = []
            if len(self.vuln_sample) < 5 and path not in self.vuln_sample:
                self.vuln_sample.append(path)
        haystack = low + (entry.query or "").lower()
        if any(marker in haystack for marker in _TRAVERSAL_MARKERS):
            self.traversal_hits += 1

        if entry.method:
            if self.methods is None:
                self.methods = {}
            self.methods[entry.method] = self.methods.get(entry.method, 0) + 1
        if self.distinct_paths is None:
            self.distinct_paths = set()
        self.distinct_paths.add(path)
        static = _is_static(path)
        if static:
            self.static_count += 1

        self._track_robots(path)
        self._track_referer(entry)
        self._track_breadth(path)
        self._track_timing_and_coload(entry, path, static)

    def _track_robots(self, path: str) -> None:
        if path == "/robots.txt":
            self.fetched_robots = True
            if not self._content_seen:
                self.robots_fetched_first = True
        else:
            self._content_seen = True
        if self._disallowed_check is not None and path and self._disallowed_check(path):
            self.disallowed_hits += 1
            if self.disallowed_sample is None:
                self.disallowed_sample = []
            if len(self.disallowed_sample) < 5 and path not in self.disallowed_sample:
                self.disallowed_sample.append(path)

    def _track_referer(self, entry: LogEntry) -> None:
        if entry.referer:
            self.ref_total += 1
            if (
                self.distinct_paths is not None
                and _referer_path(entry.referer) in self.distinct_paths
            ):
                self.ref_onsite += 1

    def _track_breadth(self, path: str) -> None:
        top = _top_segment(path)
        if self._has_prev:
            self.breadth_pairs += 1
            if top != self._prev_top:
                self.breadth_changes += 1
        self._prev_top = top
        self._has_prev = True

    def _track_timing_and_coload(self, entry: LogEntry, path: str, static: bool) -> None:
        stamp = entry.timestamp
        if stamp is not None:
            if self.first_seen is None or stamp < self.first_seen:
                self.first_seen = stamp
            if self.last_seen is None or stamp > self.last_seen:
                self.last_seen = stamp
        ts = stamp.timestamp() if stamp is not None else None
        if ts is not None:
            if self._times is None:
                self._times = array("d")
            self._times.append(ts)
        pending = self._pending_pages
        if ts is not None and pending is not None:
            while pending and pending[0] < ts - _COLOAD_WINDOW_SECONDS:
                pending.popleft()
        if _is_page(entry.status, path):
            self.pages_total += 1
            if ts is not None:
                if self._pending_pages is None:
                    self._pending_pages = deque()
                self._pending_pages.append(ts)
        elif static and ts is not None and pending:
            self.pages_satisfied += len(pending)
            pending.clear()

    def finalize(self, *, ua_count_for_ip: int = 1) -> ClientFeatures:
        if self.count == 0:
            return ClientFeatures()
        status_counts = self.status_counts or {}
        methods = self.methods or {}
        times = self._times if self._times is not None else array("d")
        with_status = sum(status_counts.values())
        classes: Counter[int] = Counter()
        for status, hits in status_counts.items():
            classes[status // 100] += hits
        timing = _timing(times)
        duration = (
            (self.last_seen - self.first_seen).total_seconds()
            if self.first_seen is not None and self.last_seen is not None
            else 0.0
        )
        distinct = len(self.distinct_paths) if self.distinct_paths is not None else 0
        return ClientFeatures(
            request_count=self.count,
            total_bytes=self.total_bytes,
            mean_bytes=self.total_bytes / self.count,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            duration_seconds=duration,
            status_counts=dict(status_counts),
            ratio_2xx=_ratio(classes.get(2, 0), with_status),
            ratio_3xx=_ratio(classes.get(3, 0), with_status),
            ratio_4xx=_ratio(classes.get(4, 0), with_status),
            ratio_5xx=_ratio(classes.get(5, 0), with_status),
            ratio_404=_ratio(self.count_404, with_status),
            distinct_404_paths=len(self.paths_404) if self.paths_404 is not None else 0,
            vuln_path_hits=self.vuln_hits,
            vuln_path_ratio=_ratio(self.vuln_hits, self.count),
            sample_vuln_paths=tuple(self.vuln_sample or ()),
            traversal_hits=self.traversal_hits,
            inter_arrival_mean=timing["mean"],
            inter_arrival_median=timing["median"],
            inter_arrival_p95=timing["p95"],
            inter_arrival_min=timing["min"],
            peak_requests_per_minute=_peak_rpm(times),
            rate_regularity=timing["cv"],
            distinct_paths=distinct,
            coverage=_ratio(distinct, self.count),
            breadth_ratio=_ratio(self.breadth_changes, self.breadth_pairs),
            referer_following_ratio=_ratio(self.ref_onsite, self.ref_total),
            asset_coload_ratio=_ratio(self.pages_satisfied, self.pages_total),
            static_ratio=_ratio(self.static_count, self.count),
            method_counts=dict(methods),
            get_ratio=_ratio(methods.get("GET", 0), self.count),
            head_ratio=_ratio(methods.get("HEAD", 0), self.count),
            post_ratio=_ratio(methods.get("POST", 0), self.count),
            exotic_method_count=sum(v for m, v in methods.items() if m in _EXOTIC_METHODS),
            fetched_robots_txt=self.fetched_robots,
            user_agent=self.user_agent,
            ua_looks_like_browser=uas.looks_like_browser(self.user_agent),
            ua_declares_bot=uas.declares_bot(self.user_agent),
            ua_empty=uas.is_empty(self.user_agent),
            ua_count_for_ip=ua_count_for_ip,
        )


def extract_features(entries: Sequence[LogEntry], *, ua_count_for_ip: int = 1) -> ClientFeatures:
    """Compute the feature vector for one client's entries (timestamp-ordered)."""
    accumulator = FeatureAccumulator()
    timed = sorted((e for e in entries if e.timestamp is not None), key=_by_timestamp)
    for entry in timed:
        accumulator.add(entry)
    for entry in (e for e in entries if e.timestamp is None):
        accumulator.add(entry)
    return accumulator.finalize(ua_count_for_ip=ua_count_for_ip)


def _by_timestamp(entry: LogEntry) -> datetime:
    assert entry.timestamp is not None
    return entry.timestamp
