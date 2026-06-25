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

import math
import re
from array import array
from collections import Counter, deque
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import TypeVar

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

# Loaded once, shared by every accumulator (not stored per instance). Compiled into
# one alternation each so a request is one regex search, not N substring scans.
_VULN_PATTERNS = tuple(p.lower() for p in load_list("vuln_paths"))
_VULN_RE = re.compile("|".join(re.escape(p) for p in _VULN_PATTERNS)) if _VULN_PATTERNS else None
_TRAVERSAL_RE = re.compile("|".join(re.escape(m) for m in _TRAVERSAL_MARKERS))

# Predicate the robots stage injects to flag a path the client may not fetch.
DisallowedCheck = Callable[[str], bool]

_K = TypeVar("_K")


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


# Tokens that mark a feed in a URL filename, e.g. /blog/feed/, /index.rss, atom.xml.
# Matched as a whole dot/dash/underscore-delimited part, not a bare substring, so
# "feedback.html" / "anatomy.html" don't read as feeds (mirrors the word-anchored
# UA-side detection in classify/feed_reader.py).
_FEED_TOKENS = frozenset({"feed", "rss", "atom"})
_FILENAME_PARTS = re.compile(r"[.\-_]")


def _response_content_type(entry: LogEntry) -> str:
    """The logged response Content-Type, lower-cased, or '' if not captured."""
    for key, value in entry.extra.items():
        if key.lower() == "out:content-type":
            return value.lower()
    return ""


def _as_identity(entry: LogEntry) -> tuple[str | None, str | None]:
    """Autonomous-system (org, number) from a MaxMind env field, or (None, None).

    Matches ``%{MM_ASORG}e`` / ``%{MM_ASN}e`` and the long MaxMind field names,
    case-insensitively. Returns whatever the log carries; nothing is inferred.
    """
    org = number = None
    for key, value in entry.extra.items():
        if not value:
            continue
        name = key.lower().split(":", 1)[-1]  # drop the 'env:' / 'note:' prefix
        if org is None and ("asorg" in name or "autonomous_system_organization" in name):
            org = value
        elif number is None and ("asn" in name or "autonomous_system_number" in name):
            number = value
    return org, number


def _is_feed_request(entry: LogEntry, path: str) -> bool:
    """True if the request looks like a feed poll: feed-ish URL or RSS/Atom type."""
    segments = [p for p in path.split("/") if p]
    filename = segments[-1].lower() if segments else ""
    if _FEED_TOKENS.intersection(_FILENAME_PARTS.split(filename)):
        return True
    content_type = _response_content_type(entry)
    return "rss" in content_type or "atom" in content_type


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


# Inter-arrival deltas are summarised in O(1) memory instead of one float per
# request: mean/min/CV are kept exactly online, and the distribution (for
# median/p95) lives in a small log-spaced histogram once a client exceeds a
# buffer of exact deltas. Covers 1ms .. ~10^7s (~116 days), 10 buckets/decade.
_IAT_MIN_EXP = -3
_IAT_MAX_EXP = 7
_IAT_PER_DECADE = 10
_IAT_BUCKETS = (_IAT_MAX_EXP - _IAT_MIN_EXP) * _IAT_PER_DECADE + 2  # + under/overflow
_IAT_BUF_CAP = 256  # below this many deltas, keep them exactly (cheap for the long tail)


def _iat_bucket(delta: float) -> int:
    """Histogram bucket for an inter-arrival delta in seconds."""
    if delta <= 0:
        return 0
    idx = int((math.log10(delta) - _IAT_MIN_EXP) * _IAT_PER_DECADE) + 1
    return max(1, min(idx, _IAT_BUCKETS - 1))


def _iat_bucket_value(idx: int) -> float:
    """A representative delta (geometric centre) for a histogram bucket."""
    if idx <= 0:
        return 0.0
    exp = _IAT_MIN_EXP + (idx - 1 + 0.5) / _IAT_PER_DECADE
    return float(10**exp)


def _hist_quantile(hist: list[int], count: int, quantile: float) -> float:
    target = quantile * count
    cumulative = 0
    for idx, hits in enumerate(hist):
        cumulative += hits
        if cumulative >= target:
            return _iat_bucket_value(idx)
    return _iat_bucket_value(len(hist) - 1)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _merge_counts(left: dict[_K, int] | None, right: dict[_K, int] | None) -> dict[_K, int] | None:
    if right is None:
        return left
    merged = dict(left) if left is not None else {}
    for key, value in right.items():
        merged[key] = merged.get(key, 0) + value
    return merged


def _merge_sets(left: set[str] | None, right: set[str] | None) -> set[str] | None:
    if right is None:
        return left
    return right if left is None else (left | right)


def _merge_sample(left: list[str] | None, right: list[str] | None) -> list[str] | None:
    if not right:
        return left
    merged = list(left) if left else []
    for item in right:
        if len(merged) >= 5:
            break
        if item not in merged:
            merged.append(item)
    return merged


class FeatureAccumulator:  # pylint: disable=too-many-instance-attributes
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
        "distinct_paths", "static_count", "fetched_robots", "user_agent", "as_org",
        "as_number", "first_seen",
        "last_seen", "_has_prev", "_prev_top", "breadth_changes",
        "breadth_pairs", "ref_total", "ref_onsite", "self_referer_hits", "pages_total",
        "pages_satisfied",
        "_pending_pages", "disallowed_hits", "disallowed_sample", "robots_fetched_first",
        "_content_seen", "feed_requests",
        # Inter-arrival timing, summarised in bounded memory (no per-request array).
        "_prev_ts", "_iat_count", "_iat_sum", "_iat_sumsq", "_iat_min",
        "_iat_buf", "_iat_hist", "_minute_counts",
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
        self.as_org: str | None = None
        self.as_number: str | None = None
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self._has_prev = False
        self._prev_top = ""
        self.breadth_changes = 0
        self.breadth_pairs = 0
        self.ref_total = 0
        self.ref_onsite = 0
        self.self_referer_hits = 0
        self.pages_total = 0
        self.pages_satisfied = 0
        self.disallowed_hits = 0
        self.robots_fetched_first = False
        self._content_seen = False
        self.feed_requests = 0
        # Inter-arrival timing: mean/min/CV kept exactly online; the distribution
        # for median/p95 stays in a small exact buffer until it overflows into a
        # fixed log-histogram. peak rpm uses per-minute counts (bounded by span).
        self._prev_ts: float | None = None
        self._iat_count = 0
        self._iat_sum = 0.0
        self._iat_sumsq = 0.0
        self._iat_min: float | None = None
        self._iat_buf: array[float] | None = None
        self._iat_hist: list[int] | None = None
        self._minute_counts: dict[int, int] | None = None
        # Lazily allocated; None until first needed.
        self.status_counts: dict[int, int] | None = None
        self.paths_404: set[str] | None = None
        self.vuln_sample: list[str] | None = None
        self.methods: dict[str, int] | None = None
        self.distinct_paths: set[str] | None = None
        self._pending_pages: deque[float] | None = None
        self.disallowed_sample: list[str] | None = None

    def add(self, entry: LogEntry) -> None:
        path = entry.path
        self.count += 1
        self.total_bytes += entry.bytes_sent or 0
        if self.user_agent is None and entry.user_agent:
            self.user_agent = entry.user_agent
        if (self.as_org is None or self.as_number is None) and entry.extra:
            # Capture each field independently and only once: a log may carry the
            # AS number but not the org (or vice versa), and a later line missing
            # the field must never overwrite a value already captured.
            org, number = _as_identity(entry)
            if self.as_org is None:
                self.as_org = org
            if self.as_number is None:
                self.as_number = number

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
        if _VULN_RE is not None and _VULN_RE.search(low):
            self.vuln_hits += 1
            if self.vuln_sample is None:
                self.vuln_sample = []
            if len(self.vuln_sample) < 5 and path not in self.vuln_sample:
                self.vuln_sample.append(path)
        haystack = low + (entry.query or "").lower()
        if _TRAVERSAL_RE.search(haystack):
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
        if _is_feed_request(entry, path):
            self.feed_requests += 1

        self._track_robots(path)
        self._track_referer(entry)
        self._track_breadth(path)
        self._track_timing_and_coload(entry, path, static)

    def _track_robots(self, path: str) -> None:
        if path == "/robots.txt":
            self.fetched_robots = True
            if not self._content_seen:
                self.robots_fetched_first = True
            return  # robots.txt is always fetchable; never a disallowed hit
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
            referer_path = _referer_path(entry.referer)
            if referer_path == entry.path:
                # Referer equals the requested URL -- impossible from real
                # navigation (you don't arrive at a page from itself), so it is a
                # fabricated referer, not evidence of on-site link following.
                self.self_referer_hits += 1
            elif self.distinct_paths is not None and referer_path in self.distinct_paths:
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
            self._record_arrival(ts)
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

    def _record_arrival(self, ts: float) -> None:
        """Fold one request's timestamp into the bounded timing summary."""
        if self._minute_counts is None:
            self._minute_counts = {}
        minute = int(ts // 60)
        self._minute_counts[minute] = self._minute_counts.get(minute, 0) + 1
        # Inter-arrival in stream order (≈ time order); skip out-of-order negatives.
        if self._prev_ts is not None and ts >= self._prev_ts:
            self._record_delta(ts - self._prev_ts)
        self._prev_ts = ts

    def _record_delta(self, delta: float) -> None:
        self._iat_count += 1
        self._iat_sum += delta
        self._iat_sumsq += delta * delta
        if self._iat_min is None or delta < self._iat_min:
            self._iat_min = delta
        if self._iat_hist is not None:
            self._iat_hist[_iat_bucket(delta)] += 1
            return
        if self._iat_buf is None:
            self._iat_buf = array("d")
        self._iat_buf.append(delta)
        if len(self._iat_buf) > _IAT_BUF_CAP:  # outgrew the exact buffer -> histogram
            self._ensure_iat_hist()

    def _ensure_iat_hist(self) -> None:
        if self._iat_hist is not None:
            return
        self._iat_hist = [0] * _IAT_BUCKETS
        for delta in self._iat_buf or ():
            self._iat_hist[_iat_bucket(delta)] += 1
        self._iat_buf = None

    def _timing_stats(self) -> dict[str, float | None]:
        """Inter-arrival statistics (seconds): mean/min/CV exact, quantiles binned."""
        if self._iat_count < 1:
            return {"mean": None, "median": None, "p95": None, "min": None, "cv": None}
        mean = self._iat_sum / self._iat_count
        variance = max(0.0, self._iat_sumsq / self._iat_count - mean * mean)
        cv = (math.sqrt(variance) / mean) if mean > 0 else None
        if self._iat_hist is not None:
            median = _hist_quantile(self._iat_hist, self._iat_count, 0.5)
            p95 = _hist_quantile(self._iat_hist, self._iat_count, 0.95)
        else:
            buf = sorted(self._iat_buf or array("d"))
            median = _median(buf)
            p95 = buf[min(len(buf) - 1, round(0.95 * (len(buf) - 1)))]
        return {"mean": mean, "median": median, "p95": p95, "min": self._iat_min, "cv": cv}

    def merge(self, other: FeatureAccumulator) -> None:
        """Fold ``other`` into this accumulator (used to collapse a bot's IPs).

        Counts and unions combine exactly; timing summaries combine additively
        (sums, min, histograms, per-minute counts); order-dependent counters are
        summed (each member was a separate connection, so summing is sound).
        """
        self.count += other.count
        self.total_bytes += other.total_bytes
        self.count_404 += other.count_404
        self.vuln_hits += other.vuln_hits
        self.traversal_hits += other.traversal_hits
        self.static_count += other.static_count
        self.breadth_changes += other.breadth_changes
        self.breadth_pairs += other.breadth_pairs
        self.ref_total += other.ref_total
        self.ref_onsite += other.ref_onsite
        self.self_referer_hits += other.self_referer_hits
        self.pages_total += other.pages_total
        self.pages_satisfied += other.pages_satisfied
        self.feed_requests += other.feed_requests
        self.disallowed_hits += other.disallowed_hits
        self.fetched_robots = self.fetched_robots or other.fetched_robots
        self.robots_fetched_first = self.robots_fetched_first or other.robots_fetched_first
        if self.user_agent is None:
            self.user_agent = other.user_agent
        if self.as_org is None:
            self.as_org = other.as_org
        if self.as_number is None:
            self.as_number = other.as_number
        if other.first_seen is not None and (
            self.first_seen is None or other.first_seen < self.first_seen
        ):
            self.first_seen = other.first_seen
        if other.last_seen is not None and (
            self.last_seen is None or other.last_seen > self.last_seen
        ):
            self.last_seen = other.last_seen
        self.status_counts = _merge_counts(self.status_counts, other.status_counts)
        self.methods = _merge_counts(self.methods, other.methods)
        self.paths_404 = _merge_sets(self.paths_404, other.paths_404)
        self.distinct_paths = _merge_sets(self.distinct_paths, other.distinct_paths)
        self.vuln_sample = _merge_sample(self.vuln_sample, other.vuln_sample)
        self.disallowed_sample = _merge_sample(self.disallowed_sample, other.disallowed_sample)
        self._merge_timing(other)

    def _merge_timing(self, other: FeatureAccumulator) -> None:
        # Combines a sibling accumulator's internals.
        # pylint: disable=protected-access
        self._iat_count += other._iat_count
        self._iat_sum += other._iat_sum
        self._iat_sumsq += other._iat_sumsq
        if other._iat_min is not None and (self._iat_min is None or other._iat_min < self._iat_min):
            self._iat_min = other._iat_min
        if other._minute_counts:
            if self._minute_counts is None:
                self._minute_counts = {}
            for minute, hits in other._minute_counts.items():
                self._minute_counts[minute] = self._minute_counts.get(minute, 0) + hits
        # Combine the inter-arrival distributions. If either side already binned,
        # or together they'd outgrow the exact buffer, both go to the histogram.
        buffered = len(self._iat_buf or ()) + len(other._iat_buf or ())
        if self._iat_hist is not None or other._iat_hist is not None or buffered > _IAT_BUF_CAP:
            self._ensure_iat_hist()
            assert self._iat_hist is not None  # _ensure_iat_hist just built it
            if other._iat_hist is not None:
                for idx, hits in enumerate(other._iat_hist):
                    self._iat_hist[idx] += hits
            else:
                for delta in other._iat_buf or ():
                    self._iat_hist[_iat_bucket(delta)] += 1
        elif other._iat_buf:
            if self._iat_buf is None:
                self._iat_buf = array("d")
            self._iat_buf.extend(other._iat_buf)

    def finalize(self, *, ua_count_for_ip: int = 1) -> ClientFeatures:
        if self.count == 0:
            return ClientFeatures()
        status_counts = self.status_counts or {}
        methods = self.methods or {}
        with_status = sum(status_counts.values())
        classes: Counter[int] = Counter()
        for status, hits in status_counts.items():
            classes[status // 100] += hits
        timing = self._timing_stats()
        peak_rpm = max(self._minute_counts.values()) if self._minute_counts else 0
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
            peak_requests_per_minute=peak_rpm,
            rate_regularity=timing["cv"],
            distinct_paths=distinct,
            coverage=_ratio(distinct, self.count),
            breadth_ratio=_ratio(self.breadth_changes, self.breadth_pairs),
            referer_following_ratio=_ratio(self.ref_onsite, self.ref_total),
            self_referer_ratio=_ratio(self.self_referer_hits, self.ref_total),
            referer_count=self.ref_total,
            asset_coload_ratio=_ratio(self.pages_satisfied, self.pages_total),
            static_ratio=_ratio(self.static_count, self.count),
            page_count=self.pages_total,
            method_counts=dict(methods),
            get_ratio=_ratio(methods.get("GET", 0), self.count),
            head_ratio=_ratio(methods.get("HEAD", 0), self.count),
            post_ratio=_ratio(methods.get("POST", 0), self.count),
            exotic_method_count=sum(v for m, v in methods.items() if m in _EXOTIC_METHODS),
            feed_requests=self.feed_requests,
            feed_ratio=_ratio(self.feed_requests, self.count),
            fetched_robots_txt=self.fetched_robots,
            user_agent=self.user_agent,
            ua_looks_like_browser=uas.looks_like_browser(self.user_agent),
            ua_declares_bot=uas.declares_bot(self.user_agent),
            ua_empty=uas.is_empty(self.user_agent),
            ua_count_for_ip=ua_count_for_ip,
            as_org=self.as_org,
            as_number=self.as_number,
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
