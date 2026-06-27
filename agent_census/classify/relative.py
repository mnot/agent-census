"""Site-relative magnitude tags, calibrated against a browser reference population.

Some signals -- how fast a client requests, how much it transfers, how broadly it
crawls, how long it stays -- are meaningless as global constants: 500 req/min is
nothing for a busy site and a flood for a blog. They only mean something *relative
to the site's own traffic*. The reference is deliberately the site's high-confidence
real browsers: bots imitate the browser User-Agent but not its behaviour, so a
browser baseline is robust even when the population is bot-dominated, and it
auto-calibrates to the site (a JS-heavy site makes real browsers fire more
sub-resource requests, lifting the envelope on its own).

The reference pool must not depend on the metrics derived from it, or the baseline
would chase the thing it measures. So :func:`is_reference_browser` is built only
from *absolute* browser evidence (UA shape, asset co-loading, caching / link
following) and never from rate/bytes/breadth/duration.

This module is metric-agnostic: it knows four metrics -- ``rate`` (peak req/min),
``bytes`` (mean response size, so it isn't a restatement of rate), ``breadth``
(fraction of hops changing subtree), ``duration`` (session span) -- but which ones
actually emit a tag for a given kind is the per-kind config's job
(``data/relative_tags.toml``), the single lever for suppressing a metric that proves
noisy for some kind. The unbounded magnitudes calibrate as ``p95(log) x margin``;
``breadth`` is a bounded ratio and uses a high linear percentile instead (see
:data:`_BOUNDED_METRICS`).
"""

from __future__ import annotations

import math
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib.resources import files

from ..errors import ConfigError
from ..model import ClientFeatures, ClientProfile, Kind
from .tags import BROWSER_COLOAD_MIN, BROWSER_FOLLOW_MIN

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 has no stdlib tomllib.
    import tomli as tomllib


# The metrics the framework can tag, each mapped to the tag it emits. A metric only
# fires when a kind's config lists it.
_METRIC_TAGS: dict[str, str] = {
    "rate": "high-rate",  # peak requests/minute well above a typical browser's
    "bytes": "high-bytes",  # mean response size -- few large objects, not just volume
    "breadth": "wide-breadth",  # fraction of hops that change subtree (bounded 0..1)
    "duration": "long-session",  # session lifespan
}
METRICS: tuple[str, ...] = tuple(_METRIC_TAGS)

# Metrics that are bounded ratios in [0, 1] rather than unbounded heavy-tailed
# magnitudes. The unbounded ones calibrate as ``p95(log) x margin``; that model is
# wrong for a bounded ratio -- a margin > 1 pushes the threshold above 1.0, where no
# client can reach it and the tag silently never fires. A bounded ratio instead uses
# a high linear percentile of the browser pool directly (no multiplicative margin),
# so "wider than ~all browsers on this site" stays reachable.
_BOUNDED_METRICS: frozenset[str] = frozenset({"breadth"})

# The bounded-metric percentile and the magnitude-stability request gate are tunable
# in relative_tags.toml [params]; they are bound to module constants at the end of
# the config section below, where the loader is in scope, so the bare predicates that
# use them (is_reference_browser / _gated) don't each need the params threaded in.


def is_reference_browser(features: ClientFeatures) -> bool:
    """A high-confidence *real* browser: the reference population for relative tags.

    Built strictly from the absolute browser signals the fingerprint tags already
    use (:data:`~agent_census.classify.tags.BROWSER_COLOAD_MIN` /
    :data:`~agent_census.classify.tags.BROWSER_FOLLOW_MIN`), never from the
    magnitude metrics we calibrate -- that is what breaks the circularity. It is a
    strict sibling of ``looks_like_fake_browser``'s inverse: a costume browser has
    ``asset_coload_ratio == 0`` and ``referer_following_ratio == 0``, so it can
    never qualify, which is exactly right -- the pool is real browsers only.
    """
    if not features.ua_looks_like_browser or features.request_count < _MIN_REQUESTS:
        return False
    if features.page_count <= 0 or features.asset_coload_ratio <= BROWSER_COLOAD_MIN:
        return False
    has_cache = features.status_counts.get(304, 0) > 0
    follows = features.referer_count > 0 and features.referer_following_ratio > BROWSER_FOLLOW_MIN
    return has_cache or follows


# A reference pool is a named membership predicate. v1 has exactly one -- browsers;
# every kind defaults to it. Adding a pool is adding an entry here plus a config
# that references it by name.
_POOLS: dict[str, Callable[[ClientFeatures], bool]] = {"browsers": is_reference_browser}


def _metric_value(features: ClientFeatures, metric: str) -> float:
    if metric == "rate":
        return float(features.peak_requests_per_minute)
    if metric == "bytes":
        # Mean response size, not total: total scales with request_count, so it
        # largely shadows high-rate. The mean isolates few-large-objects / heavy
        # downloads -- the independent signal this metric is meant to catch.
        return features.mean_bytes
    if metric == "breadth":
        return features.breadth_ratio
    if metric == "duration":
        return features.duration_seconds
    raise AssertionError(f"unknown metric {metric!r}")  # pragma: no cover


def _gated(features: ClientFeatures, metric: str) -> bool:
    """Whether ``features`` has enough data for ``metric`` to mean anything."""
    # All four magnitude metrics need a handful of requests; below that a single
    # burst or transfer would tag a client that barely showed up.
    del metric  # same gate for every metric in v1
    return features.request_count >= _MIN_REQUESTS


def _nearest_rank(values: list[float], quantile: float) -> float:
    """Nearest-rank ``quantile`` of ``values`` (assumed sorted, non-empty)."""
    rank = max(0, min(len(values) - 1, math.ceil(quantile * len(values)) - 1))
    return values[rank]


def _p95_log(values: list[float]) -> float | None:
    """The 95th-percentile of the positive values, computed on a log scale.

    These metrics are heavy-tailed, so the percentile is taken over ``log(value)``
    and exponentiated back. Returns ``None`` when no positive sample exists.
    """
    pos = sorted(v for v in values if v > 0)
    if not pos:
        return None
    # The 0.95 is fixed: it *defines* this branch's "p95(log) x margin" model and is
    # not the tunable `bounded_percentile` (which is the separate linear percentile
    # the bounded-ratio branch in _relative_threshold uses). Two distinct knobs that
    # happen to share a value -- moving one must not move the other.
    return math.exp(_nearest_rank([math.log(v) for v in pos], 0.95))


def _relative_threshold(metric: str, samples: list[float], margin: float) -> float | None:
    """The reference pool's relative bar for ``metric``, or ``None`` if uncomputable.

    Bounded ratios use a high linear percentile (zeros included) with no margin;
    unbounded heavy-tailed magnitudes use ``p95(log) x margin``.
    """
    if metric in _BOUNDED_METRICS:
        if not samples:
            return None
        return _nearest_rank(sorted(samples), _BOUNDED_PERCENTILE)
    p95 = _p95_log(samples)
    return None if p95 is None else p95 * margin


# --------------------------------------------------------------------------- config


@dataclass(frozen=True, slots=True)
class RelativeParams:
    """Tunable knobs: the relative margin, the thin-pool cutoff, per-metric floors,
    the magnitude-stability request gate, and the bounded-metric percentile."""

    margin: float
    min_reference: int
    floors: Mapping[str, float]
    min_requests: int
    bounded_percentile: float


@dataclass(frozen=True, slots=True)
class KindReference:
    """One kind's two knobs: which pool to compare against, which metrics to emit."""

    reference: str
    metrics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RelativeTagConfig:
    """The whole ``relative_tags.toml``: params, a default rule, per-kind overrides."""

    params: RelativeParams
    default: KindReference
    overrides: Mapping[str, KindReference]

    def for_kind(self, kind: Kind) -> KindReference:
        return self.overrides.get(kind.value, self.default)


_PARAMS_KEYS = {"margin", "min_reference", "min_requests", "bounded_percentile"} | {
    f"floor_{m}" for m in METRICS
}
_RULE_KEYS = {"reference", "tags"}


def _num(ctx: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"relative_tags.toml: {ctx} must be a number")
    return float(value)


def _rule(ctx: str, table: Mapping[str, object]) -> KindReference:
    extra = set(table) - _RULE_KEYS
    if extra:
        raise ConfigError(
            f"relative_tags.toml: {ctx}: unexpected key(s) {', '.join(sorted(extra))}"
        )
    reference = table.get("reference", "browsers")
    if not isinstance(reference, str) or reference not in _POOLS:
        raise ConfigError(
            f"relative_tags.toml: {ctx}: 'reference' must be one of {', '.join(sorted(_POOLS))}"
        )
    metrics = table.get("tags", [])
    if not isinstance(metrics, list) or not all(isinstance(m, str) for m in metrics):
        raise ConfigError(f"relative_tags.toml: {ctx}: 'tags' must be a list of metric names")
    bad = [m for m in metrics if m not in METRICS]
    if bad:
        raise ConfigError(
            f"relative_tags.toml: {ctx}: unknown metric(s) {', '.join(bad)} "
            f"(allowed: {', '.join(METRICS)})"
        )
    return KindReference(reference=reference, metrics=tuple(metrics))


@lru_cache(maxsize=None)
def load_relative_tags() -> RelativeTagConfig:
    """Load and validate ``data/relative_tags.toml`` (cached per run)."""
    text = (files("agent_census.data") / "relative_tags.toml").read_text(encoding="utf-8")
    return parse_relative_tags(tomllib.loads(text))


def parse_relative_tags(data: Mapping[str, object]) -> RelativeTagConfig:
    """Validate already-parsed config data into a :class:`RelativeTagConfig`."""
    extra = set(data) - {"params", "default", "kind"}
    if extra:
        raise ConfigError(
            f"relative_tags.toml: unexpected top-level key(s) {', '.join(sorted(extra))}"
        )
    raw_params = data.get("params", {})
    if not isinstance(raw_params, dict):
        raise ConfigError("relative_tags.toml: [params] must be a table")
    missing = _PARAMS_KEYS - set(raw_params)
    if missing:
        raise ConfigError(f"relative_tags.toml: [params] missing {', '.join(sorted(missing))}")
    unexpected = set(raw_params) - _PARAMS_KEYS
    if unexpected:
        raise ConfigError(
            f"relative_tags.toml: [params] unexpected key(s) {', '.join(sorted(unexpected))}"
        )
    min_ref = raw_params["min_reference"]
    if isinstance(min_ref, bool) or not isinstance(min_ref, int):
        raise ConfigError("relative_tags.toml: [params] 'min_reference' must be an integer")
    min_req = raw_params["min_requests"]
    if isinstance(min_req, bool) or not isinstance(min_req, int):
        raise ConfigError("relative_tags.toml: [params] 'min_requests' must be an integer")
    params = RelativeParams(
        margin=_num("[params] 'margin'", raw_params["margin"]),
        min_reference=min_ref,
        floors={m: _num(f"[params] 'floor_{m}'", raw_params[f"floor_{m}"]) for m in METRICS},
        min_requests=min_req,
        bounded_percentile=_num("[params] 'bounded_percentile'", raw_params["bounded_percentile"]),
    )
    raw_default = data.get("default", {})
    if not isinstance(raw_default, dict):
        raise ConfigError("relative_tags.toml: [default] must be a table")
    default = _rule("[default]", raw_default)
    overrides: dict[str, KindReference] = {}
    kinds = {k.value for k in Kind}
    raw_kinds = data.get("kind", [])
    if not isinstance(raw_kinds, list):
        raise ConfigError("relative_tags.toml: [[kind]] must be an array of tables")
    for index, table in enumerate(raw_kinds, start=1):
        if not isinstance(table, dict) or "kind" not in table:
            raise ConfigError(f"relative_tags.toml: [[kind]] #{index} needs a 'kind'")
        name = table["kind"]
        if name not in kinds:
            raise ConfigError(f"relative_tags.toml: [[kind]] #{index}: unknown kind {name!r}")
        overrides[name] = _rule(f"[[kind]] {name}", {k: v for k, v in table.items() if k != "kind"})
    return RelativeTagConfig(params=params, default=default, overrides=overrides)


# Bound once here, where the loader is fully defined, for the bare predicates above
# (is_reference_browser / _gated) that have no params in hand. The load is cached, so
# this is the same config every other caller sees.
_PARAMS = load_relative_tags().params
_MIN_REQUESTS = _PARAMS.min_requests
_BOUNDED_PERCENTILE = _PARAMS.bounded_percentile


# ----------------------------------------------------------------- sampling / tagging


@dataclass(frozen=True, slots=True)
class MetricThreshold:
    """The firing threshold for one metric in one pool, and how it was derived."""

    metric: str
    value: float  # a client whose metric exceeds this is tagged
    floor: float  # the absolute floor (the sanity guard / thin-pool fallback)
    relative: float | None  # p95 x margin, or None when the relative gate was skipped
    fallback: bool  # True when the pool was too thin and only the floor applies


@dataclass(frozen=True, slots=True)
class ReferenceCalibration:
    """Per-pool thresholds and sample sizes computed at end of stream."""

    pool_sizes: Mapping[str, int]
    thresholds: Mapping[str, Mapping[str, MetricThreshold]]
    min_reference: int

    def threshold(self, pool: str, metric: str) -> MetricThreshold | None:
        return self.thresholds.get(pool, {}).get(metric)

    def warning(self) -> str | None:
        """A header note when any pool fell back to floors, else ``None``."""
        thin = sorted(p for p, n in self.pool_sizes.items() if n < self.min_reference)
        if not thin:
            return None
        size = self.pool_sizes.get(thin[0], 0)
        return (
            "Site-relative tags fell back to absolute floors — only "
            f"{size} high-confidence browser(s), too few for site-relative "
            f"calibration (need {self.min_reference})."
        )


class ReferenceCollector:
    """Accumulates reference-pool metric samples as clients stream past ``emit``.

    Fed for *every* client (resident / evicted / retired), so it sees the full
    distribution and is eviction-safe -- not just the capped ``kept`` heap.
    """

    __slots__ = ("_pools", "_samples", "_counts")

    def __init__(self, pools: Mapping[str, Callable[[ClientFeatures], bool]]) -> None:
        self._pools = pools
        self._samples: dict[str, dict[str, list[float]]] = {
            name: {m: [] for m in METRICS} for name in pools
        }
        self._counts: dict[str, int] = {name: 0 for name in pools}

    def observe(self, features: ClientFeatures) -> None:
        for name, predicate in self._pools.items():
            if predicate(features):
                self._counts[name] += 1
                bucket = self._samples[name]
                for metric in METRICS:
                    bucket[metric].append(_metric_value(features, metric))

    def calibrate(self, params: RelativeParams) -> ReferenceCalibration:
        thresholds: dict[str, dict[str, MetricThreshold]] = {}
        for name in self._pools:
            thin = self._counts[name] < params.min_reference
            per_metric: dict[str, MetricThreshold] = {}
            for metric in METRICS:
                floor = params.floors[metric]
                relative = (
                    None
                    if thin
                    else _relative_threshold(metric, self._samples[name][metric], params.margin)
                )
                value = floor if relative is None else max(floor, relative)
                per_metric[metric] = MetricThreshold(
                    metric=metric, value=value, floor=floor, relative=relative, fallback=thin
                )
            thresholds[name] = per_metric
        return ReferenceCalibration(
            pool_sizes=dict(self._counts), thresholds=thresholds, min_reference=params.min_reference
        )


def make_collector() -> ReferenceCollector:
    """A collector over the built-in reference pools."""
    return ReferenceCollector(_POOLS)


def _fmt_metric(metric: str, value: float) -> str:
    """A site-relative metric value rendered for inspect evidence."""
    if metric == "rate":
        return f"peak {value:,.0f} req/min"
    if metric == "bytes":
        return f"mean {value:,.0f} B/response"
    if metric == "breadth":
        return f"breadth {value:.0%}"
    if metric == "duration":
        return f"span {value:,.0f}s"
    return f"{value:g}"  # pragma: no cover


def _relative_evidence(metric: str, value: float, threshold: MetricThreshold, pool_n: int) -> str:
    """Why a site-relative tag fired: this client's value vs. the site's browser bar."""
    val, bound = _fmt_metric(metric, value), _fmt_metric(metric, threshold.value)
    if threshold.fallback:
        return f"{val} exceeds the absolute floor {bound} (too few reference browsers to calibrate)"
    return f"{val} exceeds this site's browser bar {bound} (from {pool_n:,} reference browser(s))"


def relative_tag_evidence(
    features: ClientFeatures,
    kind: Kind,
    config: RelativeTagConfig,
    calibration: ReferenceCalibration,
) -> dict[str, str]:
    """Site-relative tags a client of ``kind`` earns, each paired with its evidence.

    The single source for both :func:`relative_tags` and inspect mode's per-tag
    rationale, so the tag and the value-vs-threshold reason can't drift apart.
    """
    rule = config.for_kind(kind)
    pool_n = calibration.pool_sizes.get(rule.reference, 0)
    out: dict[str, str] = {}
    for metric in rule.metrics:
        if not _gated(features, metric):
            continue
        threshold = calibration.threshold(rule.reference, metric)
        if threshold is None:
            continue
        value = _metric_value(features, metric)
        if value > threshold.value:
            out[_METRIC_TAGS[metric]] = _relative_evidence(metric, value, threshold, pool_n)
    return out


def relative_tags(
    features: ClientFeatures,
    kind: Kind,
    config: RelativeTagConfig,
    calibration: ReferenceCalibration,
) -> frozenset[str]:
    """The site-relative tags a client of ``kind`` earns, per its class config."""
    return frozenset(relative_tag_evidence(features, kind, config, calibration))


def tag_profile(
    profile: ClientProfile,
    config: RelativeTagConfig,
    calibration: ReferenceCalibration,
    *,
    keep_evidence: bool = True,
) -> ClientProfile:
    """Return ``profile`` with any site-relative tags folded into its classification.

    A multi-client display fold (``profile.is_aggregate``) is left untouched: its
    rate / bytes / breadth / duration are the union of many independent clients,
    not one client's magnitudes, so a site-relative tag on it would be an artifact.

    ``keep_evidence`` carries the per-tag rationale onto the classification for
    inspect mode; the bulk ``analyze`` path passes ``False`` to hold no extra
    strings, mirroring the combiner's ``keep_signals``.
    """
    if profile.is_aggregate:
        return profile
    extra = relative_tag_evidence(
        profile.features, profile.classification.primary, config, calibration
    )
    if not extra:
        return profile
    cls = profile.classification
    tag_evidence = cls.tag_evidence + (tuple(extra.items()) if keep_evidence else ())
    classification = replace(cls, tags=cls.tags | set(extra), tag_evidence=tag_evidence)
    return replace(profile, classification=classification)
