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

This module is metric-agnostic: it knows four metrics but which ones actually emit
a tag is the per-kind config's job (``data/relative_tags.toml``). The first slice
wires only ``rate``; ``bytes`` / ``breadth`` / ``duration`` reuse all of this and
are turned on by listing them in a kind's ``tags``.
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


# The metrics the framework can tag, each mapped to the tag it emits. A metric
# only fires when a kind's config lists it; the value side is heavy-tailed and
# calibrated on a log scale against the reference pool's p95.
_METRIC_TAGS: dict[str, str] = {
    "rate": "high-rate",  # peak requests/minute well above a typical browser's
    "bytes": "high-bytes",  # total bytes transferred (fast-follow)
    "breadth": "wide-breadth",  # subtree-changing hops (fast-follow)
    "duration": "long-session",  # session lifespan (fast-follow)
}
METRICS: tuple[str, ...] = tuple(_METRIC_TAGS)

# Enough requests for a magnitude to be stable -- a singleton or near-singleton has
# no meaningful rate/volume. Matches the cadence tags' gate.
_MIN_REQUESTS = 5


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
        return float(features.total_bytes)
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


def _p95_log(values: list[float]) -> float | None:
    """The 95th-percentile of the positive values, computed on a log scale.

    These metrics are heavy-tailed, so the percentile is taken over ``log(value)``
    and exponentiated back. Returns ``None`` when no positive sample exists.
    """
    pos = sorted(v for v in values if v > 0)
    if not pos:
        return None
    logs = [math.log(v) for v in pos]
    rank = max(0, min(len(logs) - 1, math.ceil(0.95 * len(logs)) - 1))
    return math.exp(logs[rank])


# --------------------------------------------------------------------------- config


@dataclass(frozen=True, slots=True)
class RelativeParams:
    """Tunable knobs: the relative margin, the thin-pool cutoff, per-metric floors."""

    margin: float
    min_reference: int
    floors: Mapping[str, float]


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


_PARAMS_KEYS = {"margin", "min_reference"} | {f"floor_{m}" for m in METRICS}
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
    params = RelativeParams(
        margin=_num("[params] 'margin'", raw_params["margin"]),
        min_reference=min_ref,
        floors={m: _num(f"[params] 'floor_{m}'", raw_params[f"floor_{m}"]) for m in METRICS},
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
                p95 = None if thin else _p95_log(self._samples[name][metric])
                relative = None if p95 is None else p95 * params.margin
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


def relative_tags(
    features: ClientFeatures,
    kind: Kind,
    config: RelativeTagConfig,
    calibration: ReferenceCalibration,
) -> frozenset[str]:
    """The site-relative tags a client of ``kind`` earns, per its class config."""
    rule = config.for_kind(kind)
    out: set[str] = set()
    for metric in rule.metrics:
        if not _gated(features, metric):
            continue
        threshold = calibration.threshold(rule.reference, metric)
        if threshold is None:
            continue
        if _metric_value(features, metric) > threshold.value:
            out.add(_METRIC_TAGS[metric])
    return frozenset(out)


def tag_profile(
    profile: ClientProfile,
    config: RelativeTagConfig,
    calibration: ReferenceCalibration,
) -> ClientProfile:
    """Return ``profile`` with any site-relative tags folded into its classification."""
    extra = relative_tags(profile.features, profile.classification.primary, config, calibration)
    if not extra:
        return profile
    classification = replace(profile.classification, tags=profile.classification.tags | extra)
    return replace(profile, classification=classification)
