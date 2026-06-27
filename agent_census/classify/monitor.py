"""Uptime / monitoring checks.

A monitor hammers one or a few URLs on a fixed schedule, often with HEAD, at very
regular intervals — the lowest timing variability of any client kind.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..dataload import load_list, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

# Monitoring-service UA tokens live in data/signatures/monitor_uas.toml; numeric knobs in
# data/tuning/monitor.toml.
_MONITOR_UA = re.compile("|".join(re.escape(s) for s in load_list("monitor_uas")), re.I)
_TUNING_SCHEMA = {
    "ua_weight": "monitor_ua.weight",
    "few_urls_distinct_max": "few_urls.distinct_paths_max",
    "few_urls_min_requests": "few_urls.min_requests",
    "few_urls_weight": "few_urls.weight",
    "head_ratio_min": "head_polling.head_ratio_min",
    "head_weight": "head_polling.weight",
    "regular_max": "regular_polling.regularity_max",
    "regular_min_requests": "regular_polling.min_requests",
    "regular_weight": "regular_polling.weight",
}
_T = load_tuning("monitor", _TUNING_SCHEMA)


@lru_cache(maxsize=16384)
def _ua_is_monitor(ua: str | None) -> bool:
    return bool(ua and _MONITOR_UA.search(ua))


class MonitorClassifier(Classifier):
    label = Kind.MONITOR
    name = "monitor"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        if _ua_is_monitor(features.user_agent):
            confidence += _T["ua_weight"]
            evidence.append("User-Agent names a monitoring service")

        if (
            features.distinct_paths <= _T["few_urls_distinct_max"]
            and features.request_count >= _T["few_urls_min_requests"]
        ):
            confidence += _T["few_urls_weight"]
            evidence.append(f"polls just {features.distinct_paths} URL(s) repeatedly")

        if features.head_ratio > _T["head_ratio_min"]:
            confidence += _T["head_weight"]
            evidence.append(f"{features.head_ratio:.0%} HEAD requests")

        regularity = features.rate_regularity
        if (
            regularity is not None
            and regularity < _T["regular_max"]
            and features.request_count >= _T["regular_min_requests"]
        ):
            confidence += _T["regular_weight"]
            evidence.append("highly regular polling interval")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
