"""Uptime / monitoring checks.

A monitor hammers one or a few URLs on a fixed schedule, often with HEAD, at very
regular intervals — the lowest timing variability of any client kind.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..dataload import load_list, load_tokens, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier


def _monitor_ua_pattern() -> "re.Pattern[str]":
    """UA substrings that name a monitoring service, from two sources kept distinct:

    * ``signatures/monitor_uas.toml`` -- monitor UA tokens with no origin to
      verify; and
    * ``agents/monitor.toml`` -- named monitors whose ``ua_substring`` is recorded
      there to authenticate them against a published range.

    Folding the latter in means a named monitor's UA lives in exactly one file
    (the one that also carries its ranges), not duplicated across both. Same
    contract as classify/vuln_scanner.py's ``_scanner_ua_tokens``.
    """
    tokens = list(load_list("monitor_uas"))
    tokens += [ua for ua, _spec in load_tokens("monitor")]
    return re.compile("|".join(re.escape(s) for s in dict.fromkeys(tokens)), re.I)


# Numeric knobs in data/tuning/monitor.toml.
_MONITOR_UA = _monitor_ua_pattern()
_TUNING_SCHEMA = {
    "ua_weight": "monitor_ua.weight",
    "few_urls_distinct_max": "few_urls.distinct_targets_max",
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
            features.distinct_targets <= _T["few_urls_distinct_max"]
            and features.request_count >= _T["few_urls_min_requests"]
        ):
            confidence += _T["few_urls_weight"]
            evidence.append(f"polls just {features.distinct_targets} URL(s) repeatedly")

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
