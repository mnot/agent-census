"""Uptime / monitoring checks.

A monitor hammers one or a few URLs on a fixed schedule, often with HEAD, at very
regular intervals — the lowest timing variability of any client kind.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .. import uas
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

_MONITOR_UA = re.compile(
    r"uptimerobot|pingdom|statuscake|site24x7|newrelic|datadog|nagios|zabbix|"
    r"monitor|healthcheck|hetrixtools|updown|cron-job",
    re.I,
)


@lru_cache(maxsize=uas.UA_CACHE_SIZE)
def _ua_is_monitor(ua: str | None) -> bool:
    return bool(ua and _MONITOR_UA.search(ua))


class MonitorClassifier(Classifier):
    label = Kind.MONITOR
    name = "monitor"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        if _ua_is_monitor(features.user_agent):
            confidence += 0.4
            evidence.append("User-Agent names a monitoring service")

        if features.distinct_paths <= 2 and features.request_count >= 5:
            confidence += 0.2
            evidence.append(f"polls just {features.distinct_paths} URL(s) repeatedly")

        if features.head_ratio > 0.5:
            confidence += 0.2
            evidence.append(f"{features.head_ratio:.0%} HEAD requests")

        regularity = features.rate_regularity
        if regularity is not None and regularity < 0.2 and features.request_count >= 5:
            confidence += 0.25
            evidence.append("highly regular polling interval")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
