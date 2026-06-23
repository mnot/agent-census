"""Interactive browsers.

The strongest tell is sub-resource co-loading: a real browser, after fetching a
page, pulls its CSS/JS/images within seconds. Bursty (irregular) timing, on-site
link navigation, a browser-shaped UA, and a low error rate corroborate it.
"""

from __future__ import annotations

from ..model import ClientFeatures, Kind, Signal
from .base import Classifier


class BrowserClassifier(Classifier):
    label = Kind.BROWSER
    name = "browser"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        if features.asset_coload_ratio > 0.4:
            confidence += 0.45
            evidence.append(
                f"{features.asset_coload_ratio:.0%} of pages followed by sub-resource loads"
            )

        if features.ua_looks_like_browser:
            confidence += 0.2
            evidence.append("User-Agent matches a real browser profile")

        regularity = features.rate_regularity
        if regularity is not None and regularity > 0.6:
            confidence += 0.1
            evidence.append("irregular, bursty timing (human-like)")

        if features.referer_following_ratio > 0.3:
            confidence += 0.1
            evidence.append(
                f"{features.referer_following_ratio:.0%} of requests follow on-site links"
            )

        if features.ratio_404 < 0.1 and features.vuln_path_hits == 0:
            confidence += 0.1
            evidence.append("low error rate, no probing")

        if features.static_ratio > 0.3:
            confidence += 0.05
            evidence.append(f"{features.static_ratio:.0%} static-asset requests")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
