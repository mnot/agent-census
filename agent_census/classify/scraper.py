"""Content scrapers: broad harvesting of pages without following links.

Like a crawler in volume and coverage, but hits URLs cold (little to no on-site
link-following) and often rides a generic HTTP-library or empty User-Agent.
"""

from __future__ import annotations

from .. import uas
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier


class ScraperClassifier(Classifier):
    label = Kind.SCRAPER
    name = "scraper"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        broad = features.distinct_paths >= 10 and features.request_count >= 15
        if broad and features.asset_coload_ratio < 0.1 and not features.ua_looks_like_browser:
            confidence += 0.3
            evidence.append(
                f"harvests many pages ({features.distinct_paths} paths), no sub-resource loading"
            )

        if broad and features.referer_following_ratio < 0.1:
            confidence += 0.15
            evidence.append("accesses URLs cold (no on-site link-following)")

        if uas.is_library(features.user_agent):
            confidence += 0.2
            evidence.append("User-Agent is a generic HTTP library")
        elif features.ua_empty and broad:
            confidence += 0.15
            evidence.append("no User-Agent while harvesting many pages")

        if features.vuln_path_hits == 0 and features.ratio_2xx > 0.6 and confidence > 0:
            confidence += 0.05
            evidence.append("mostly successful, not probing")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
