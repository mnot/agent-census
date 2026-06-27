"""Content scrapers: broad harvesting of pages without following links.

Like a crawler in volume and coverage, but hits URLs cold (little to no on-site
link-following) and often rides a generic HTTP-library or empty User-Agent.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_shared_tuning, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import recognised_specific_agent

# Numeric knobs: this classifier's own in data/tuning/scraper.toml, the co-load and
# link-following cutoffs in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "broad_distinct_min": "broad.distinct_paths_min",
    "broad_min_requests": "broad.min_requests",
    "harvest_weight": "harvest.weight",
    "cold_weight": "cold.weight",
    "library_weight": "library.weight",
    "no_ua_weight": "no_user_agent.weight",
    "benign_ratio_2xx_min": "benign.ratio_2xx_min",
    "benign_weight": "benign.weight",
}
_T = load_tuning("scraper", _TUNING_SCHEMA)
_S = load_shared_tuning()


class ScraperClassifier(Classifier):
    label = Kind.SCRAPER
    name = "scraper"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        # A recognised specific agent (known crawler by UA/AS, or a feed reader) is
        # owned by its own classifier; the generic scraper defers to it.
        if recognised_specific_agent(features):
            return []
        confidence = 0.0
        evidence: list[str] = []

        broad = (
            features.distinct_paths >= _T["broad_distinct_min"]
            and features.request_count >= _T["broad_min_requests"]
        )
        if (
            broad
            and features.asset_coload_ratio < _S["browser_no_coload_max"]
            and not features.ua_looks_like_browser
        ):
            confidence += _T["harvest_weight"]
            evidence.append(
                f"harvests many pages ({features.distinct_paths} paths), no sub-resource loading"
            )

        if broad and features.referer_following_ratio < _S["browser_no_follow_max"]:
            confidence += _T["cold_weight"]
            evidence.append("accesses URLs cold (no on-site link-following)")

        if uas.is_library(features.user_agent):
            confidence += _T["library_weight"]
            evidence.append("User-Agent is a generic HTTP library")
        elif features.ua_empty and broad:
            confidence += _T["no_ua_weight"]
            evidence.append("no User-Agent while harvesting many pages")

        if (
            features.vuln_path_hits == 0
            and features.ratio_2xx > _T["benign_ratio_2xx_min"]
            and confidence > 0
        ):
            confidence += _T["benign_weight"]
            evidence.append("mostly successful, not probing")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
