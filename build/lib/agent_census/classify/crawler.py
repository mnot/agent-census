"""Generic crawlers that walk the site following links at a steady pace.

Distinguished from a browser by the absence of sub-resource co-loading, and from
a scraper by actually following on-site links (high referer-following) rather
than hitting URLs cold.
"""

from __future__ import annotations

from ..dataload import load_shared_tuning, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import recognised_specific_agent

# Numeric knobs: this classifier's own in data/tuning/crawler.toml, the co-load and
# link-following cutoffs in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "broad_distinct_min": "broad_coverage.distinct_paths_min",
    "broad_coverage_min": "broad_coverage.coverage_min",
    "broad_weight": "broad_coverage.weight",
    "steady_regularity_max": "steady_cadence.regularity_max",
    "steady_min_requests": "steady_cadence.min_requests",
    "steady_weight": "steady_cadence.weight",
    "follows_weight": "follows_links.weight",
    "declared_weight": "declared_bot.weight",
    "declared_min_requests": "declared_bot.min_requests",
    "declared_broad_distinct_min": "declared_bot.broad_distinct_paths_min",
    "declared_broad_weight": "declared_bot.broad_weight",
    "declared_modest_weight": "declared_bot.modest_weight",
    "success_ratio_2xx_min": "successful_pages.ratio_2xx_min",
    "success_weight": "successful_pages.weight",
}
_T = load_tuning("crawler", _TUNING_SCHEMA)
_S = load_shared_tuning()


class CrawlerClassifier(Classifier):
    label = Kind.CRAWLER
    name = "crawler"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        # A client recognised as a specific agent -- a known crawler (by UA token or
        # origin AS) or a feed reader -- belongs to that classifier; the generic
        # crawler must not compete (its behavioural score could otherwise outrank the
        # recognition). It still claims an *un*recognised self-declared bot.
        if recognised_specific_agent(features):
            return []
        confidence = 0.0
        evidence: list[str] = []

        if (
            features.distinct_paths >= _T["broad_distinct_min"]
            and features.coverage > _T["broad_coverage_min"]
        ):
            confidence += _T["broad_weight"]
            evidence.append(
                f"broad coverage: {features.distinct_paths} distinct paths "
                f"({features.coverage:.0%} unique)"
            )

        regularity = features.rate_regularity
        if (
            regularity is not None
            and regularity < _T["steady_regularity_max"]
            and features.request_count >= _T["steady_min_requests"]
        ):
            confidence += _T["steady_weight"]
            evidence.append("steady, regular request cadence")

        if features.referer_following_ratio > _S["browser_follow_min"]:
            confidence += _T["follows_weight"]
            evidence.append(
                f"{features.referer_following_ratio:.0%} of requests follow on-site links"
            )

        if features.ua_declares_bot:
            confidence += _T["declared_weight"]
            evidence.append("User-Agent self-identifies as a bot")
            # A self-declared bot fetching pages with no browser sub-resource loading
            # is a crawler whether it walks a broad path set or re-requests a few --
            # the "MyBot/1.0 (+url)" client. Broad coverage earns more; a modest path
            # set still clears the unknown floor rather than dangling there.
            if (
                features.asset_coload_ratio < _S["browser_no_coload_max"]
                and features.request_count >= _T["declared_min_requests"]
            ):
                broad = features.distinct_paths >= _T["declared_broad_distinct_min"]
                confidence += _T["declared_broad_weight"] if broad else _T["declared_modest_weight"]
                evidence.append(
                    "walks many pages without browser sub-resource loading"
                    if broad
                    else "self-identified bot fetching pages, no browser sub-resource loading"
                )

        if (
            features.ratio_2xx > _T["success_ratio_2xx_min"]
            and features.asset_coload_ratio < _S["browser_no_coload_max"]
        ):
            confidence += _T["success_weight"]
            evidence.append("mostly successful page fetches, no browser sub-resource loading")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
