"""Generic crawlers that walk the site following links at a steady pace.

Distinguished from a browser by the absence of sub-resource co-loading, and from
a scraper by actually following on-site links (high referer-following) rather
than hitting URLs cold.
"""

from __future__ import annotations

from ..model import ClientFeatures, Kind, Signal
from .base import Classifier


class CrawlerClassifier(Classifier):
    label = Kind.CRAWLER
    name = "crawler"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        if features.distinct_paths >= 20 and features.coverage > 0.7:
            confidence += 0.3
            evidence.append(
                f"broad coverage: {features.distinct_paths} distinct paths "
                f"({features.coverage:.0%} unique)"
            )

        regularity = features.rate_regularity
        if regularity is not None and regularity < 0.5 and features.request_count >= 10:
            confidence += 0.2
            evidence.append("steady, regular request cadence")

        if features.referer_following_ratio > 0.3:
            confidence += 0.15
            evidence.append(
                f"{features.referer_following_ratio:.0%} of requests follow on-site links"
            )

        if features.ua_declares_bot:
            confidence += 0.15
            evidence.append("User-Agent self-identifies as a bot")

        if features.ratio_2xx > 0.7 and features.asset_coload_ratio < 0.1:
            confidence += 0.1
            evidence.append("mostly successful page fetches, no browser sub-resource loading")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
