"""RSS / Atom feed pollers.

Recognized mainly from the User-Agent (feed clients are well-behaved about
identifying themselves), corroborated by repeated polling of a small number of
URLs at a steady interval.
"""

from __future__ import annotations

import re

from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

_FEED_UA = re.compile(
    r"feed|rss|atom|podcast|feedly|newsblur|inoreader|theoldreader|"
    r"universalfeedparser|tiny tiny rss|miniflux|feedbin|subscriber",
    re.I,
)


class FeedReaderClassifier(Classifier):
    label = Kind.FEED_READER
    name = "feed_reader"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        if features.user_agent and _FEED_UA.search(features.user_agent):
            confidence += 0.5
            evidence.append("User-Agent identifies a feed reader")

        if features.distinct_paths <= 3 and features.request_count >= 4:
            confidence += 0.15
            evidence.append(f"polls {features.distinct_paths} URL(s) repeatedly")

        regularity = features.rate_regularity
        if regularity is not None and regularity < 0.3 and features.request_count >= 4:
            confidence += 0.1
            evidence.append("steady polling interval")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
