"""RSS / Atom feed pollers.

Recognized primarily from behaviour: requesting feed resources -- a URL whose
filename contains ``feed``/``rss``/``atom``, or a response with an RSS/Atom media
type (when the log captures it). A feed-reader User-Agent and steady polling of a
small number of URLs corroborate it.
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

        if features.feed_requests > 0:
            if features.feed_ratio >= 0.5:
                confidence += 0.5
                evidence.append(f"{features.feed_ratio:.0%} of requests are for feed resources")
            else:
                confidence += 0.3
                evidence.append(f"{features.feed_requests} request(s) for feed resources")

        if features.user_agent and _FEED_UA.search(features.user_agent):
            confidence += 0.4
            evidence.append("User-Agent identifies a feed reader")

        if features.distinct_paths <= 3 and features.request_count >= 4:
            confidence += 0.1
            evidence.append(f"polls {features.distinct_paths} URL(s) repeatedly")

        regularity = features.rate_regularity
        if regularity is not None and regularity < 0.3 and features.request_count >= 4:
            confidence += 0.1
            evidence.append("steady polling interval")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
