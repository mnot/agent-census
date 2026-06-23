"""RSS / Atom feed pollers.

Recognized primarily from behaviour: requesting feed resources -- a URL whose
filename contains ``feed``/``rss``/``atom``, or a response with an RSS/Atom media
type (when the log captures it). A feed-reader User-Agent and steady polling of a
small number of URLs corroborate it.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..dataload import load_list
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

# Generic feed terms plus the specific reader product names from feed_readers.txt,
# folded into one compiled alternation. A single C-level search beats scanning the
# product list per call -- which matters on high-cardinality logs where the cache
# below thrashes and most calls miss (this was the hottest spot in profiling).
_FEED_TERMS = ("feed", "rss", "atom", "podcast", "subscriber")
_FEED_UA = re.compile(
    "|".join(re.escape(term) for term in (*_FEED_TERMS, *load_list("feed_readers"))), re.I
)


@lru_cache(maxsize=16384)
def _ua_is_feed_reader(ua: str | None) -> bool:
    if not ua:
        return False
    return bool(_FEED_UA.search(ua))


class FeedReaderClassifier(Classifier):
    label = Kind.FEED_READER
    name = "feed_reader"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        feed_ua = _ua_is_feed_reader(features.user_agent)
        feed_dominant = features.feed_requests > 0 and features.feed_ratio >= 0.5
        # Feeds have to be the point: either a declared reader, or feeds are the
        # majority of traffic. A client that mostly hammers non-feed pages and only
        # grazes a feed is not a feed reader -- its other behaviour decides the kind.
        if not (feed_ua or feed_dominant):
            return []

        confidence = 0.0
        evidence: list[str] = []

        if feed_dominant:
            confidence += 0.5
            evidence.append(f"{features.feed_ratio:.0%} of requests are for feed resources")
        elif features.feed_requests > 0:
            confidence += 0.2
            evidence.append(f"{features.feed_requests} request(s) for feed resources")

        if feed_ua:
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
