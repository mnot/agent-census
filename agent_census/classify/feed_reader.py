"""RSS / Atom feed pollers.

Recognized primarily from behaviour: requesting feed resources -- a URL whose
filename contains ``feed``/``rss``/``atom``, or a response with an RSS/Atom media
type (when the log captures it). A feed-reader User-Agent and steady polling of a
small number of URLs corroborate it.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..dataload import load_list, load_tuning, load_ua_signatures
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

# Numeric knobs live in data/tuning/feed_reader.toml.
_TUNING_SCHEMA = {
    "dominant_ratio_min": "feed_traffic.dominant_ratio_min",
    "dominant_weight": "feed_traffic.dominant_weight",
    "present_weight": "feed_traffic.present_weight",
    "feed_ua_weight": "feed_ua.weight",
    "few_urls_distinct_max": "few_urls.distinct_paths_max",
    "few_urls_min_requests": "few_urls.min_requests",
    "few_urls_weight": "few_urls.weight",
    "steady_regularity_max": "steady_polling.regularity_max",
    "steady_min_requests": "steady_polling.min_requests",
    "steady_weight": "steady_polling.weight",
    "conditional_weight": "conditional.weight",
    "head_ratio_min": "head_checks.head_ratio_min",
    "head_weight": "head_checks.weight",
}
_T = load_tuning("feed_reader", _TUNING_SCHEMA)

# Generic feed terms plus the specific reader product names from feed_readers.toml,
# folded into one compiled alternation. A single C-level search beats scanning the
# product list per call -- which matters on high-cardinality logs where the cache
# below thrashes and most calls miss (this was the hottest spot in profiling).
# The generic terms are short, so they're anchored to word boundaries to avoid
# matching inside unrelated words ("atom" in "Anatomy"/"atomic", "rss" in a
# random token); the product names stay plain substrings. Both lists are data:
# the terms in data/ua_signatures.toml, the product names in data/feed_readers.toml.
_FEED_TERMS = load_ua_signatures().feed_terms
_FEED_UA = re.compile(
    "|".join(
        [
            r"\b(?:" + "|".join(re.escape(term) for term in _FEED_TERMS) + r")\b",
            *(re.escape(name) for name in load_list("feed_readers")),
        ]
    ),
    re.I,
)


@lru_cache(maxsize=16384)
def ua_is_feed_reader(ua: str | None) -> bool:
    """True if the UA names a feed reader or generic feed tool (rss/atom/…).

    Shared with the tag layer so a feed reader is recognised identically there --
    keeping it out of the browser / spoofed-browser heuristics and the ``bot-ua``
    tag, however it behaves in a given window.
    """
    if not ua:
        return False
    return bool(_FEED_UA.search(ua))


class FeedReaderClassifier(Classifier):
    label = Kind.FEED_READER
    name = "feed_reader"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        feed_ua = ua_is_feed_reader(features.user_agent)
        feed_dominant = (
            features.feed_requests > 0 and features.feed_ratio >= _T["dominant_ratio_min"]
        )
        # Feeds have to be the point: either a declared reader, or feeds are the
        # majority of traffic. A client that mostly hammers non-feed pages and only
        # grazes a feed is not a feed reader -- its other behaviour decides the kind.
        if not (feed_ua or feed_dominant):
            return []

        confidence = 0.0
        evidence: list[str] = []

        if feed_dominant:
            confidence += _T["dominant_weight"]
            evidence.append(f"{features.feed_ratio:.0%} of requests are for feed resources")
        elif features.feed_requests > 0:
            confidence += _T["present_weight"]
            evidence.append(f"{features.feed_requests} request(s) for feed resources")

        if feed_ua:
            confidence += _T["feed_ua_weight"]
            evidence.append("User-Agent identifies a feed reader")

        if (
            features.distinct_paths <= _T["few_urls_distinct_max"]
            and features.request_count >= _T["few_urls_min_requests"]
        ):
            confidence += _T["few_urls_weight"]
            evidence.append(f"polls {features.distinct_paths} URL(s) repeatedly")

        regularity = features.rate_regularity
        if (
            regularity is not None
            and regularity < _T["steady_regularity_max"]
            and features.request_count >= _T["steady_min_requests"]
        ):
            confidence += _T["steady_weight"]
            evidence.append("steady polling interval")

        if features.status_counts.get(304, 0) > 0:
            # A polite reader sends conditional requests and gets 304s when the feed
            # is unchanged -- caching, the hallmark of a well-behaved poller.
            confidence += _T["conditional_weight"]
            evidence.append("conditional polling (304 Not Modified)")

        if features.head_ratio > _T["head_ratio_min"]:
            # Some readers HEAD a feed to check for a change before fetching it --
            # weak corroboration of a machine poller, unlike a browser, which never
            # issues HEAD.
            confidence += _T["head_weight"]
            evidence.append(f"{features.head_ratio:.0%} HEAD requests (freshness checks)")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
