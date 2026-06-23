"""Shared logic for classifiers driven by a known-UA-token data list.

Good bots and AI crawlers are recognized the same way — a token in the UA — and
differ only in which list and label they use, so the matching lives here. The
claim is taken at face value (high confidence); the combiner downgrades it to
``impersonator`` when DNS verification or behavior contradicts the UA.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_tokens
from ..model import ClientFeatures, Signal
from .base import Classifier


class KnownBotClassifier(Classifier):
    """Fires when the UA contains a token from the :attr:`category` data list."""

    category: str = ""
    descriptor: str = ""

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        known = uas.match_known(features.user_agent, load_tokens(self.category))
        if known is None:
            return []
        token, _spec = known
        confidence = 0.7
        evidence = [f"User-Agent declares {token!r}, a known {self.descriptor}"]
        if features.fetched_robots_txt:
            confidence += 0.08
            evidence.append("fetched /robots.txt")
        if features.vuln_path_hits == 0 and features.traversal_hits == 0:
            confidence += 0.05
            evidence.append("no vulnerability probing observed")
        return [self._signal(confidence, evidence)]
