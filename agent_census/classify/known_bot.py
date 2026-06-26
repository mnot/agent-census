"""Shared logic for classifiers driven by a known-UA-token data list.

Good bots and AI crawlers are recognized the same way — a token in the UA — and
differ only in which list and label they use, so the matching lives here. The
claim is taken at face value (high confidence); the combiner downgrades it to
``impersonator`` when DNS verification or behavior contradicts the UA.
"""

from __future__ import annotations

from .. import uas
from ..model import ClientFeatures, Signal
from .base import Classifier


class KnownBotClassifier(Classifier):
    """Fires when the UA contains a token from the :attr:`category` data list."""

    category: str = ""
    descriptor: str = ""

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        known = uas.match_category(features.user_agent, self.category)
        if known is None:
            return self._by_asn(features)
        token, _spec = known
        confidence = 0.7
        evidence = [f"User-Agent declares {token!r}, a known {self.descriptor}"]
        if features.fetched_robots_txt:
            confidence += 0.08
            evidence.append("fetched /robots.txt")
        no_probing = (
            features.vuln_path_hits == 0
            and features.traversal_hits == 0
            and features.evasion_hits == 0
        )
        if no_probing:
            confidence += 0.05
            evidence.append("no vulnerability probing observed")
        return [self._signal(confidence, evidence)]

    def _by_asn(self, features: ClientFeatures) -> list[Signal]:
        """Recognise an agent by its origin AS number when the UA doesn't name it.

        Some operators crawl behind rotating, spoofed browser User-Agents; the
        constant is the network they come from, which a configured ASN names.
        """
        label = uas.match_asn(features.as_number, self.category)
        if label is None:
            return []
        asn = uas.parse_asn(features.as_number)
        return [
            self._signal(
                0.6, [f"origin AS{asn} is {label}, a recognised {self.descriptor} network"]
            )
        ]
