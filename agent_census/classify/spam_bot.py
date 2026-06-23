"""Comment / form spam and credential-stuffing bots.

The tell is a POST-heavy request mix aimed at a small set of submission endpoints
(comment forms, login, xmlrpc), usually without any browser sub-resource loading.
"""

from __future__ import annotations

import re

from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

_SUBMIT_PATH = re.compile(
    r"wp-comments-post|comment|xmlrpc|wp-login|/login|signin|register|contact|sendmail",
    re.I,
)


class SpamBotClassifier(Classifier):
    label = Kind.SPAM_BOT
    name = "spam_bot"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        posts = features.method_counts.get("POST", 0)
        if features.post_ratio > 0.3 and posts >= 3:
            confidence += 0.4
            evidence.append(f"{features.post_ratio:.0%} POST requests ({posts} total)")

        if features.post_ratio > 0.3 and features.asset_coload_ratio < 0.1:
            confidence += 0.15
            evidence.append("submits forms with no browser sub-resource loading")

        submit_hits = any(_SUBMIT_PATH.search(p) for p in features.sample_vuln_paths)
        if submit_hits:
            confidence += 0.15
            evidence.append("targets comment/login submission endpoints")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
