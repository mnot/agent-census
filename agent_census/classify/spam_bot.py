"""Comment / form spam and credential-stuffing bots.

The tell is a POST-heavy request mix aimed at a small set of submission endpoints
(comment forms, login, xmlrpc), usually without any browser sub-resource loading.
"""

from __future__ import annotations

import re

from ..dataload import load_list, load_shared_tuning, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

# Submission-endpoint substrings live in data/submit_paths.toml; numeric knobs in
# data/tuning/spam_bot.toml, the no-co-load cutoff in data/tuning/shared.toml.
_SUBMIT_PATH = re.compile("|".join(re.escape(p) for p in load_list("submit_paths")), re.I)
_TUNING_SCHEMA = {
    "post_ratio_min": "post_volume.post_ratio_min",
    "post_min_posts": "post_volume.min_posts",
    "post_volume_weight": "post_volume.weight",
    "post_no_assets_weight": "post_no_assets.weight",
    "submit_weight": "submission_endpoint.weight",
}
_T = load_tuning("spam_bot", _TUNING_SCHEMA)
_S = load_shared_tuning()


class SpamBotClassifier(Classifier):
    label = Kind.SPAM_BOT
    name = "spam_bot"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        posts = features.method_counts.get("POST", 0)
        if features.post_ratio > _T["post_ratio_min"] and posts >= _T["post_min_posts"]:
            confidence += _T["post_volume_weight"]
            evidence.append(f"{features.post_ratio:.0%} POST requests ({posts} total)")

        if (
            features.post_ratio > _T["post_ratio_min"]
            and features.asset_coload_ratio < _S["browser_no_coload_max"]
        ):
            confidence += _T["post_no_assets_weight"]
            evidence.append("submits forms with no browser sub-resource loading")

        submit_hits = any(_SUBMIT_PATH.search(p) for p in features.sample_vuln_paths)
        if submit_hits:
            confidence += _T["submit_weight"]
            evidence.append("targets comment/login submission endpoints")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
