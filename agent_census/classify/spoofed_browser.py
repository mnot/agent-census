"""Browser costumes: a browser-shaped User-Agent that does not behave like a browser.

A real browser renders pages (co-loading their sub-resources), follows links via the
Referer, and keeps a cache (revalidating with 304s). A client claiming to be a browser
that shows none of that -- and often carries a positive spoof tell besides (a Referer no
browser could emit, HEAD-heavy traffic, fabricated referers) -- is presenting a costume.

Unlike the other classifiers this one reads combiner-level *context* (the origin network
type and the site's redirect regime) as well as the feature vector, so it overrides
:meth:`~Classifier.evaluate_in_context` rather than the pure :meth:`evaluate`. It
accumulates the spoof tells into a score; a strong enough combination -- on ANY origin --
makes the client a spoofed_browser, with the datacenter origin only one weighted tell
among many. This is the accumulation model issue #100 calls for, replacing the old single
hard-AND costume gate that only fired from a datacenter IP.

Weights and the firing threshold live in data/tuning/spoofed_browser.toml (calibrated on
a live digest); the shared browser-shape / fabricated-referer / HEAD lines it reads are in
data/tuning/shared.toml.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_shared_tuning, load_tuning
from ..model import ClassifyContext, ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import identifies_as_known_agent, looks_like_impossible_referer

_TUNING_SCHEMA = {
    "threshold": "score.threshold",
    "confidence_cap": "score.confidence_cap",
    "min_requests": "gate.min_requests",
    "w_impossible_referer": "weights.impossible_referer",
    "w_datacenter": "weights.datacenter",
    "w_no_cache": "weights.holds_no_cache",
    "w_head_heavy": "weights.head_heavy",
    "w_forged_referer": "weights.forged_referer",
    "w_no_coload": "weights.no_coload",
    "w_no_follow": "weights.no_follow",
    "w_ua_age": "weights.ua_age",
}
_T = load_tuning("spoofed_browser", _TUNING_SCHEMA)
_S = load_shared_tuning()


class SpoofedBrowserClassifier(Classifier):
    label = Kind.SPOOFED_BROWSER
    name = "spoofed_browser"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        # The pure-feature entry point: score the tells computable from features alone
        # (no origin, no redirect regime), i.e. under an empty context. Keeps the
        # classifier independently testable; the combiner runs evaluate_in_context.
        return self._evaluate(features, ClassifyContext())

    def evaluate_in_context(
        self, features: ClientFeatures, context: ClassifyContext
    ) -> list[Signal]:
        return self._evaluate(features, context)

    def _evaluate(self, features: ClientFeatures, context: ClassifyContext) -> list[Signal]:
        # Base gate: only a browser-claiming client can be a *spoofed* browser. A client
        # that identifies itself (feed reader / crawler / bot) is that thing, not a
        # costume; a feed-fetching client is a feed reader even behind a browser UA (the
        # digest is full of browser-UA feed readers), so exclude any feed activity.
        if (
            not features.ua_looks_like_browser
            or identifies_as_known_agent(features)
            or features.feed_requests != 0
            or features.request_count < _T["min_requests"]
        ):
            return []

        score = 0.0
        evidence: list[str] = []

        def tell(weight: float, why: str) -> None:
            nonlocal score
            score += weight
            evidence.append(why)

        # Active-deception and origin tells: these count regardless of how browser-shaped
        # the rest of the traffic looks. A client replaying an impossible Referer, faking
        # referers, or hammering HEAD is deceiving even if it also renders pages -- a
        # URL-replayer co-loads assets too -- so genuine co-loading must not excuse them.

        # Dispositive on its own: a same-site Referer naming the site's redirect-only
        # host form, impossible from a compliant browser (issue #101).
        if looks_like_impossible_referer(features, context.redirect_shadow):
            tell(
                _T["w_impossible_referer"],
                "carries a same-site Referer no real browser could emit after the site's "
                "www/apex redirect",
            )
        # Origin is corroboration now, not a gate: a person rarely browses from hosting.
        if context.datacenter:
            why = "origin is datacenter / hosting infrastructure"
            if features.as_org:
                why += f" ({features.as_org})"
            tell(_T["w_datacenter"], why)
        if features.head_ratio > _S["head_notable_ratio"]:
            tell(
                _T["w_head_heavy"], f"{features.head_ratio:.0%} HEAD requests — browsers issue GET"
            )
        if (
            features.self_referer_ratio >= _S["fabricated_self_referer_min"]
            and features.request_count >= _S["fabricated_min_requests"]
        ):
            tell(
                _T["w_forged_referer"],
                f"Referer equals the requested URL on {features.self_referer_ratio:.0%} of "
                "requests — fabricated navigation",
            )

        # Cold / costume tells: absence-of-browserness. A client that genuinely co-loads a
        # page's sub-resources IS rendering like a browser, so these do not count for it --
        # the design's "a real browser signal lowers the score" guard, which keeps a
        # cache-disabled or privacy human who still loads assets out of the net. The active
        # tells above are untouched, so a co-loading URL-replayer is still caught by its
        # impossible / forged Referer.
        if features.asset_coload_ratio <= _S["browser_coload_min"]:
            if features.page_count > 0 and features.asset_coload_ratio == 0.0:
                tell(
                    _T["w_no_coload"],
                    f"fetched {features.page_count:,} page(s) but co-loaded none of their "
                    "sub-resources",
                )
            if features.referer_following_ratio == 0.0:
                tell(_T["w_no_follow"], "followed no on-site links")
            if features.holds_no_cache:
                tell(
                    _T["w_no_cache"],
                    f"{features.request_count:,} requests, never a 304 — holds no browser cache",
                )
            if uas.version_age_band(features.user_agent, features.last_seen) in (
                "ancient",
                "impossible",
            ):
                tell(
                    _T["w_ua_age"],
                    "browser User-Agent version is frozen far from its active period",
                )

        if round(score, 3) < _T["threshold"]:
            return []
        return [self._signal(min(score, _T["confidence_cap"]), evidence)]
