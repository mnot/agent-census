"""Interactive browsers.

The strongest tell is sub-resource co-loading: a real browser, after fetching a
page, pulls its CSS/JS/images within seconds. Bursty (irregular) timing, on-site
link navigation, a browser-shaped UA, and a low error rate corroborate it.
"""

from __future__ import annotations

from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import identifies_as_known_agent


class BrowserClassifier(Classifier):
    label = Kind.BROWSER
    name = "browser"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        # A UA that names a feed reader, crawler, or bot is not a browser, even if
        # it renders pages and co-loads their sub-resources -- its declared
        # identity wins.
        if identifies_as_known_agent(features):
            return []

        confidence = 0.0
        evidence: list[str] = []

        if features.asset_coload_ratio > 0.4:
            confidence += 0.45
            evidence.append(
                f"{features.asset_coload_ratio:.0%} of pages followed by sub-resource loads"
            )

        if features.ua_looks_like_browser:
            confidence += 0.2
            evidence.append("User-Agent matches a real browser profile")

        regularity = features.rate_regularity
        if regularity is not None and regularity > 0.6:
            confidence += 0.1
            evidence.append("irregular, bursty timing (human-like)")
        elif regularity is not None and regularity < 0.15 and features.request_count >= 5:
            # Metronomic cadence is a machine, not a person clicking around.
            confidence -= 0.2
            evidence.append("metronomic timing — automated, not human")

        if features.referer_following_ratio > 0.3:
            confidence += 0.1
            evidence.append(
                f"{features.referer_following_ratio:.0%} of requests follow on-site links"
            )

        if features.ratio_404 < 0.1 and features.vuln_path_hits == 0:
            confidence += 0.1
            evidence.append("low error rate, no probing")

        if features.static_ratio > 0.3:
            confidence += 0.05
            evidence.append(f"{features.static_ratio:.0%} static-asset requests")

        if features.status_counts.get(304, 0) > 0:
            # Conditional requests answered 304 mean a real cache -- a browser tell.
            confidence += 0.1
            evidence.append("revalidates from cache (304 Not Modified)")

        # A person at a browser never fetches attack paths. Vuln probing or
        # directory traversal means this is automation wearing a browser engine
        # (e.g. headless Chrome), so cap the browser hypothesis below the unknown
        # threshold rather than let asset co-loading carry it to a confident
        # verdict. (Ignoring robots.txt is NOT penalised -- it does not bind a
        # human browsing by hand.)
        if features.traversal_hits > 0 or features.vuln_path_hits >= 2:
            confidence = min(confidence, 0.3)
            evidence.append("but probes attack paths — not human browsing")

        # Fabricated referers (the Referer is the requested URL itself) are
        # impossible from real navigation; a client doing this systematically is
        # faking organic traffic, not browsing.
        if features.self_referer_ratio >= 0.5 and features.request_count >= 4:
            confidence = min(confidence, 0.3)
            evidence.append("but referers are fabricated (Referer = the requested URL)")

        # A browser fetches pages and their sub-resources with GET; it does not
        # issue HEAD. Meaningful HEAD traffic from something otherwise browser-
        # shaped is a machine (a monitor, link-checker, or other bot) behind a
        # browser UA -- cap the hypothesis below the confident threshold. Gated on
        # an existing browser signal so monitors/feed readers that legitimately
        # HEAD don't each pick up a spurious browser signal.
        if evidence and features.head_ratio > 0.1:
            confidence = min(confidence, 0.3)
            evidence.append(f"but {features.head_ratio:.0%} HEAD requests — browsers issue GET")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
