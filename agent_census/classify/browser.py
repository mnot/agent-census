"""Interactive browsers.

The strongest tell is sub-resource co-loading: a real browser, after fetching a
page, pulls its CSS/JS/images within seconds. Bursty (irregular) timing, on-site
link navigation, a browser-shaped UA, and a low error rate corroborate it.
"""

from __future__ import annotations

from .. import uas
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import identifies_as_known_agent

# A browser-shaped UA with positive evidence but no disqualifying behaviour is
# floored to here, so a brief, asset-less visit (a real person who didn't trigger
# sub-resource loading) isn't lost to UNKNOWN. It matches the default unknown
# threshold; the combiner's datacenter discount then keeps the rescue to
# residential clients -- a hosting "browser" still drops to spoofed_browser.
_BROWSER_FLOOR = 0.45


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
        # Set when a signal positively argues *against* a browser (a cap or a
        # penalty). While clean, an under-supported browser shape is floored at the
        # end; once disqualified, it is left to fall where its confidence lands. A
        # stale (but not ancient) version is a mild nudge, not a disqualifier.
        disqualified = False

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
            disqualified = True
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

        # Chromium-based browsers and Firefox auto-update on a ~monthly cadence, so
        # a real browser is rarely far behind. A UA claiming a version years old
        # (measured against when the client was active) is almost always a frozen,
        # spoofed string; a current one weakly corroborates. Bots can copy a recent
        # UA, so the fresh bonus is small and the stale penalty is the load-bearing
        # half. Old but real cases exist (locked fleets, embedded WebViews, ESR),
        # so only a very old version caps the verdict.
        band = uas.version_age_band(features.user_agent, features.last_seen)
        if evidence and band == "current":
            confidence += 0.1
            evidence.append("up-to-date browser version")
        elif evidence and band == "stale":
            confidence -= 0.15
            evidence.append("browser version well out of date")
        elif evidence and band == "ancient":
            # Years behind on a family that auto-updates: almost always a frozen,
            # spoofed UA, so cap the browser hypothesis below the threshold.
            confidence = min(confidence, 0.3)
            disqualified = True
            evidence.append("browser version years out of date — modern browsers auto-update")
        elif evidence and band == "impossible":
            # Claims a version that doesn't exist yet: a forged UA, not a real
            # browser, so cap the hypothesis just like an ancient one.
            confidence = min(confidence, 0.3)
            disqualified = True
            evidence.append("browser version is impossibly new — forged User-Agent")

        # A browser never auto-fetches /robots.txt; checking it is a crawler's
        # habit. Slight on its own (a person could type the URL once), but it
        # nudges an otherwise browser-shaped client the right way.
        if evidence and features.fetched_robots_txt:
            confidence -= 0.15
            disqualified = True
            evidence.append("fetched /robots.txt — a crawler's habit, not a browser's")

        # A client that holds no browser cache (re-fetches the same URLs, or makes
        # a large number of requests, yet never earns a 304) is not browsing -- see
        # ClientFeatures.holds_no_cache.
        revisits = features.request_count - features.distinct_paths
        cold_refetch = revisits >= 20
        if evidence and features.holds_no_cache:
            dominant = (cold_refetch and revisits >= features.request_count * 0.5) or (
                features.request_count >= 2000
            )
            disqualified = True
            if dominant:
                # Re-fetching dominates, or the volume is large enough that zero
                # revalidations is itself damning: cap below the confident threshold.
                confidence = min(confidence, 0.3)
                evidence.append("heavy traffic without a single 304 — holds no browser cache")
            else:
                confidence -= 0.2
                evidence.append("many requests, never revalidated (no 304s)")

        # A person at a browser never fetches attack paths. Vuln probing or
        # directory traversal means this is automation wearing a browser engine
        # (e.g. headless Chrome), so cap the browser hypothesis below the unknown
        # threshold rather than let asset co-loading carry it to a confident
        # verdict. (Ignoring robots.txt is NOT penalised -- it does not bind a
        # human browsing by hand.)
        if features.traversal_hits > 0 or features.vuln_path_hits >= 2:
            confidence = min(confidence, 0.3)
            disqualified = True
            evidence.append("but probes attack paths — not human browsing")

        # Fabricated referers (the Referer is the requested URL itself) are
        # impossible from real navigation; a client doing this systematically is
        # faking organic traffic, not browsing.
        if features.self_referer_ratio >= 0.5 and features.request_count >= 4:
            confidence = min(confidence, 0.3)
            disqualified = True
            evidence.append("but referers are fabricated (Referer = the requested URL)")

        # A browser fetches pages and their sub-resources with GET; it does not
        # issue HEAD. Meaningful HEAD traffic from something otherwise browser-
        # shaped is a machine (a monitor, link-checker, or other bot) behind a
        # browser UA -- cap the hypothesis below the confident threshold. Gated on
        # an existing browser signal so monitors/feed readers that legitimately
        # HEAD don't each pick up a spurious browser signal.
        if evidence and features.head_ratio > 0.1:
            confidence = min(confidence, 0.3)
            disqualified = True
            evidence.append(f"but {features.head_ratio:.0%} HEAD requests — browsers issue GET")

        if not evidence:
            return []
        # A browser-shaped UA with positive evidence and nothing arguing against it
        # is a probable browser even without the asset-loading proof -- a brief
        # visit. Floor it so it clears the unknown threshold rather than being lost;
        # ancient/forged UAs and any non-browser behaviour disqualify it above.
        if features.ua_looks_like_browser and not disqualified and confidence < _BROWSER_FLOOR:
            confidence = _BROWSER_FLOOR
            evidence.append("browser-shaped User-Agent with no non-browser behaviour")
        return [self._signal(confidence, evidence)]
