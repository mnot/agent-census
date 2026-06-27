"""Interactive browsers.

The strongest tell is sub-resource co-loading: a real browser, after fetching a
page, pulls its CSS/JS/images within seconds. Bursty (irregular) timing, on-site
link navigation, a browser-shaped UA, and a low error rate corroborate it.
"""

from __future__ import annotations

from .. import uas
from ..dataload import load_shared_tuning, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import identifies_as_known_agent

# Numeric knobs live in data/tuning/browser.toml (this classifier's own) and
# data/tuning/shared.toml (thresholds shared with the tags and other classifiers).
# Both are tunable there without touching this logic.
_TUNING_SCHEMA = {
    "disqualified_ceiling": "disqualified_ceiling",
    "min_requests_for_timing": "min_requests_for_timing",
    "asset_coload_weight": "asset_coload.weight",
    "ua_browser_shape_weight": "ua_browser_shape.weight",
    "bursty_weight": "bursty_timing.weight",
    "follows_links_weight": "follows_links.weight",
    "low_error_404_max": "low_error_no_probing.ratio_404_max",
    "low_error_weight": "low_error_no_probing.weight",
    "static_ratio_min": "static_assets.static_ratio_min",
    "static_weight": "static_assets.weight",
    "revalidates_weight": "revalidates_cache.weight",
    "version_current_weight": "version_current.weight",
    "metronomic_penalty": "metronomic_timing.weight",
    "version_stale_penalty": "version_stale.weight",
    "fetched_robots_penalty": "fetched_robots.weight",
    "no_cache_soft_penalty": "no_cache.soft_penalty",
    "cold_refetch_min": "no_cache.cold_refetch_min",
    "dominant_fraction": "no_cache.dominant_fraction",
    "high_volume": "no_cache.high_volume",
    "vuln_hits_cap": "probing.vuln_hits_cap",
}
_T = load_tuning("browser", _TUNING_SCHEMA)
_S = load_shared_tuning()


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

        if features.asset_coload_ratio > _S["browser_coload_min"]:
            confidence += _T["asset_coload_weight"]
            evidence.append(
                f"{features.asset_coload_ratio:.0%} of pages followed by sub-resource loads"
            )

        if features.ua_looks_like_browser:
            confidence += _T["ua_browser_shape_weight"]
            evidence.append("User-Agent matches a real browser profile")

        regularity = features.rate_regularity
        if regularity is not None and regularity > _S["cadence_bursty_min"]:
            confidence += _T["bursty_weight"]
            evidence.append("irregular, bursty timing (human-like)")
        elif (
            regularity is not None
            and regularity < _S["cadence_metronomic_max"]
            and features.request_count >= _T["min_requests_for_timing"]
        ):
            # Metronomic cadence is a machine, not a person clicking around.
            confidence -= _T["metronomic_penalty"]
            disqualified = True
            evidence.append("metronomic timing — automated, not human")

        if features.referer_following_ratio > _S["browser_follow_min"]:
            confidence += _T["follows_links_weight"]
            evidence.append(
                f"{features.referer_following_ratio:.0%} of requests follow on-site links"
            )

        if features.ratio_404 < _T["low_error_404_max"] and features.vuln_path_hits == 0:
            confidence += _T["low_error_weight"]
            evidence.append("low error rate, no probing")

        if features.static_ratio > _T["static_ratio_min"]:
            confidence += _T["static_weight"]
            evidence.append(f"{features.static_ratio:.0%} static-asset requests")

        if features.status_counts.get(304, 0) > 0:
            # Conditional requests answered 304 mean a real cache -- a browser tell.
            confidence += _T["revalidates_weight"]
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
            confidence += _T["version_current_weight"]
            evidence.append("up-to-date browser version")
        elif evidence and band == "stale":
            confidence -= _T["version_stale_penalty"]
            evidence.append("browser version well out of date")
        elif evidence and band == "ancient":
            # Years behind on a family that auto-updates: almost always a frozen,
            # spoofed UA, so cap the browser hypothesis below the threshold.
            confidence = min(confidence, _T["disqualified_ceiling"])
            disqualified = True
            evidence.append("browser version years out of date — modern browsers auto-update")
        elif evidence and band == "impossible":
            # Claims a version that doesn't exist yet: a forged UA, not a real
            # browser, so cap the hypothesis just like an ancient one.
            confidence = min(confidence, _T["disqualified_ceiling"])
            disqualified = True
            evidence.append("browser version is impossibly new — forged User-Agent")

        # A browser never auto-fetches /robots.txt; checking it is a crawler's
        # habit. Slight on its own (a person could type the URL once), but it
        # nudges an otherwise browser-shaped client the right way.
        if evidence and features.fetched_robots_txt:
            confidence -= _T["fetched_robots_penalty"]
            disqualified = True
            evidence.append("fetched /robots.txt — a crawler's habit, not a browser's")

        # A client that holds no browser cache (re-fetches the same URLs, or makes
        # a large number of requests, yet never earns a 304) is not browsing -- see
        # ClientFeatures.holds_no_cache.
        revisits = features.request_count - features.distinct_paths
        cold_refetch = revisits >= _T["cold_refetch_min"]
        if evidence and features.holds_no_cache:
            dominant = (
                cold_refetch and revisits >= features.request_count * _T["dominant_fraction"]
            ) or (features.request_count >= _T["high_volume"])
            disqualified = True
            if dominant:
                # Re-fetching dominates, or the volume is large enough that zero
                # revalidations is itself damning: cap below the confident threshold.
                confidence = min(confidence, _T["disqualified_ceiling"])
                evidence.append("heavy traffic without a single 304 — holds no browser cache")
            else:
                confidence -= _T["no_cache_soft_penalty"]
                evidence.append("many requests, never revalidated (no 304s)")

        # A person at a browser never fetches attack paths. Vuln probing or
        # directory traversal means this is automation wearing a browser engine
        # (e.g. headless Chrome), so cap the browser hypothesis below the unknown
        # threshold rather than let asset co-loading carry it to a confident
        # verdict. (Ignoring robots.txt is NOT penalised -- it does not bind a
        # human browsing by hand.)
        if (
            features.traversal_hits > 0
            or features.evasion_hits > 0
            or features.vuln_path_hits >= _T["vuln_hits_cap"]
        ):
            confidence = min(confidence, _T["disqualified_ceiling"])
            disqualified = True
            evidence.append("but probes attack paths — not human browsing")

        # Fabricated referers (the Referer is the requested URL itself) are
        # impossible from real navigation; a client doing this systematically is
        # faking organic traffic, not browsing.
        if (
            features.self_referer_ratio >= _S["fabricated_self_referer_min"]
            and features.request_count >= _S["fabricated_min_requests"]
        ):
            confidence = min(confidence, _T["disqualified_ceiling"])
            disqualified = True
            evidence.append("but referers are fabricated (Referer = the requested URL)")

        # A browser fetches pages and their sub-resources with GET; it does not
        # issue HEAD. Meaningful HEAD traffic from something otherwise browser-
        # shaped is a machine (a monitor, link-checker, or other bot) behind a
        # browser UA -- cap the hypothesis below the confident threshold. Gated on
        # an existing browser signal so monitors/feed readers that legitimately
        # HEAD don't each pick up a spurious browser signal.
        if evidence and features.head_ratio > _S["head_notable_ratio"]:
            confidence = min(confidence, _T["disqualified_ceiling"])
            disqualified = True
            evidence.append(f"but {features.head_ratio:.0%} HEAD requests — browsers issue GET")

        if not evidence:
            return []
        # A browser-shaped UA with positive evidence and nothing arguing against it
        # is a probable browser even without the asset-loading proof -- a brief
        # visit. Floor it to the unknown threshold so it clears the bar rather than
        # being lost; ancient/forged UAs and any non-browser behaviour disqualify it
        # above. The combiner's datacenter discount keeps this rescue to residential
        # clients -- a hosting "browser" still drops to spoofed_browser.
        floor = _S["unknown_threshold"]
        if features.ua_looks_like_browser and not disqualified and confidence < floor:
            confidence = floor
            evidence.append("browser-shaped User-Agent with no non-browser behaviour")
        return [self._signal(confidence, evidence)]
