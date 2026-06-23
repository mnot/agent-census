"""Vulnerability / misconfiguration scanners.

The signature: lots of requests to known probe paths, a high 404 rate spread
across many distinct missing paths (probing, not a broken link), fast cadence,
traversal/injection markers, and no browser-like sub-resource loading.
"""

from __future__ import annotations

from ..dataload import load_list
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier

_SCANNER_UA = tuple(token.lower() for token in load_list("scanner_ua"))


def _ua_is_scanner(ua: str | None) -> str | None:
    if not ua:
        return None
    low = ua.lower()
    return next((token for token in _SCANNER_UA if token in low), None)


class VulnScannerClassifier(Classifier):
    label = Kind.VULN_SCANNER
    name = "vuln_scanner"

    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        confidence = 0.0
        evidence: list[str] = []

        scanner_token = _ua_is_scanner(features.user_agent)
        if scanner_token is not None:
            confidence += 0.5
            evidence.append(f"User-Agent names a scanning tool ({scanner_token})")

        if features.vuln_path_hits >= 3:
            confidence += 0.45
            sample = ", ".join(features.sample_vuln_paths[:3])
            evidence.append(f"{features.vuln_path_hits} requests to known probe paths ({sample})")
        elif features.vuln_path_hits >= 1:
            confidence += 0.2
            sample = ", ".join(features.sample_vuln_paths[:3])
            evidence.append(f"{features.vuln_path_hits} request(s) to known probe paths ({sample})")

        if features.ratio_404 > 0.6 and features.distinct_404_paths >= 15:
            confidence += 0.3
            evidence.append(
                f"{features.ratio_404:.0%} 404s across {features.distinct_404_paths} distinct paths"
            )

        if features.traversal_hits > 0:
            confidence += 0.15
            evidence.append(f"{features.traversal_hits} path-traversal / injection marker(s)")

        if features.exotic_method_count > 0:
            confidence += 0.1
            evidence.append(f"{features.exotic_method_count} unusual-method request(s)")

        median = features.inter_arrival_median
        if median is not None and median < 0.5 and features.request_count >= 5:
            confidence += 0.1
            evidence.append(f"fast cadence: median {median:.2f}s between requests")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
