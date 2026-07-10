"""Vulnerability / misconfiguration scanners.

The signature: lots of requests to known probe paths, a high 404 rate spread
across many distinct missing paths (probing, not a broken link), fast cadence,
traversal/injection markers, and no browser-like sub-resource loading.
"""

from __future__ import annotations

from ..dataload import load_list, load_shared_tuning, load_tokens, load_tuning
from ..model import ClientFeatures, Kind, Signal
from .base import Classifier
from .tags import forbidden_share, is_forbidden_heavy


def _scanner_ua_tokens() -> tuple[str, ...]:
    """UA substrings that name a scanning tool, from two sources kept distinct:

    * ``signatures/scanner_ua.toml`` -- anonymous tool signatures (sqlmap, nmap,
      ...) with no operator identity or origin to verify; and
    * ``agents/vuln_scanner.toml`` -- named scanners whose ``ua_substring`` is
      already recorded there to authenticate them against a published range.

    Folding the latter in here means a named scanner's UA lives in exactly one
    file (the one that also carries its ranges), not duplicated across both.
    """
    tokens = [token.lower() for token in load_list("scanner_ua")]
    tokens += [ua.lower() for ua, _spec in load_tokens("vuln_scanner")]
    return tuple(dict.fromkeys(tokens))  # de-duplicate, preserving order


_SCANNER_UA = _scanner_ua_tokens()

# Numeric knobs: this classifier's own in data/tuning/vuln_scanner.toml, the
# 404-storm thresholds in data/tuning/shared.toml.
_TUNING_SCHEMA = {
    "scanner_ua_weight": "scanner_ua.weight",
    "probe_strong_min_hits": "probe_paths.strong_min_hits",
    "probe_strong_ratio": "probe_paths.strong_ratio",
    "probe_strong_weight": "probe_paths.strong_weight",
    "probe_incidental_weight": "probe_paths.incidental_weight",
    "storm_404_weight": "storm_404.weight",
    "forbidden_weight": "forbidden.weight",
    "traversal_weight": "traversal.weight",
    "evasion_weight": "encoding_evasion.weight",
    "exotic_weight": "exotic_method.weight",
    "fast_median_max": "fast_cadence.median_max",
    "fast_min_requests": "fast_cadence.min_requests",
    "fast_weight": "fast_cadence.weight",
}
_T = load_tuning("vuln_scanner", _TUNING_SCHEMA)
_S = load_shared_tuning()


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
            confidence += _T["scanner_ua_weight"]
            evidence.append(f"User-Agent names a scanning tool ({scanner_token})")

        hits = features.vuln_path_hits
        if hits >= 1:
            sample = ", ".join(features.sample_vuln_paths[:3])
            # A burst of probes, or a client whose traffic is *mostly* probes --
            # even a single request that is itself a probe -- is a scanner; one
            # probe amid otherwise normal traffic is incidental. Keying the strong
            # tier on the ratio (not raw count) rescues a lone pure probe from the
            # singleton bucket: one GET /.env is as hostile as a hundred.
            if (
                hits >= _T["probe_strong_min_hits"]
                or hits >= features.request_count * _T["probe_strong_ratio"]
            ):
                confidence += _T["probe_strong_weight"]
                evidence.append(f"{hits} request(s) to known probe paths ({sample})")
            else:
                confidence += _T["probe_incidental_weight"]
                evidence.append(f"{hits} request(s) to known probe paths ({sample}); incidental")

        if (
            features.ratio_404 > _S["storm_404_ratio_min"]
            and features.distinct_404_targets >= _S["storm_404_distinct_paths_min"]
        ):
            confidence += _T["storm_404_weight"]
            urls = features.distinct_404_targets
            evidence.append(f"{features.ratio_404:.0%} 404s across {urls} distinct URLs")

        # The server's own hostility verdict: it refuses most of this client's requests
        # (403). Corroboration only -- a 403 can be a benign hotlink / WAF block, so this
        # is weighted below the direct probe tells and cannot fire the scanner on its own.
        if is_forbidden_heavy(features):
            confidence += _T["forbidden_weight"]
            forbidden, total = forbidden_share(features)
            evidence.append(
                f"server refused {forbidden / total:.0%} of requests with 403 — "
                "the site's defences treat it as hostile"
            )

        if features.traversal_hits > 0:
            confidence += _T["traversal_weight"]
            evidence.append(f"{features.traversal_hits} path-traversal / injection marker(s)")

        if features.evasion_hits > 0:
            # Double / overlong encoding has no legitimate use -- weight it above
            # plain traversal.
            confidence += _T["evasion_weight"]
            evidence.append(f"{features.evasion_hits} encoding-evasion marker(s)")

        if features.exotic_method_count > 0:
            confidence += _T["exotic_weight"]
            evidence.append(f"{features.exotic_method_count} unusual-method request(s)")

        median = features.inter_arrival_median
        if (
            median is not None
            and median < _T["fast_median_max"]
            and features.request_count >= _T["fast_min_requests"]
        ):
            confidence += _T["fast_weight"]
            evidence.append(f"fast cadence: median {median:.2f}s between requests")

        if not evidence:
            return []
        return [self._signal(confidence, evidence)]
