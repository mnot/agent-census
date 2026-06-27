"""Client classification: independent rule-based classifiers + a combiner.

The public entry point is :func:`classify_client`, which runs every registered
classifier over a client's features and combines their signals into a single
:class:`~agent_census.model.Classification` (primary kind plus tags).
"""

from __future__ import annotations

from ..model import BotVerification, Classification, ClientFeatures, ComplianceReport, Signal
from .base import Classifier
from .combiner import DEFAULT_UNKNOWN_THRESHOLD, combine
from .registry import all_classifiers


def run_classifiers(features: ClientFeatures) -> list[Signal]:
    """Collect signals from every classifier for one client."""
    signals: list[Signal] = []
    for classifier in all_classifiers():
        signals.extend(classifier.evaluate(features))
    return signals


def classify_client(
    features: ClientFeatures,
    *,
    compliance: ComplianceReport | None = None,
    verification: BotVerification | None = None,
    datacenter: bool = False,
    aggregate: bool = False,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
) -> Classification:
    """Run all classifiers over ``features`` and combine into a verdict.

    ``aggregate`` marks a multi-client display fold (a privacy-relay / VPN row),
    suppressing the per-client cadence tags.
    """
    signals = run_classifiers(features)
    return combine(
        signals,
        features,
        compliance=compliance,
        verification=verification,
        datacenter=datacenter,
        aggregate=aggregate,
        unknown_threshold=unknown_threshold,
        keep_signals=keep_signals,
    )


__all__ = [
    "Classifier",
    "classify_client",
    "run_classifiers",
    "combine",
    "all_classifiers",
    "DEFAULT_UNKNOWN_THRESHOLD",
]
