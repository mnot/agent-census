"""Client classification: independent rule-based classifiers + a combiner.

The public entry point is :func:`classify_client`, which runs every registered
classifier over a client's features and combines their signals into a single
:class:`~agent_census.model.Classification` (primary kind plus tags).
"""

from __future__ import annotations

from ..model import (
    BotVerification,
    Classification,
    ClassifyContext,
    ClientFeatures,
    ComplianceReport,
    Signal,
    WbaResult,
)
from .base import Classifier
from .combiner import DEFAULT_UNKNOWN_THRESHOLD, combine
from .registry import all_classifiers


def run_classifiers(
    features: ClientFeatures, context: ClassifyContext | None = None
) -> list[Signal]:
    """Collect signals from every classifier for one client.

    ``context`` carries the combiner-level inputs (origin network, redirect regime) a
    context-aware classifier may read; it defaults to an empty context, under which
    every classifier behaves exactly as its pure :meth:`~Classifier.evaluate`.
    """
    ctx = context if context is not None else ClassifyContext()
    signals: list[Signal] = []
    for classifier in all_classifiers():
        signals.extend(classifier.evaluate_in_context(features, ctx))
    return signals


def classify_client(
    features: ClientFeatures,
    *,
    compliance: ComplianceReport | None = None,
    verification: BotVerification | None = None,
    wba: WbaResult | None = None,
    datacenter: bool = False,
    aggregate: bool = False,
    redirect_shadow: str | None = None,
    unknown_threshold: float = DEFAULT_UNKNOWN_THRESHOLD,
    keep_signals: bool = True,
) -> Classification:
    """Run all classifiers over ``features`` and combine into a verdict.

    ``aggregate`` marks a multi-client display fold (a privacy-relay / VPN row),
    suppressing the per-client cadence tags. ``wba`` is the Web Bot Auth verdict,
    the cryptographic-identity channel weighed alongside the network ``verification``.
    ``redirect_shadow`` names the host form the site redirects away (``"www"`` or
    ``"apex"``), arming the impossible-referer spoof tell for that direction.
    """
    context = ClassifyContext(datacenter=datacenter, redirect_shadow=redirect_shadow)
    signals = run_classifiers(features, context)
    return combine(
        signals,
        features,
        compliance=compliance,
        verification=verification,
        wba=wba,
        datacenter=datacenter,
        aggregate=aggregate,
        redirect_shadow=redirect_shadow,
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
