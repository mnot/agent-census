"""The classifier contract.

A classifier is a pure function of :class:`ClientFeatures`: it reads only the
feature vector (and its own static data lists) and emits zero or more
:class:`Signal` votes for the kind it argues for. It never imports another
classifier and never sees the final decision — that keeps each one independently
testable and free to evolve. "This client is NOT a browser" is expressed simply
by the browser classifier not firing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..model import ClientFeatures, Kind, Signal


class Classifier(ABC):
    """Argues, from features alone, that a client is of a particular kind."""

    #: the kind this classifier votes for
    label: Kind = Kind.UNKNOWN
    #: short stable name, recorded on each signal for provenance
    name: str = ""

    @abstractmethod
    def evaluate(self, features: ClientFeatures) -> list[Signal]:
        """Return signals supporting :attr:`label` (possibly empty)."""

    def _signal(
        self,
        confidence: float,
        evidence: list[str],
        *,
        agent_name: str | None = None,
        boilerplate_lead: bool = False,
    ) -> Signal:
        """Helper to build a signal for this classifier's label."""
        return Signal(
            kind=self.label,
            # Clamp to the documented [0, 1] range. A classifier that sums and
            # subtracts weights (e.g. the browser one's metronomic penalty) can land
            # below 0; the combiner already floors negatives via max(), so pinning
            # it here is behaviour-neutral and keeps Signal.confidence honest.
            confidence=max(0.0, min(confidence, 1.0)),
            evidence=tuple(evidence),
            classifier=self.name,
            agent_name=agent_name,
            boilerplate_lead=boilerplate_lead,
        )
