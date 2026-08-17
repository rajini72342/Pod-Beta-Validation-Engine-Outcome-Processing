"""Outcome Classifier core logic.

Converts a RawValidationResult (produced by the Validation Engine) into
a fully classified OutcomeVerdict: one of Detected / Missed / Partial /
NoData, with confidence, causal chain, MTTD, and alert fidelity.

Classification thresholds (per the Module 2 PRD, section 3.4):

    Detected -> confidence in [0.7, 1.0]
    Partial  -> confidence in [0.3, 0.6]
    Missed   -> confidence in [0.0, 0.2], or no match at all
    NoData   -> no telemetry was available from the SIEM connector
"""

from __future__ import annotations

from .causal_chain import CausalChainBuilder
from .fidelity import FidelityAssessor
from .mttd import compute_mttd_seconds
from .models import OutcomeVerdict, RawValidationResult, VerdictType


class OutcomeClassifier:
    """Classifies raw validation results into final verdicts."""

    DETECTED_THRESHOLD = 0.7
    PARTIAL_THRESHOLD = 0.3

    def __init__(
        self,
        causal_chain_builder: CausalChainBuilder | None = None,
        fidelity_assessor: FidelityAssessor | None = None,
    ) -> None:
        self._causal_chain_builder = causal_chain_builder or CausalChainBuilder()
        self._fidelity_assessor = fidelity_assessor or FidelityAssessor()

    def classify(self, result: RawValidationResult) -> OutcomeVerdict:
        verdict_type = self._determine_verdict(result)

        causal_chain = self._causal_chain_builder.build(result, verdict_type)

        alert_fidelity = None
        if verdict_type in (VerdictType.DETECTED, VerdictType.PARTIAL):
            alert_fidelity = self._fidelity_assessor.assess(result)

        mttd_seconds = None
        if verdict_type in (VerdictType.DETECTED, VerdictType.PARTIAL):
            mttd_seconds = compute_mttd_seconds(result)

        matched_evidence_ref = None
        if result.matched_events:
            matched_evidence_ref = result.matched_events[0].event_id

        return OutcomeVerdict(
            action_id=result.action_id,
            technique_ref=result.technique_ref,
            rule_id=result.rule_id,
            verdict=verdict_type,
            confidence=result.confidence,
            causal_chain=causal_chain,
            mttd_seconds=mttd_seconds,
            alert_fidelity=alert_fidelity,
            matched_evidence_ref=matched_evidence_ref,
        )

    def _determine_verdict(self, result: RawValidationResult) -> VerdictType:
        if result.no_data:
            return VerdictType.NO_DATA

        if result.confidence >= self.DETECTED_THRESHOLD:
            return VerdictType.DETECTED

        if result.confidence >= self.PARTIAL_THRESHOLD:
            return VerdictType.PARTIAL

        return VerdictType.MISSED
