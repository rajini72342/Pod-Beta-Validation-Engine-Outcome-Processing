"""Alert fidelity assessment.

Classifies a Detected/Partial verdict's underlying alert(s) into
High / Medium / Low fidelity, based on how specifically the alert
references the underlying MITRE ATT&CK technique and how completely
the expected observable fields were matched.
"""

from __future__ import annotations

from .models import AlertFidelity, MatchedEvent, RawValidationResult


class FidelityAssessor:
    """Assesses alert fidelity for Detected/Partial verdicts.

    Fidelity is derived from two signals:
      1. Technique specificity: does the alert/rule explicitly reference
         the same MITRE technique ID as the evidence event?
      2. Field coverage: what fraction of expected observable fields
         were present in the matched event(s)?

    Scoring (both signals contribute, technique specificity weighted
    more heavily since a generic rule that happens to fire is a much
    weaker signal than a rule purpose-built for the technique):

        combined_score = 0.6 * technique_specificity + 0.4 * field_coverage

        combined_score >= 0.75 -> HIGH
        combined_score >= 0.4  -> MEDIUM
        else                   -> LOW
    """

    HIGH_THRESHOLD = 0.75
    MEDIUM_THRESHOLD = 0.4

    def assess(self, result: RawValidationResult) -> AlertFidelity:
        if not result.matched_events:
            return AlertFidelity.LOW

        specificity = self._technique_specificity(result)
        coverage = self._field_coverage(result)

        combined = (0.6 * specificity) + (0.4 * coverage)

        if combined >= self.HIGH_THRESHOLD:
            return AlertFidelity.HIGH
        if combined >= self.MEDIUM_THRESHOLD:
            return AlertFidelity.MEDIUM
        return AlertFidelity.LOW

    @staticmethod
    def _technique_specificity(result: RawValidationResult) -> float:
        """1.0 if any matched event explicitly tags the same technique,
        0.5 if a related/partial technique reference exists, else 0.0."""
        exact = 0
        partial = 0
        for ev in result.matched_events:
            ref = ev.technique_ref_in_alert
            if not ref:
                continue
            if ref == result.technique_ref:
                exact += 1
            elif ref.split(".")[0] == result.technique_ref.split(".")[0]:
                partial += 1

        if exact:
            return 1.0
        if partial:
            return 0.5
        return 0.0

    @staticmethod
    def _field_coverage(result: RawValidationResult) -> float:
        expected = set(result.expected_fields)
        if not expected:
            # No specific fields declared; fall back to confidence as
            # a proxy for coverage.
            return result.confidence

        found = set()
        for ev in result.matched_events:
            found.update(ev.matched_fields)

        return len(found & expected) / len(expected)
