"""Causal chain analysis.

Builds a deterministic, step-by-step reasoning trail that explains why
a particular verdict was assigned. The same RawValidationResult always
produces the same causal chain (reproducibility requirement from the
Module 2 spec).
"""

from __future__ import annotations

from typing import List

from .models import CausalStep, MatchedEvent, RawValidationResult, VerdictType


class CausalChainBuilder:
    """Builds the causal_chain field for an OutcomeVerdict."""

    def build(
        self,
        result: RawValidationResult,
        verdict: VerdictType,
    ) -> List[CausalStep]:
        steps: List[CausalStep] = []
        step_no = 1

        steps.append(
            CausalStep(
                step_number=step_no,
                description=(
                    f"Evidence event received for action '{result.action_id}' "
                    f"(technique {result.technique_ref}), expecting observable: "
                    f"'{result.expected_observable}'."
                ),
                evidence_ref=result.action_id,
            )
        )
        step_no += 1

        steps.append(
            CausalStep(
                step_number=step_no,
                description=(
                    f"Detection rule '{result.rule_id}' executed against "
                    f"available telemetry for technique {result.technique_ref}."
                ),
                evidence_ref=result.rule_id,
            )
        )
        step_no += 1

        if result.no_data:
            steps.append(
                CausalStep(
                    step_number=step_no,
                    description=(
                        "No telemetry was returned by the SIEM connector for the "
                        "relevant time window. Verdict cannot be determined "
                        "(NoData)."
                    ),
                )
            )
            step_no += 1
            return steps

        if not result.matched_events:
            steps.append(
                CausalStep(
                    step_number=step_no,
                    description=(
                        "No matching defensive events were found. The rule did "
                        "not fire and no telemetry matched the expected "
                        "observable."
                    ),
                )
            )
            step_no += 1
            steps.append(
                CausalStep(
                    step_number=step_no,
                    description="Verdict assigned: Missed. Detection gap identified.",
                )
            )
            return steps

        matched_field_summary = self._summarize_matches(result, result.matched_events)
        steps.append(
            CausalStep(
                step_number=step_no,
                description=matched_field_summary,
                evidence_ref=result.matched_events[0].event_id,
            )
        )
        step_no += 1

        if verdict == VerdictType.DETECTED:
            conclusion = (
                f"All expected fields matched with high confidence "
                f"({result.confidence:.2f}). Verdict assigned: Detected."
            )
        elif verdict == VerdictType.PARTIAL:
            conclusion = (
                f"Some but not all expected observables were present "
                f"(confidence {result.confidence:.2f}). Verdict assigned: Partial."
            )
        else:
            conclusion = (
                f"Match strength was insufficient (confidence "
                f"{result.confidence:.2f}). Verdict assigned: {verdict.value}."
            )

        steps.append(CausalStep(step_number=step_no, description=conclusion))
        return steps

    @staticmethod
    def _summarize_matches(
        result: RawValidationResult, matched: List[MatchedEvent]
    ) -> str:
        expected = set(result.expected_fields)
        found = set()
        for ev in matched:
            found.update(ev.matched_fields)

        if expected:
            missing = expected - found
            if missing:
                return (
                    f"{len(matched)} candidate event(s) matched. "
                    f"Matched fields: {sorted(found)}. "
                    f"Missing expected fields: {sorted(missing)}."
                )
            return (
                f"{len(matched)} candidate event(s) matched, covering all "
                f"expected fields: {sorted(found)}."
            )

        return f"{len(matched)} candidate event(s) matched against the rule logic."
