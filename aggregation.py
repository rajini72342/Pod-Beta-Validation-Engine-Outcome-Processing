"""Verdict Aggregation (Pod Beta, Module 2).

A single simulated action can end up with more than one OutcomeVerdict
attached to it - e.g. more than one detection rule was mapped to the
same technique, or the action was re-validated across multiple runs.
The VerdictAggregator combines every OutcomeVerdict for the same
action_id into a single AggregatedVerdict that represents the overall
validation outcome for that action.

Aggregation strategy ("best-evidence"): the strongest signal wins.
Detected beats Partial beats Missed beats NoData, because a single
rule firing cleanly is stronger evidence of coverage than nine other
rules reporting no telemetry. Ties within the winning verdict type are
broken by taking the highest confidence. Causal chains from every
contributing verdict are merged (in input order, renumbered) so the
aggregated verdict stays fully explainable.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from .models import AggregatedVerdict, CausalStep, OutcomeVerdict, VerdictType

# Best evidence wins: lower index = stronger signal.
_VERDICT_PRIORITY: Dict[VerdictType, int] = {
    VerdictType.DETECTED: 0,
    VerdictType.PARTIAL: 1,
    VerdictType.MISSED: 2,
    VerdictType.NO_DATA: 3,
}


class VerdictAggregationError(ValueError):
    """Raised when a set of verdicts cannot be aggregated together."""


class VerdictAggregator:
    """Combines multiple OutcomeVerdicts for a single action into one
    AggregatedVerdict representing the overall validation outcome."""

    strategy_name = "best-evidence"

    def aggregate(self, verdicts: Sequence[OutcomeVerdict]) -> AggregatedVerdict:
        if not verdicts:
            raise VerdictAggregationError("Cannot aggregate an empty list of verdicts")

        action_ids = {v.action_id for v in verdicts}
        if len(action_ids) > 1:
            raise VerdictAggregationError(
                "All verdicts passed to aggregate() must share the same "
                f"action_id, got: {sorted(action_ids)}"
            )

        # Pick the winning verdict: best VerdictType priority, then
        # highest confidence within that priority as the tie-break.
        winner = min(
            verdicts,
            key=lambda v: (_VERDICT_PRIORITY[v.verdict], -v.confidence),
        )

        merged_chain = self._merge_causal_chains(verdicts, winner)
        contributing_rule_ids = self._ordered_unique([v.rule_id for v in verdicts])

        return AggregatedVerdict(
            action_id=winner.action_id,
            technique_ref=winner.technique_ref,
            verdict=winner.verdict,
            confidence=winner.confidence,
            contributing_rule_ids=contributing_rule_ids,
            contributing_verdict_count=len(verdicts),
            causal_chain=merged_chain,
            mttd_seconds=winner.mttd_seconds,
            alert_fidelity=winner.alert_fidelity,
            matched_evidence_ref=winner.matched_evidence_ref,
            aggregation_strategy=self.strategy_name,
        )

    def aggregate_many(
        self, verdicts: Sequence[OutcomeVerdict]
    ) -> List[AggregatedVerdict]:
        """Group an arbitrary list of verdicts by action_id and
        aggregate each group. Input order of action_ids is preserved."""
        grouped: Dict[str, List[OutcomeVerdict]] = {}
        order: List[str] = []
        for v in verdicts:
            if v.action_id not in grouped:
                grouped[v.action_id] = []
                order.append(v.action_id)
            grouped[v.action_id].append(v)

        return [self.aggregate(grouped[action_id]) for action_id in order]

    @staticmethod
    def _ordered_unique(items: Sequence[str]) -> List[str]:
        seen: Dict[str, None] = {}
        for item in items:
            seen.setdefault(item, None)
        return list(seen.keys())

    @staticmethod
    def _merge_causal_chains(
        verdicts: Sequence[OutcomeVerdict], winner: OutcomeVerdict
    ) -> List[CausalStep]:
        """Merge the winner's causal chain first, then note any other
        contributing rules that were also evaluated, so the aggregated
        chain remains fully explainable when more than one verdict fed
        into the outcome."""
        merged: List[CausalStep] = []
        step_number = 1
        for step in winner.causal_chain:
            merged.append(
                CausalStep(
                    step_number=step_number,
                    description=step.description,
                    evidence_ref=step.evidence_ref,
                )
            )
            step_number += 1

        others = [v for v in verdicts if v is not winner]
        if others:
            other_rules = ", ".join(sorted({v.rule_id for v in others}))
            merged.append(
                CausalStep(
                    step_number=step_number,
                    description=(
                        f"Aggregated against {len(others)} additional verdict(s) "
                        f"from rule(s) [{other_rules}]; best-evidence verdict "
                        f"'{winner.verdict.value}' (rule '{winner.rule_id}') retained."
                    ),
                    evidence_ref=winner.matched_evidence_ref,
                )
            )
        return merged
