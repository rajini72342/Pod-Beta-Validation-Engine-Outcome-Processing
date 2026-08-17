import pytest

from outcome_classifier.aggregation import VerdictAggregationError, VerdictAggregator
from outcome_classifier.models import CausalStep, OutcomeVerdict, VerdictType


def make_verdict(
    action_id="action-001",
    rule_id="rule-a",
    verdict=VerdictType.DETECTED,
    confidence=0.9,
    technique_ref="T1486",
    causal_chain=None,
):
    return OutcomeVerdict(
        action_id=action_id,
        technique_ref=technique_ref,
        rule_id=rule_id,
        verdict=verdict,
        confidence=confidence,
        causal_chain=causal_chain
        or [CausalStep(step_number=1, description=f"{rule_id} fired", evidence_ref="evt-1")],
        matched_evidence_ref="evt-1" if verdict != VerdictType.MISSED else None,
    )


class TestVerdictAggregator:
    def test_single_verdict_passthrough(self):
        v = make_verdict()
        result = VerdictAggregator().aggregate([v])
        assert result.action_id == "action-001"
        assert result.verdict == VerdictType.DETECTED
        assert result.confidence == 0.9
        assert result.contributing_rule_ids == ["rule-a"]
        assert result.contributing_verdict_count == 1

    def test_detected_beats_missed(self):
        detected = make_verdict(rule_id="rule-a", verdict=VerdictType.DETECTED, confidence=0.8)
        missed = make_verdict(rule_id="rule-b", verdict=VerdictType.MISSED, confidence=0.1)
        result = VerdictAggregator().aggregate([missed, detected])
        assert result.verdict == VerdictType.DETECTED
        assert result.confidence == 0.8
        assert set(result.contributing_rule_ids) == {"rule-a", "rule-b"}
        assert result.contributing_verdict_count == 2

    def test_partial_beats_missed_beats_nodata(self):
        no_data = make_verdict(rule_id="rule-c", verdict=VerdictType.NO_DATA, confidence=0.0)
        missed = make_verdict(rule_id="rule-b", verdict=VerdictType.MISSED, confidence=0.1)
        partial = make_verdict(rule_id="rule-a", verdict=VerdictType.PARTIAL, confidence=0.45)
        result = VerdictAggregator().aggregate([no_data, missed, partial])
        assert result.verdict == VerdictType.PARTIAL

        result2 = VerdictAggregator().aggregate([no_data, missed])
        assert result2.verdict == VerdictType.MISSED

        result3 = VerdictAggregator().aggregate([no_data])
        assert result3.verdict == VerdictType.NO_DATA

    def test_tie_break_uses_highest_confidence(self):
        low = make_verdict(rule_id="rule-a", verdict=VerdictType.DETECTED, confidence=0.71)
        high = make_verdict(rule_id="rule-b", verdict=VerdictType.DETECTED, confidence=0.98)
        result = VerdictAggregator().aggregate([low, high])
        assert result.confidence == 0.98
        assert result.matched_evidence_ref == high.matched_evidence_ref

    def test_causal_chain_merged_and_renumbered(self):
        v1 = make_verdict(
            rule_id="rule-a",
            verdict=VerdictType.DETECTED,
            confidence=0.9,
            causal_chain=[
                CausalStep(step_number=1, description="Step one", evidence_ref="e1"),
                CausalStep(step_number=2, description="Step two", evidence_ref="e2"),
            ],
        )
        v2 = make_verdict(rule_id="rule-b", verdict=VerdictType.MISSED, confidence=0.1)
        result = VerdictAggregator().aggregate([v1, v2])
        assert [s.step_number for s in result.causal_chain] == [1, 2, 3]
        assert "rule-b" in result.causal_chain[-1].description

    def test_empty_list_raises(self):
        with pytest.raises(VerdictAggregationError):
            VerdictAggregator().aggregate([])

    def test_mismatched_action_ids_raises(self):
        v1 = make_verdict(action_id="action-001")
        v2 = make_verdict(action_id="action-002")
        with pytest.raises(VerdictAggregationError):
            VerdictAggregator().aggregate([v1, v2])

    def test_aggregate_many_groups_by_action_id(self):
        a1 = make_verdict(action_id="action-001", rule_id="rule-a", verdict=VerdictType.DETECTED)
        a2 = make_verdict(action_id="action-001", rule_id="rule-b", verdict=VerdictType.MISSED)
        b1 = make_verdict(action_id="action-002", rule_id="rule-c", verdict=VerdictType.NO_DATA)

        results = VerdictAggregator().aggregate_many([a1, a2, b1])
        assert [r.action_id for r in results] == ["action-001", "action-002"]
        assert results[0].verdict == VerdictType.DETECTED
        assert results[1].verdict == VerdictType.NO_DATA

    def test_duplicate_rule_ids_deduplicated(self):
        v1 = make_verdict(rule_id="rule-a", verdict=VerdictType.PARTIAL, confidence=0.4)
        v2 = make_verdict(rule_id="rule-a", verdict=VerdictType.PARTIAL, confidence=0.5)
        result = VerdictAggregator().aggregate([v1, v2])
        assert result.contributing_rule_ids == ["rule-a"]
        assert result.contributing_verdict_count == 2
