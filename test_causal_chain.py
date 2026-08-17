from outcome_classifier.causal_chain import CausalChainBuilder
from outcome_classifier.models import VerdictType


def test_causal_chain_for_detected_has_all_expected_steps(
    high_confidence_full_match_result,
):
    chain = CausalChainBuilder().build(
        high_confidence_full_match_result, VerdictType.DETECTED
    )

    assert len(chain) >= 4
    assert chain[0].step_number == 1
    assert "Evidence event received" in chain[0].description
    assert "rule" in chain[1].description.lower()
    assert any("Detected" in step.description for step in chain)
    # Step numbers must be sequential
    for i, step in enumerate(chain, start=1):
        assert step.step_number == i


def test_causal_chain_for_missed_explains_absence(missed_result):
    chain = CausalChainBuilder().build(missed_result, VerdictType.MISSED)

    descriptions = " ".join(step.description for step in chain)
    assert "No matching defensive events" in descriptions
    assert "Missed" in descriptions


def test_causal_chain_for_no_data_explains_lack_of_telemetry(no_data_result):
    chain = CausalChainBuilder().build(no_data_result, VerdictType.NO_DATA)

    descriptions = " ".join(step.description for step in chain)
    assert "No telemetry" in descriptions
    assert "NoData" in descriptions


def test_causal_chain_for_partial_lists_missing_fields(partial_match_result):
    chain = CausalChainBuilder().build(partial_match_result, VerdictType.PARTIAL)

    descriptions = " ".join(step.description for step in chain)
    assert "Missing expected fields" in descriptions
    assert "Partial" in descriptions


def test_causal_chain_is_reproducible(high_confidence_full_match_result):
    builder = CausalChainBuilder()
    chain_a = builder.build(high_confidence_full_match_result, VerdictType.DETECTED)
    chain_b = builder.build(high_confidence_full_match_result, VerdictType.DETECTED)

    assert [s.model_dump() for s in chain_a] == [s.model_dump() for s in chain_b]
