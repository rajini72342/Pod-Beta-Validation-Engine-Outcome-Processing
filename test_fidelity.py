from datetime import timedelta

from outcome_classifier.fidelity import FidelityAssessor
from outcome_classifier.models import AlertFidelity, MatchedEvent
from tests.conftest import BASE_TIME, make_result


def test_full_coverage_exact_technique_is_high_fidelity(
    high_confidence_full_match_result,
):
    fidelity = FidelityAssessor().assess(high_confidence_full_match_result)
    assert fidelity == AlertFidelity.HIGH


def test_partial_coverage_is_medium_or_low_fidelity(partial_match_result):
    fidelity = FidelityAssessor().assess(partial_match_result)
    assert fidelity in (AlertFidelity.MEDIUM, AlertFidelity.LOW)


def test_no_technique_reference_and_low_coverage_is_low_fidelity(
    low_fidelity_detected_result,
):
    fidelity = FidelityAssessor().assess(low_fidelity_detected_result)
    assert fidelity == AlertFidelity.LOW


def test_no_matched_events_is_low_fidelity(missed_result):
    fidelity = FidelityAssessor().assess(missed_result)
    assert fidelity == AlertFidelity.LOW


def test_related_subtechnique_gives_medium_specificity_boost():
    event = MatchedEvent(
        event_id="evt-sub",
        matched_fields=["CommandLine", "Image", "host"],
        technique_ref_in_alert="T1486.001",  # related sub-technique
        timestamp=BASE_TIME + timedelta(seconds=10),
    )
    result = make_result(confidence=0.8, matched_events=[event])
    fidelity = FidelityAssessor().assess(result)
    # Full field coverage (0.4*1.0=0.4) + partial specificity (0.6*0.5=0.3) = 0.7
    assert fidelity == AlertFidelity.MEDIUM
