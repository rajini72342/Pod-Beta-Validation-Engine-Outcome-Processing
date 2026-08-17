from outcome_classifier.classifier import OutcomeClassifier
from outcome_classifier.models import AlertFidelity, VerdictType


def test_high_confidence_full_match_yields_detected(high_confidence_full_match_result):
    result = OutcomeClassifier().classify(high_confidence_full_match_result)

    assert result.verdict == VerdictType.DETECTED
    assert result.confidence == 0.95
    assert result.matched_evidence_ref == "evt-001"
    assert result.alert_fidelity == AlertFidelity.HIGH
    assert result.mttd_seconds == 42.0


def test_partial_match_yields_partial_verdict(partial_match_result):
    result = OutcomeClassifier().classify(partial_match_result)

    assert result.verdict == VerdictType.PARTIAL
    assert result.confidence == 0.45
    assert result.mttd_seconds == 90.0
    assert result.alert_fidelity is not None


def test_no_match_yields_missed(missed_result):
    result = OutcomeClassifier().classify(missed_result)

    assert result.verdict == VerdictType.MISSED
    assert result.mttd_seconds is None
    assert result.alert_fidelity is None
    assert result.matched_evidence_ref is None


def test_no_telemetry_yields_no_data(no_data_result):
    result = OutcomeClassifier().classify(no_data_result)

    assert result.verdict == VerdictType.NO_DATA
    assert result.mttd_seconds is None
    assert result.alert_fidelity is None


def test_generic_rule_match_yields_low_fidelity_despite_detected(
    low_fidelity_detected_result,
):
    result = OutcomeClassifier().classify(low_fidelity_detected_result)

    assert result.verdict == VerdictType.DETECTED
    assert result.alert_fidelity == AlertFidelity.LOW


def test_boundary_confidence_0_70_is_detected():
    from tests.conftest import make_result
    from outcome_classifier.models import MatchedEvent
    from datetime import timedelta
    from tests.conftest import BASE_TIME

    event = MatchedEvent(
        event_id="evt-boundary",
        matched_fields=["CommandLine", "Image", "host"],
        technique_ref_in_alert="T1486",
        timestamp=BASE_TIME + timedelta(seconds=5),
    )
    result = make_result(confidence=0.70, matched_events=[event])
    verdict = OutcomeClassifier().classify(result)
    assert verdict.verdict == VerdictType.DETECTED


def test_boundary_confidence_0_30_is_partial():
    from tests.conftest import make_result

    result = make_result(confidence=0.30, matched_events=[])
    verdict = OutcomeClassifier().classify(result)
    assert verdict.verdict == VerdictType.PARTIAL


def test_boundary_confidence_just_below_partial_is_missed():
    from tests.conftest import make_result

    result = make_result(confidence=0.29, matched_events=[])
    verdict = OutcomeClassifier().classify(result)
    assert verdict.verdict == VerdictType.MISSED


def test_no_data_takes_precedence_over_confidence():
    """Even if confidence looks 'high', no_data=True must always win."""
    from tests.conftest import make_result

    result = make_result(confidence=0.9, no_data=True, matched_events=[])
    verdict = OutcomeClassifier().classify(result)
    assert verdict.verdict == VerdictType.NO_DATA


def test_classification_is_deterministic(high_confidence_full_match_result):
    classifier = OutcomeClassifier()
    first = classifier.classify(high_confidence_full_match_result)
    second = classifier.classify(high_confidence_full_match_result)

    assert first.model_dump() == second.model_dump()
