from datetime import datetime, timedelta, timezone

import pytest

from outcome_classifier.models import MatchedEvent, RawValidationResult

BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_result(
    *,
    confidence: float,
    no_data: bool = False,
    matched_events=None,
    expected_fields=None,
    technique_ref: str = "T1486",
    evidence_offset_seconds: float = 0.0,
) -> RawValidationResult:
    return RawValidationResult(
        action_id="action-001",
        technique_ref=technique_ref,
        rule_id="rule-ransomware-001",
        confidence=confidence,
        expected_observable="mass file encryption via vssadmin/wbadmin",
        expected_fields=expected_fields or ["CommandLine", "Image", "host"],
        matched_events=matched_events or [],
        no_data=no_data,
        evidence_timestamp=BASE_TIME + timedelta(seconds=evidence_offset_seconds),
        tenant_id="tenant-alpha",
    )


@pytest.fixture
def high_confidence_full_match_result() -> RawValidationResult:
    event = MatchedEvent(
        event_id="evt-001",
        rule_id="rule-ransomware-001",
        alert_name="Ransomware File Encryption Activity Detected",
        matched_fields=["CommandLine", "Image", "host"],
        technique_ref_in_alert="T1486",
        timestamp=BASE_TIME + timedelta(seconds=42),
    )
    return make_result(confidence=0.95, matched_events=[event])


@pytest.fixture
def partial_match_result() -> RawValidationResult:
    event = MatchedEvent(
        event_id="evt-002",
        rule_id="rule-ransomware-001",
        alert_name="Suspicious Encryption Command",
        matched_fields=["CommandLine"],
        technique_ref_in_alert="T1486",
        timestamp=BASE_TIME + timedelta(seconds=90),
    )
    return make_result(confidence=0.45, matched_events=[event])


@pytest.fixture
def missed_result() -> RawValidationResult:
    return make_result(confidence=0.0, matched_events=[])


@pytest.fixture
def no_data_result() -> RawValidationResult:
    return make_result(confidence=0.0, no_data=True, matched_events=[])


@pytest.fixture
def low_fidelity_detected_result() -> RawValidationResult:
    # High confidence but the matched alert doesn't reference the
    # technique at all and only covers one of three expected fields.
    event = MatchedEvent(
        event_id="evt-003",
        rule_id="generic-rule-999",
        alert_name="Generic Process Anomaly",
        matched_fields=["host"],
        technique_ref_in_alert=None,
        timestamp=BASE_TIME + timedelta(seconds=15),
    )
    return make_result(confidence=0.72, matched_events=[event])
