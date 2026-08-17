from datetime import timedelta

from outcome_classifier.mttd import compute_mttd_seconds
from outcome_classifier.models import MatchedEvent
from tests.conftest import BASE_TIME, make_result


def test_mttd_computed_from_earliest_matched_event():
    early = MatchedEvent(
        event_id="evt-early", timestamp=BASE_TIME + timedelta(seconds=30)
    )
    late = MatchedEvent(
        event_id="evt-late", timestamp=BASE_TIME + timedelta(seconds=120)
    )
    result = make_result(confidence=0.9, matched_events=[late, early])

    mttd = compute_mttd_seconds(result)
    assert mttd == 30.0


def test_mttd_is_none_when_no_matched_events():
    result = make_result(confidence=0.0, matched_events=[])
    assert compute_mttd_seconds(result) is None


def test_mttd_is_none_when_no_evidence_timestamp():
    result = make_result(confidence=0.9, matched_events=[])
    result.evidence_timestamp = None
    assert compute_mttd_seconds(result) is None


def test_mttd_is_none_when_matched_events_lack_timestamps():
    event = MatchedEvent(event_id="evt-no-ts", timestamp=None)
    result = make_result(confidence=0.9, matched_events=[event])
    assert compute_mttd_seconds(result) is None


def test_mttd_guards_against_negative_delta():
    """An alert that appears to fire before the attack indicates a
    clock/timestamp issue, not a valid (negative) detection latency."""
    event = MatchedEvent(
        event_id="evt-before", timestamp=BASE_TIME - timedelta(seconds=5)
    )
    result = make_result(confidence=0.9, matched_events=[event])
    assert compute_mttd_seconds(result) is None
