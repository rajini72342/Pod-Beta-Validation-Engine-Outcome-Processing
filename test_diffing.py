from outcome_classifier.diffing import ValidationResultDiffer
from outcome_classifier.models import OutcomeVerdict, VerdictDiffType, VerdictType


def make_verdict(action_id, verdict=VerdictType.DETECTED, confidence=0.9, rule_id="rule-a"):
    return OutcomeVerdict(
        action_id=action_id,
        technique_ref="T1486",
        rule_id=rule_id,
        verdict=verdict,
        confidence=confidence,
    )


class TestValidationResultDiffer:
    def test_identical_sets_are_unchanged(self):
        old = [make_verdict("action-001"), make_verdict("action-002", VerdictType.MISSED, 0.1)]
        new = [make_verdict("action-001"), make_verdict("action-002", VerdictType.MISSED, 0.1)]
        report = ValidationResultDiffer().diff(old, new)
        assert report.total_compared == 2
        assert report.changed_count == 0
        assert report.unchanged_count == 2
        assert all(e.diff_type == VerdictDiffType.UNCHANGED for e in report.entries)

    def test_verdict_change_detected(self):
        old = [make_verdict("action-001", VerdictType.MISSED, 0.1)]
        new = [make_verdict("action-001", VerdictType.DETECTED, 0.9)]
        report = ValidationResultDiffer().diff(old, new)
        assert report.changed_count == 1
        entry = report.entries[0]
        assert entry.diff_type == VerdictDiffType.VERDICT_CHANGED
        assert entry.old_verdict == VerdictType.MISSED
        assert entry.new_verdict == VerdictType.DETECTED

    def test_confidence_only_change_detected(self):
        old = [make_verdict("action-001", VerdictType.DETECTED, 0.75)]
        new = [make_verdict("action-001", VerdictType.DETECTED, 0.95)]
        report = ValidationResultDiffer().diff(old, new)
        entry = report.entries[0]
        assert entry.diff_type == VerdictDiffType.CONFIDENCE_CHANGED
        assert entry.old_confidence == 0.75
        assert entry.new_confidence == 0.95

    def test_tiny_confidence_drift_is_not_flagged(self):
        old = [make_verdict("action-001", VerdictType.DETECTED, 0.750000001)]
        new = [make_verdict("action-001", VerdictType.DETECTED, 0.750000002)]
        report = ValidationResultDiffer().diff(old, new)
        assert report.entries[0].diff_type == VerdictDiffType.UNCHANGED

    def test_new_action_id_flagged(self):
        old = [make_verdict("action-001")]
        new = [make_verdict("action-001"), make_verdict("action-002")]
        report = ValidationResultDiffer().diff(old, new)
        assert report.new_count == 1
        new_entry = [e for e in report.entries if e.action_id == "action-002"][0]
        assert new_entry.diff_type == VerdictDiffType.NEW
        assert new_entry.old_verdict is None

    def test_removed_action_id_flagged(self):
        old = [make_verdict("action-001"), make_verdict("action-002")]
        new = [make_verdict("action-001")]
        report = ValidationResultDiffer().diff(old, new)
        assert report.removed_count == 1
        removed_entry = [e for e in report.entries if e.action_id == "action-002"][0]
        assert removed_entry.diff_type == VerdictDiffType.REMOVED
        assert removed_entry.new_verdict is None

    def test_empty_vs_empty(self):
        report = ValidationResultDiffer().diff([], [])
        assert report.total_compared == 0
        assert report.changed_count == 0

    def test_summary_counts_add_up(self):
        old = [
            make_verdict("a1", VerdictType.DETECTED, 0.9),
            make_verdict("a2", VerdictType.MISSED, 0.1),
            make_verdict("a3", VerdictType.PARTIAL, 0.4),
        ]
        new = [
            make_verdict("a1", VerdictType.DETECTED, 0.9),  # unchanged
            make_verdict("a2", VerdictType.DETECTED, 0.8),  # verdict changed
            # a3 removed
            make_verdict("a4", VerdictType.NO_DATA, 0.0),  # new
        ]
        report = ValidationResultDiffer().diff(old, new)
        assert report.total_compared == 4
        assert report.unchanged_count == 1
        assert report.new_count == 1
        assert report.removed_count == 1
        by_id = {e.action_id: e.diff_type for e in report.entries}
        assert by_id["a2"] == VerdictDiffType.VERDICT_CHANGED
