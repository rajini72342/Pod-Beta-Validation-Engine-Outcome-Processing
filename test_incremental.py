from datetime import datetime, timezone

import pytest

from outcome_classifier.incremental import IncrementalValidator
from outcome_classifier.models import OutcomeVerdict, VerdictType
from outcome_classifier.validation_engine import EvidenceEvent

BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


class FakeEngine:
    """Deterministic stand-in for ValidationEngine: every event it's
    asked to process_batch comes back Detected, so tests can assert
    exactly which action_ids were (re)validated vs. skipped."""

    def __init__(self):
        self.process_batch_calls: list[list[EvidenceEvent]] = []

    async def process_batch(self, events):
        self.process_batch_calls.append(list(events))
        return [
            OutcomeVerdict(
                action_id=e.action_id,
                technique_ref=e.technique_ref,
                rule_id=e.rule_id,
                verdict=VerdictType.DETECTED,
                confidence=0.99,
            )
            for e in events
        ]

    async def close(self):
        pass


def make_event(action_id, rule_id):
    return EvidenceEvent(
        action_id=action_id,
        technique_ref="T1486",
        rule_id=rule_id,
        expected_observable="mass file encryption",
        expected_fields=["CommandLine", "Image"],
        window_start=BASE_TIME,
        window_end=BASE_TIME,
    )


def make_prior_verdict(action_id, rule_id, verdict=VerdictType.MISSED, confidence=0.1):
    return OutcomeVerdict(
        action_id=action_id,
        technique_ref="T1486",
        rule_id=rule_id,
        verdict=verdict,
        confidence=confidence,
    )


class TestIncrementalValidator:
    @pytest.mark.asyncio
    async def test_only_affected_events_are_revalidated(self):
        events = [
            make_event("action-001", "rule-a"),
            make_event("action-002", "rule-b"),
            make_event("action-003", "rule-a"),
        ]
        previous = {
            "action-001": make_prior_verdict("action-001", "rule-a"),
            "action-002": make_prior_verdict("action-002", "rule-b"),
            "action-003": make_prior_verdict("action-003", "rule-a"),
        }
        engine = FakeEngine()
        validator = IncrementalValidator(engine=engine)

        result = await validator.revalidate_changed_rules(
            events, changed_rule_ids=["rule-a"], previous_verdicts=previous
        )

        assert sorted(result.revalidated_action_ids) == ["action-001", "action-003"]
        assert result.skipped_action_ids == ["action-002"]
        # Only the affected events were actually sent through the engine.
        assert len(engine.process_batch_calls) == 1
        assert {e.action_id for e in engine.process_batch_calls[0]} == {
            "action-001",
            "action-003",
        }

    @pytest.mark.asyncio
    async def test_carried_forward_verdicts_are_reused_not_regenerated(self):
        events = [make_event("action-002", "rule-b")]
        previous_verdict = make_prior_verdict("action-002", "rule-b", VerdictType.PARTIAL, 0.5)
        previous = {"action-002": previous_verdict}
        engine = FakeEngine()
        validator = IncrementalValidator(engine=engine)

        result = await validator.revalidate_changed_rules(
            events, changed_rule_ids=["rule-a"], previous_verdicts=previous
        )

        assert result.skipped_action_ids == ["action-002"]
        assert result.verdicts[0].verdict == VerdictType.PARTIAL
        assert result.verdicts[0].confidence == 0.5
        assert engine.process_batch_calls == [[]]

    @pytest.mark.asyncio
    async def test_event_with_no_prior_verdict_is_always_revalidated(self):
        events = [make_event("action-new", "rule-untouched")]
        engine = FakeEngine()
        validator = IncrementalValidator(engine=engine)

        result = await validator.revalidate_changed_rules(
            events, changed_rule_ids=["rule-a"], previous_verdicts={}
        )

        assert result.revalidated_action_ids == ["action-new"]
        assert result.skipped_action_ids == []

    @pytest.mark.asyncio
    async def test_result_order_matches_input_event_order(self):
        events = [
            make_event("action-001", "rule-a"),
            make_event("action-002", "rule-b"),
            make_event("action-003", "rule-a"),
        ]
        previous = {
            "action-001": make_prior_verdict("action-001", "rule-a"),
            "action-002": make_prior_verdict("action-002", "rule-b"),
            "action-003": make_prior_verdict("action-003", "rule-a"),
        }
        engine = FakeEngine()
        validator = IncrementalValidator(engine=engine)

        result = await validator.revalidate_changed_rules(
            events, changed_rule_ids=["rule-a"], previous_verdicts=previous
        )
        assert [v.action_id for v in result.verdicts] == [
            "action-001",
            "action-002",
            "action-003",
        ]

    @pytest.mark.asyncio
    async def test_no_changed_rules_skips_everything_with_history(self):
        events = [make_event("action-001", "rule-a"), make_event("action-002", "rule-b")]
        previous = {
            "action-001": make_prior_verdict("action-001", "rule-a"),
            "action-002": make_prior_verdict("action-002", "rule-b"),
        }
        engine = FakeEngine()
        validator = IncrementalValidator(engine=engine)

        result = await validator.revalidate_changed_rules(
            events, changed_rule_ids=[], previous_verdicts=previous
        )
        assert result.revalidated_action_ids == []
        assert sorted(result.skipped_action_ids) == ["action-001", "action-002"]

    def test_affected_events_helper(self):
        events = [
            make_event("action-001", "rule-a"),
            make_event("action-002", "rule-b"),
            make_event("action-003", "rule-c"),
        ]
        affected = IncrementalValidator.affected_events(events, ["rule-a", "rule-c"])
        assert {e.action_id for e in affected} == {"action-001", "action-003"}
