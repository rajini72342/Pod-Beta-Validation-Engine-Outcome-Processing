from datetime import datetime, timezone

import pytest

from outcome_classifier.cache import QueryCache
from outcome_classifier.classifier import OutcomeClassifier
from outcome_classifier.models import MatchedEvent, VerdictType
from outcome_classifier.siem_connector import MultiSIEMConnector
from outcome_classifier.validation_engine import EvidenceEvent, ValidationEngine

BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


class _StubConnector:
    def __init__(self, events):
        self.name = "stub"
        self._events = events
        self.call_count = 0

    async def query(self, **kwargs):
        self.call_count += 1
        return self._events


def make_event(action_id="a1", rule_id="rule-1", fields=None):
    return EvidenceEvent(
        action_id=action_id,
        technique_ref="T1486",
        rule_id=rule_id,
        expected_observable="mass file encryption",
        expected_fields=fields or ["CommandLine", "Image", "host"],
        window_start=BASE_TIME,
        window_end=BASE_TIME,
    )


class TestValidationEngineSingle:
    @pytest.mark.asyncio
    async def test_full_match_yields_detected(self):
        matched = MatchedEvent(
            event_id="evt-1",
            rule_id="rule-1",
            matched_fields=["CommandLine", "Image", "host"],
        )
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[_StubConnector([matched])]),
            cache=QueryCache(),
            classifier=OutcomeClassifier(),
        )
        verdict = await engine.classify_one(make_event())
        assert verdict.verdict == VerdictType.DETECTED
        assert verdict.confidence == 1.0

    @pytest.mark.asyncio
    async def test_no_matches_yields_missed(self):
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[_StubConnector([])]),
            cache=QueryCache(),
            classifier=OutcomeClassifier(),
        )
        verdict = await engine.classify_one(make_event())
        assert verdict.verdict == VerdictType.MISSED
        assert verdict.confidence == 0.0

    @pytest.mark.asyncio
    async def test_second_query_is_served_from_cache(self):
        matched = MatchedEvent(
            event_id="evt-1", rule_id="rule-1", matched_fields=["CommandLine"]
        )
        stub = _StubConnector([matched])
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[stub]),
            cache=QueryCache(),
            classifier=OutcomeClassifier(),
        )
        event = make_event()
        await engine.validate_one(event)
        await engine.validate_one(event)
        assert stub.call_count == 1
        assert engine.cache.stats["hits"] == 1


class TestValidationEngineBatch:
    @pytest.mark.asyncio
    async def test_empty_batch_returns_empty(self):
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[_StubConnector([])]),
        )
        assert await engine.process_batch([]) == []

    @pytest.mark.asyncio
    async def test_batch_preserves_order_and_count(self):
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[_StubConnector([])]),
        )
        events = [make_event(action_id=f"a{i}") for i in range(5)]
        verdicts = await engine.process_batch(events)
        assert [v.action_id for v in verdicts] == [f"a{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_batch_runs_concurrently(self):
        import asyncio
        import time

        class SlowConnector:
            name = "slow"

            async def query(self, **kwargs):
                await asyncio.sleep(0.1)
                return []

        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[SlowConnector()]),
        )
        events = [make_event(action_id=f"a{i}") for i in range(10)]
        start = time.perf_counter()
        await engine.process_batch(events)
        elapsed = time.perf_counter() - start
        # Sequential would take ~1.0s (10 x 0.1s); concurrent should be
        # close to a single 0.1s round trip.
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_close_closes_cache(self):
        engine = ValidationEngine(
            connector=MultiSIEMConnector(connectors=[_StubConnector([])]),
        )
        await engine.close()
