"""Validation Engine (Pod Beta, Module 2).

Given a batch of evidence events (attacks/actions that were executed
during a Pod Beta run), the engine:

1. Checks the query cache for a previously-computed result for that
   exact query (action_id + rule_id + technique_ref + time window).
2. On a cache miss, queries every configured SIEM connector *in
   parallel* (see `siem_connector.MultiSIEMConnector`) and caches the
   merged result with a TTL so identical re-runs are served
   instantly.
3. Scores confidence from how completely the merged telemetry covers
   the expected observable's fields.
4. Builds a `RawValidationResult` and hands it to the
   `OutcomeClassifier` to produce the final `OutcomeVerdict`.

Batch processing: `process_batch` runs every event in the batch
*concurrently* via `asyncio.gather`, rather than looping and awaiting
one event at a time, so a batch of N events costs roughly one event's
latency (bounded by cache/connector speed) instead of N times that.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import List, Optional, Sequence

from pydantic import BaseModel, Field

from .cache import DEFAULT_TTL_SECONDS, QueryCache, build_cache_key
from .classifier import OutcomeClassifier
from .models import MatchedEvent, OutcomeVerdict, RawValidationResult
from .siem_connector import MultiSIEMConnector


class EvidenceEvent(BaseModel):
    """A single simulated-attack action awaiting validation.

    This is the input the Validation Engine consumes - upstream of the
    `RawValidationResult` contract the Outcome Classifier expects.
    """

    action_id: str
    technique_ref: str
    rule_id: str
    expected_observable: str
    expected_fields: List[str] = Field(default_factory=list)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    evidence_timestamp: Optional[datetime] = None
    tenant_id: Optional[str] = None


class ValidationEngine:
    """Executes detection rules against SIEM telemetry and produces
    classified verdicts, with caching, batching, and parallel connector
    fan-out."""

    def __init__(
        self,
        connector: Optional[MultiSIEMConnector] = None,
        cache: Optional[QueryCache] = None,
        classifier: Optional[OutcomeClassifier] = None,
        cache_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.connector = connector or MultiSIEMConnector()
        self.cache = cache or QueryCache()
        self.classifier = classifier or OutcomeClassifier()
        self.cache_ttl_seconds = cache_ttl_seconds

    async def _resolve_matched_events(self, event: EvidenceEvent) -> List[MatchedEvent]:
        cache_key = build_cache_key(
            action_id=event.action_id,
            technique_ref=event.technique_ref,
            rule_id=event.rule_id,
            expected_observable=event.expected_observable,
            expected_fields=event.expected_fields,
            window_start=event.window_start.isoformat() if event.window_start else None,
            window_end=event.window_end.isoformat() if event.window_end else None,
            tenant_id=event.tenant_id,
        )
        cached = await self.cache.get(cache_key)
        if cached is not None:
            return [MatchedEvent(**item) for item in cached]

        matched = await self.connector.query_all(
            action_id=event.action_id,
            technique_ref=event.technique_ref,
            rule_id=event.rule_id,
            expected_observable=event.expected_observable,
            expected_fields=event.expected_fields,
            window_start=event.window_start,
            window_end=event.window_end,
            tenant_id=event.tenant_id,
        )
        await self.cache.set(
            cache_key,
            [m.model_dump(mode="json") for m in matched],
            ttl_seconds=self.cache_ttl_seconds,
        )
        return matched

    @staticmethod
    def _score_confidence(event: EvidenceEvent, matched: List[MatchedEvent]) -> float:
        if not matched:
            return 0.0
        expected = set(event.expected_fields)
        if not expected:
            return 0.85 if matched else 0.0
        found = set()
        for ev in matched:
            found.update(ev.matched_fields)
        return round(len(found & expected) / len(expected), 4)

    async def validate_one(self, event: EvidenceEvent) -> RawValidationResult:
        """Resolve a single evidence event into a RawValidationResult
        (cache-checked, connector-fanned-out query under the hood)."""
        matched = await self._resolve_matched_events(event)
        confidence = self._score_confidence(event, matched)
        return RawValidationResult(
            action_id=event.action_id,
            technique_ref=event.technique_ref,
            rule_id=event.rule_id,
            confidence=confidence,
            expected_observable=event.expected_observable,
            expected_fields=event.expected_fields,
            matched_events=matched,
            no_data=False,
            evidence_timestamp=event.evidence_timestamp,
            tenant_id=event.tenant_id,
        )

    async def classify_one(self, event: EvidenceEvent) -> OutcomeVerdict:
        raw_result = await self.validate_one(event)
        return self.classifier.classify(raw_result)

    async def process_batch(self, events: Sequence[EvidenceEvent]) -> List[OutcomeVerdict]:
        """Validate + classify a batch of evidence events concurrently.

        This is the "batch requests" entry point: instead of the caller
        looping and issuing N sequential `classify_one` calls, the whole
        batch is scheduled together with `asyncio.gather`, so the total
        latency is governed by the slowest single event's SIEM lookups
        (or a cache hit), not the sum of every event in the batch.
        """
        if not events:
            return []
        return await asyncio.gather(*(self.classify_one(event) for event in events))

    async def close(self) -> None:
        await self.cache.close()
