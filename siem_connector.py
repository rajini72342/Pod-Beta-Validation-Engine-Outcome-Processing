"""SIEM connector layer for the Validation Engine.

Each connector represents a live telemetry source (Splunk, CrowdStrike
Falcon, Microsoft Sentinel, ...). A connector's job is simply to answer
"what alerts/events do you have that could match this expected
observable?" for a given evidence event and time window.

The Validation Engine fans a single query out to every registered
connector *concurrently* (via asyncio.gather) instead of querying them
one at a time, since each connector call is I/O bound (network round
trip to the SIEM API) and independent of the others.

Connectors here are simulated (deterministic, hash-seeded pseudo-random
telemetry + an artificial network delay) so the engine and its tests do
not depend on live SIEM infrastructure. Swapping in a real connector
only requires implementing the same `query` interface.
"""

from __future__ import annotations

import abc
import asyncio
import hashlib
import random
from datetime import datetime
from typing import List, Optional, Sequence

from .models import MatchedEvent


class SIEMConnector(abc.ABC):
    """Base interface every SIEM connector must implement."""

    #: Short identifier used in rule_id/alert provenance and logging.
    name: str = "base"

    #: Simulated network/query latency range, in seconds. Real
    #: connectors would drop this entirely (latency is whatever the
    #: HTTP call actually takes); it exists here purely so the
    #: "parallel vs. sequential" performance win is observable.
    _latency_range = (0.05, 0.20)

    @abc.abstractmethod
    async def query(
        self,
        *,
        action_id: str,
        technique_ref: str,
        rule_id: str,
        expected_observable: str,
        expected_fields: Sequence[str],
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> List[MatchedEvent]:
        """Return any matching defensive events from this data source."""
        raise NotImplementedError

    async def _simulate_network_delay(self) -> None:
        await asyncio.sleep(random.uniform(*self._latency_range))

    @staticmethod
    def _seed(*parts: str) -> random.Random:
        """A Random instance seeded deterministically from the query
        params, so repeated queries against the same inputs return the
        same simulated telemetry (needed for cache-hit tests)."""
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return random.Random(digest)


class SplunkConnector(SIEMConnector):
    """Simulated Splunk SIEM connector (SPL search over indexed logs)."""

    name = "splunk"

    async def query(
        self,
        *,
        action_id: str,
        technique_ref: str,
        rule_id: str,
        expected_observable: str,
        expected_fields: Sequence[str],
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> List[MatchedEvent]:
        await self._simulate_network_delay()
        rng = self._seed(self.name, action_id, technique_ref, rule_id)
        if rng.random() < 0.15:
            return []
        field_count = rng.randint(1, max(1, len(expected_fields)))
        matched_fields = list(expected_fields[:field_count])
        return [
            MatchedEvent(
                event_id=f"{self.name}-{action_id}-1",
                rule_id=rule_id,
                alert_name=f"Splunk correlation search: {expected_observable[:40]}",
                matched_fields=matched_fields,
                technique_ref_in_alert=technique_ref if rng.random() < 0.8 else None,
                timestamp=window_start,
                raw={"source": self.name, "tenant_id": tenant_id},
            )
        ]


class CrowdStrikeConnector(SIEMConnector):
    """Simulated CrowdStrike Falcon EDR connector."""

    name = "crowdstrike"

    async def query(
        self,
        *,
        action_id: str,
        technique_ref: str,
        rule_id: str,
        expected_observable: str,
        expected_fields: Sequence[str],
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> List[MatchedEvent]:
        await self._simulate_network_delay()
        rng = self._seed(self.name, action_id, technique_ref, rule_id)
        if rng.random() < 0.25:
            return []
        field_count = rng.randint(1, max(1, len(expected_fields)))
        matched_fields = list(expected_fields[:field_count])
        return [
            MatchedEvent(
                event_id=f"{self.name}-{action_id}-1",
                rule_id=rule_id,
                alert_name=f"Falcon detection: {expected_observable[:40]}",
                matched_fields=matched_fields,
                technique_ref_in_alert=technique_ref if rng.random() < 0.7 else None,
                timestamp=window_start,
                raw={"source": self.name, "tenant_id": tenant_id},
            )
        ]


class SentinelConnector(SIEMConnector):
    """Simulated Microsoft Sentinel connector."""

    name = "sentinel"

    async def query(
        self,
        *,
        action_id: str,
        technique_ref: str,
        rule_id: str,
        expected_observable: str,
        expected_fields: Sequence[str],
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> List[MatchedEvent]:
        await self._simulate_network_delay()
        rng = self._seed(self.name, action_id, technique_ref, rule_id)
        if rng.random() < 0.35:
            return []
        field_count = rng.randint(1, max(1, len(expected_fields)))
        matched_fields = list(expected_fields[:field_count])
        return [
            MatchedEvent(
                event_id=f"{self.name}-{action_id}-1",
                rule_id=rule_id,
                alert_name=f"Sentinel analytics rule: {expected_observable[:40]}",
                matched_fields=matched_fields,
                technique_ref_in_alert=technique_ref if rng.random() < 0.6 else None,
                timestamp=window_start,
                raw={"source": self.name, "tenant_id": tenant_id},
            )
        ]


DEFAULT_CONNECTORS: List[SIEMConnector] = [
    SplunkConnector(),
    CrowdStrikeConnector(),
    SentinelConnector(),
]


class MultiSIEMConnector:
    """Fans a single query out to N SIEM connectors concurrently and
    merges the results.

    Using `asyncio.gather` here means the total wall-clock cost of
    querying every connector is bounded by the *slowest single
    connector*, not the sum of all of them - the key win requested for
    "run SIEM connectors in parallel".
    """

    def __init__(self, connectors: Optional[Sequence[SIEMConnector]] = None) -> None:
        if connectors is None:
            connectors = DEFAULT_CONNECTORS
        self.connectors: List[SIEMConnector] = list(connectors)

    async def query_all(
        self,
        *,
        action_id: str,
        technique_ref: str,
        rule_id: str,
        expected_observable: str,
        expected_fields: Sequence[str],
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        tenant_id: Optional[str] = None,
    ) -> List[MatchedEvent]:
        if not self.connectors:
            return []

        results = await asyncio.gather(
            *(
                connector.query(
                    action_id=action_id,
                    technique_ref=technique_ref,
                    rule_id=rule_id,
                    expected_observable=expected_observable,
                    expected_fields=expected_fields,
                    window_start=window_start,
                    window_end=window_end,
                    tenant_id=tenant_id,
                )
                for connector in self.connectors
            ),
            return_exceptions=True,
        )

        merged: List[MatchedEvent] = []
        for connector, result in zip(self.connectors, results):
            if isinstance(result, Exception):
                # A single connector outage should not fail the whole
                # validation - the engine just treats it as "no
                # telemetry from that source" and continues.
                continue
            merged.extend(result)
        return merged
