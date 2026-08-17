import pytest

from outcome_classifier.siem_connector import (
    CrowdStrikeConnector,
    MultiSIEMConnector,
    SentinelConnector,
    SplunkConnector,
)


class _FailingConnector:
    name = "failing"

    async def query(self, **kwargs):
        raise RuntimeError("connector is down")


class _StubConnector:
    def __init__(self, name, events):
        self.name = name
        self._events = events

    async def query(self, **kwargs):
        return self._events


QUERY_KWARGS = dict(
    action_id="a1",
    technique_ref="T1486",
    rule_id="rule-1",
    expected_observable="mass file encryption",
    expected_fields=["CommandLine", "Image", "host"],
)


class TestIndividualConnectors:
    @pytest.mark.asyncio
    async def test_splunk_deterministic_for_same_inputs(self):
        c = SplunkConnector()
        r1 = await c.query(**QUERY_KWARGS)
        r2 = await c.query(**QUERY_KWARGS)
        assert [e.event_id for e in r1] == [e.event_id for e in r2]

    @pytest.mark.asyncio
    async def test_crowdstrike_returns_matched_events_or_empty(self):
        c = CrowdStrikeConnector()
        result = await c.query(**QUERY_KWARGS)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_sentinel_events_reference_rule_id(self):
        c = SentinelConnector()
        result = await c.query(**QUERY_KWARGS)
        for event in result:
            assert event.rule_id == "rule-1"


class TestMultiSIEMConnector:
    @pytest.mark.asyncio
    async def test_fans_out_to_all_default_connectors(self):
        multi = MultiSIEMConnector()
        assert len(multi.connectors) == 3

    @pytest.mark.asyncio
    async def test_merges_results_from_all_connectors(self):
        multi = MultiSIEMConnector(
            connectors=[
                _StubConnector("a", [_matched_event("a-1")]),
                _StubConnector("b", [_matched_event("b-1")]),
            ]
        )
        results = await multi.query_all(**QUERY_KWARGS)
        assert {e.event_id for e in results} == {"a-1", "b-1"}

    @pytest.mark.asyncio
    async def test_failing_connector_is_skipped_not_fatal(self):
        multi = MultiSIEMConnector(
            connectors=[_FailingConnector(), _StubConnector("b", [_matched_event("b-1")])]
        )
        results = await multi.query_all(**QUERY_KWARGS)
        assert [e.event_id for e in results] == ["b-1"]

    @pytest.mark.asyncio
    async def test_empty_connector_list_returns_empty(self):
        multi = MultiSIEMConnector(connectors=[])
        results = await multi.query_all(**QUERY_KWARGS)
        assert results == []
        # Regression test for the bug noted in the Pod Beta performance
        # update: an explicit empty list must NOT silently fall back to
        # DEFAULT_CONNECTORS.
        assert multi.connectors == []

    @pytest.mark.asyncio
    async def test_runs_connectors_concurrently(self):
        import time

        multi = MultiSIEMConnector()  # 3 real connectors with simulated delay
        start = time.perf_counter()
        await multi.query_all(**QUERY_KWARGS)
        elapsed = time.perf_counter() - start
        # Sequential worst case would be ~3 * 0.20s = 0.6s; parallel
        # fan-out should stay well under that.
        assert elapsed < 0.5


def _matched_event(event_id: str):
    from outcome_classifier.models import MatchedEvent

    return MatchedEvent(event_id=event_id, matched_fields=["CommandLine"])
