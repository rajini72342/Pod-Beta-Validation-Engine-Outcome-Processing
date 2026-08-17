import pytest
from httpx import ASGITransport, AsyncClient

from outcome_classifier.app import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


RAW_RESULT_DETECTED = {
    "action_id": "action-001",
    "technique_ref": "T1486",
    "rule_id": "rule-ransomware-001",
    "confidence": 0.95,
    "expected_observable": "mass file encryption via vssadmin/wbadmin",
    "expected_fields": ["CommandLine", "Image", "host"],
    "matched_events": [
        {
            "event_id": "evt-001",
            "rule_id": "rule-ransomware-001",
            "matched_fields": ["CommandLine", "Image", "host"],
            "technique_ref_in_alert": "T1486",
        }
    ],
    "no_data": False,
}


def make_verdict_payload(action_id, verdict="Detected", confidence=0.9, rule_id="rule-a"):
    return {
        "action_id": action_id,
        "technique_ref": "T1486",
        "rule_id": rule_id,
        "verdict": verdict,
        "confidence": confidence,
        "causal_chain": [],
    }


class TestHealthAndClassify:
    @pytest.mark.asyncio
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_classify_detected(self, client):
        resp = await client.post("/classify", json=RAW_RESULT_DETECTED)
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "Detected"


class TestBatchAndCache:
    @pytest.mark.asyncio
    async def test_validate_batch_empty(self, client):
        resp = await client.post("/validate/batch", json=[])
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_validate_batch_returns_verdict_per_event(self, client):
        event = {
            "action_id": "batch-a1",
            "technique_ref": "T1486",
            "rule_id": "rule-1",
            "expected_observable": "mass file encryption",
            "expected_fields": ["CommandLine"],
        }
        resp = await client.post("/validate/batch", json=[event])
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["action_id"] == "batch-a1"

    @pytest.mark.asyncio
    async def test_cache_stats_endpoint(self, client):
        resp = await client.get("/cache/stats")
        assert resp.status_code == 200
        assert "using_redis" in resp.json()


class TestAggregationEndpoint:
    @pytest.mark.asyncio
    async def test_aggregate_single_action(self, client):
        payload = [
            make_verdict_payload("action-001", "Detected", 0.9, "rule-a"),
            make_verdict_payload("action-001", "Missed", 0.1, "rule-b"),
        ]
        resp = await client.post("/verdicts/aggregate", json=payload)
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "Detected"

    @pytest.mark.asyncio
    async def test_aggregate_rejects_empty(self, client):
        resp = await client.post("/verdicts/aggregate", json=[])
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_aggregate_batch_groups_by_action(self, client):
        payload = [
            make_verdict_payload("action-001", "Detected", 0.9, "rule-a"),
            make_verdict_payload("action-002", "NoData", 0.0, "rule-c"),
        ]
        resp = await client.post("/verdicts/aggregate/batch", json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2


class TestRegulatoryEndpoint:
    @pytest.mark.asyncio
    async def test_map_single_verdict(self, client):
        resp = await client.post(
            "/regulatory/map", json=make_verdict_payload("action-001")
        )
        assert resp.status_code == 200
        controls = resp.json()["controls"]
        frameworks = {c["framework"] for c in controls}
        assert "GDPR" in frameworks
        assert "PCI DSS 4.0" in frameworks

    @pytest.mark.asyncio
    async def test_map_batch(self, client):
        payload = [
            make_verdict_payload("action-001", "Detected"),
            make_verdict_payload("action-002", "Missed"),
        ]
        resp = await client.post("/regulatory/map/batch", json=payload)
        assert resp.status_code == 200
        assert len(resp.json()) == 2


class TestIncrementalEndpoint:
    @pytest.mark.asyncio
    async def test_incremental_validation(self, client):
        payload = {
            "events": [
                {
                    "action_id": "action-001",
                    "technique_ref": "T1486",
                    "rule_id": "rule-a",
                    "expected_observable": "mass file encryption",
                    "expected_fields": ["CommandLine"],
                }
            ],
            "changed_rule_ids": ["rule-a"],
            "previous_verdicts": {},
        }
        resp = await client.post("/validate/incremental", json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert body["revalidated_action_ids"] == ["action-001"]


class TestDiffEndpoint:
    @pytest.mark.asyncio
    async def test_diff_endpoint(self, client):
        payload = {
            "old_verdicts": [make_verdict_payload("action-001", "Missed", 0.1)],
            "new_verdicts": [make_verdict_payload("action-001", "Detected", 0.9)],
        }
        resp = await client.post("/verdicts/diff", json=payload)
        assert resp.status_code == 200
        body = resp.json()
        assert body["changed_count"] == 1
        assert body["entries"][0]["diff_type"] == "verdict_changed"
