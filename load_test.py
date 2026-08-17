#!/usr/bin/env python3
"""Performance load test for the Validation Engine (Pod Beta).

Feeds a configurable number of fake evidence events (default: 1,000)
through the engine end-to-end - parallel SIEM connector fan-out,
Redis/in-memory query caching, batch processing - and reports how fast
the engine responds from start to finish.

Two modes:

in-process (default)
    Talks to a ValidationEngine directly in this process via
    asyncio, in configurable batch sizes. No server needs to be
    running. This isolates engine performance from HTTP overhead.

http
    Sends the same 1,000 events as batched POST requests against a
    *running* instance of the FastAPI app (e.g.
    `uvicorn outcome_classifier.app:app`), exercising the full
    request/response path including caching state shared across
    requests.

Usage:
    python scripts/load_test.py
    python scripts/load_test.py --events 1000 --batch-size 50
    python scripts/load_test.py --mode http --host http://localhost:8003
    python scripts/load_test.py --repeat-fraction 0.3  # simulate cache hits
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from outcome_classifier.validation_engine import EvidenceEvent  # noqa: E402

TECHNIQUES = ["T1486", "T1059", "T1078", "T1105", "T1027", "T1071", "T1053", "T1548"]
FIELD_POOL = ["CommandLine", "Image", "host", "ParentImage", "User", "DestinationIp", "TargetFilename"]
BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def generate_events(count: int, repeat_fraction: float = 0.0) -> List[EvidenceEvent]:
    """Generate `count` fake evidence events. `repeat_fraction` controls
    what fraction of events are exact duplicates of an earlier event
    (same query params), to demonstrate the cache's effect on a
    realistic workload where the same rule/action combination is
    re-validated."""
    rng = random.Random(42)
    events: List[EvidenceEvent] = []
    unique_pool: List[EvidenceEvent] = []
    for i in range(count):
        if unique_pool and rng.random() < repeat_fraction:
            template = rng.choice(unique_pool)
            events.append(template.model_copy())
            continue
        technique = rng.choice(TECHNIQUES)
        fields = rng.sample(FIELD_POOL, k=rng.randint(2, len(FIELD_POOL)))
        event = EvidenceEvent(
            action_id=f"load-action-{i:05d}",
            technique_ref=technique,
            rule_id=f"rule-{technique.lower()}-{rng.randint(1, 5):03d}",
            expected_observable=f"synthetic observable for {technique}",
            expected_fields=fields,
            window_start=BASE_TIME + timedelta(seconds=i),
            window_end=BASE_TIME + timedelta(seconds=i + 300),
            evidence_timestamp=BASE_TIME + timedelta(seconds=i),
            tenant_id="tenant-loadtest",
        )
        events.append(event)
        unique_pool.append(event)
    return events


def chunk(items: List[EvidenceEvent], size: int) -> List[List[EvidenceEvent]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def print_report(label: str, batch_latencies: List[float], total_events: int, total_seconds: float) -> None:
    print(f"\n=== {label} ===")
    print(f"Total events: {total_events}")
    print(f"Total wall time: {total_seconds:.3f}s")
    print(f"Throughput: {total_events / total_seconds:.1f} events/sec")
    if batch_latencies:
        print(f"Batches: {len(batch_latencies)}")
        print(f"Batch latency min: {min(batch_latencies) * 1000:.1f}ms")
        print(f"Batch latency avg: {statistics.mean(batch_latencies) * 1000:.1f}ms")
        if len(batch_latencies) > 1:
            print(f"Batch latency p95: {statistics.quantiles(batch_latencies, n=20)[18] * 1000:.1f}ms")
        print(f"Batch latency max: {max(batch_latencies) * 1000:.1f}ms")


async def run_in_process(events: List[EvidenceEvent], batch_size: int) -> None:
    from outcome_classifier.cache import QueryCache
    from outcome_classifier.classifier import OutcomeClassifier
    from outcome_classifier.siem_connector import MultiSIEMConnector
    from outcome_classifier.validation_engine import ValidationEngine

    engine = ValidationEngine(
        connector=MultiSIEMConnector(),
        cache=QueryCache(),  # in-memory unless REDIS_URL is exported
        classifier=OutcomeClassifier(),
    )
    batches = chunk(events, batch_size)
    batch_latencies: List[float] = []
    start = time.perf_counter()
    for batch in batches:
        batch_start = time.perf_counter()
        verdicts = await engine.process_batch(batch)
        batch_latencies.append(time.perf_counter() - batch_start)
        assert len(verdicts) == len(batch)
    total = time.perf_counter() - start
    print_report(f"In-process (batch_size={batch_size})", batch_latencies, len(events), total)
    print(f"Cache backend: {'redis' if engine.cache.using_redis else 'in-memory'}")
    print(f"Cache stats: {engine.cache.stats}")
    await engine.close()


async def run_http(events: List[EvidenceEvent], batch_size: int, host: str) -> None:
    import httpx

    batches = chunk(events, batch_size)
    batch_latencies: List[float] = []
    async with httpx.AsyncClient(base_url=host, timeout=30.0) as client:
        health = await client.get("/health")
        health.raise_for_status()
        start = time.perf_counter()
        for batch in batches:
            payload = [e.model_dump(mode="json") for e in batch]
            batch_start = time.perf_counter()
            resp = await client.post("/validate/batch", json=payload)
            batch_latencies.append(time.perf_counter() - batch_start)
            resp.raise_for_status()
            assert len(resp.json()) == len(batch)
        total = time.perf_counter() - start
        stats_resp = await client.get("/cache/stats")
    print_report(f"HTTP against {host} (batch_size={batch_size})", batch_latencies, len(events), total)
    if stats_resp.status_code == 200:
        print(f"Cache stats: {stats_resp.json()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", type=int, default=1000, help="Number of fake events to feed (default: 1000)")
    parser.add_argument("--batch-size", type=int, default=50, help="Events per batch request (default: 50)")
    parser.add_argument("--mode", choices=["in-process", "http"], default="in-process")
    parser.add_argument("--host", default="http://localhost:8003", help="Base URL when --mode http")
    parser.add_argument(
        "--repeat-fraction",
        type=float,
        default=0.0,
        help="Fraction (0-1) of events that duplicate an earlier event's query params, to exercise the cache",
    )
    args = parser.parse_args()

    events = generate_events(args.events, repeat_fraction=args.repeat_fraction)
    if args.mode == "in-process":
        asyncio.run(run_in_process(events, args.batch_size))
    else:
        asyncio.run(run_http(events, args.batch_size, args.host))


if __name__ == "__main__":
    main()
