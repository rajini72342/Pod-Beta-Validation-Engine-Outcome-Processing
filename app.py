"""FastAPI application for the Outcome Classifier service (Pod Beta).

Exposes the core classify endpoint, the batch/cache performance
endpoints, and the four Pod Beta validation-engine features: verdict
aggregation, regulatory control mapping, incremental validation, and
validation result diffing.
"""

from __future__ import annotations

import os
from typing import Dict, List

from fastapi import FastAPI, HTTPException

from .aggregation import VerdictAggregationError, VerdictAggregator
from .cache import QueryCache
from .classifier import OutcomeClassifier
from .diffing import ValidationResultDiffer
from .incremental import IncrementalValidator
from .models import (
    AggregatedVerdict,
    DiffReport,
    IncrementalValidationResult,
    OutcomeVerdict,
    RawValidationResult,
    RegulatoryMappingResult,
)
from .regulatory_mapping import RegulatoryControlMapper
from .siem_connector import MultiSIEMConnector
from .validation_engine import EvidenceEvent, ValidationEngine

app = FastAPI(
    title="Outcome Classifier",
    description="CyBreach Module 2: The Validator - Outcome Classifier Service",
    version="1.1.0",
)

classifier = OutcomeClassifier()

# Validation Engine wiring: Redis-backed query cache (falls back to an
# in-memory cache automatically if REDIS_URL is unset or unreachable),
# fanning out to all configured SIEM connectors in parallel.
_cache = QueryCache(redis_url=os.environ.get("REDIS_URL"))
_connector = MultiSIEMConnector()
validation_engine = ValidationEngine(
    connector=_connector, cache=_cache, classifier=classifier
)

# Pod Beta feature services.
aggregator = VerdictAggregator()
regulatory_mapper = RegulatoryControlMapper()
incremental_validator = IncrementalValidator(engine=validation_engine)
differ = ValidationResultDiffer()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "outcome_classifier"}


@app.post("/classify", response_model=OutcomeVerdict)
async def classify(result: RawValidationResult) -> OutcomeVerdict:
    try:
        return classifier.classify(result)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/validate/batch", response_model=List[OutcomeVerdict])
async def validate_batch(events: List[EvidenceEvent]) -> List[OutcomeVerdict]:
    """Validate and classify a batch of evidence events in a single
    request.

    Every event in the batch is resolved concurrently: cached query
    results are served instantly, and cache misses fan out to all
    SIEM connectors in parallel, so batch latency is governed by the
    slowest individual lookup rather than the sum of all of them.
    """
    if not events:
        return []
    try:
        return await validation_engine.process_batch(events)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/cache/stats")
async def cache_stats() -> dict:
    return {"using_redis": _cache.using_redis, **_cache.stats}


# ---------------------------------------------------------------------------
# Pod Beta: Verdict Aggregation
# ---------------------------------------------------------------------------


@app.post("/verdicts/aggregate", response_model=AggregatedVerdict)
async def aggregate_verdicts(verdicts: List[OutcomeVerdict]) -> AggregatedVerdict:
    """Combine multiple OutcomeVerdicts for the *same* action_id into a
    single AggregatedVerdict representing the overall outcome."""
    try:
        return aggregator.aggregate(verdicts)
    except VerdictAggregationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/verdicts/aggregate/batch", response_model=List[AggregatedVerdict])
async def aggregate_verdicts_batch(
    verdicts: List[OutcomeVerdict],
) -> List[AggregatedVerdict]:
    """Group an arbitrary list of verdicts by action_id and aggregate
    each group independently."""
    try:
        return aggregator.aggregate_many(verdicts)
    except VerdictAggregationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pod Beta: Regulatory Control Mapping
# ---------------------------------------------------------------------------


@app.post("/regulatory/map", response_model=RegulatoryMappingResult)
async def map_verdict_to_controls(verdict: OutcomeVerdict) -> RegulatoryMappingResult:
    """Map a single OutcomeVerdict to its relevant NIST CSF 2.0,
    ISO/IEC 27001:2022, PCI DSS 4.0, and GDPR controls."""
    return regulatory_mapper.map_verdict(verdict)


@app.post("/regulatory/map/batch", response_model=List[RegulatoryMappingResult])
async def map_verdicts_to_controls(
    verdicts: List[OutcomeVerdict],
) -> List[RegulatoryMappingResult]:
    return regulatory_mapper.map_verdicts(verdicts)


# ---------------------------------------------------------------------------
# Pod Beta: Incremental Validation
# ---------------------------------------------------------------------------


@app.post("/validate/incremental", response_model=IncrementalValidationResult)
async def validate_incremental(
    events: List[EvidenceEvent],
    changed_rule_ids: List[str],
    previous_verdicts: Dict[str, OutcomeVerdict],
) -> IncrementalValidationResult:
    """Re-validate only the evidence events affected by `changed_rule_ids`,
    carrying forward `previous_verdicts` for everything else."""
    try:
        return await incremental_validator.revalidate_changed_rules(
            events, changed_rule_ids, previous_verdicts
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pod Beta: Validation Result Diffing
# ---------------------------------------------------------------------------


@app.post("/verdicts/diff", response_model=DiffReport)
async def diff_verdicts(
    old_verdicts: List[OutcomeVerdict], new_verdicts: List[OutcomeVerdict]
) -> DiffReport:
    """Compare an old and new set of OutcomeVerdicts and report which
    action_ids changed verdict, changed confidence, are new, or were
    removed."""
    return differ.diff(old_verdicts, new_verdicts)
