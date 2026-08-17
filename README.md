# Pod-Beta-Validation-Engine-Outcome-Processing
# The Validator: Outcome Classifier (Pod Beta)

CyBreach Module 2: The Validator - Outcome Classifier & Validation Engine microservice.

Converts raw validation results (rule execution vs. evidence) into
classified verdicts, per section 3.4 of the Module 2 Technical Doc,
then runs those verdicts through a full validation-engine pipeline:
batched/parallel/cached SIEM querying, cross-rule verdict aggregation,
regulatory control mapping, incremental re-validation, and result
diffing.

## What it does

**Outcome Classifier (core)**
- **Verdict classification** - turns a `RawValidationResult` into one of
  four verdicts: `Detected`, `Missed`, `Partial`, `NoData`.
- **Causal chain analysis** - builds a deterministic, step-by-step
  reasoning trail explaining why a verdict was assigned.
- **Alert fidelity assessment** - classifies `Detected`/`Partial` alerts
  as `high`, `medium`, or `low` fidelity based on technique specificity
  and expected-field coverage.
- **MTTD computation** - measures Mean Time To Detect (seconds) between
  the simulated attack (evidence timestamp) and the first matching
  alert.

**Validation Engine (performance layer)**
- **Batch requests** - `process_batch()` / `POST /validate/batch` resolve
  a list of evidence events concurrently via `asyncio.gather` instead of
  one at a time.
- **Query result caching** - `QueryCache` is a TTL-based cache keyed by
  query params, backed by Redis (`REDIS_URL`) with an automatic
  in-memory fallback. Cache failures fail open as a miss.
- **Parallel SIEM connector fan-out** - `MultiSIEMConnector` queries
  Splunk, CrowdStrike Falcon, and Microsoft Sentinel connectors
  concurrently; total latency is bounded by the slowest connector, and a
  failing connector is skipped rather than failing the whole query.
- **Load testing** - `scripts/load_test.py` feeds a configurable number
  of synthetic evidence events through the engine and reports
  throughput and batch-latency percentiles, in-process or over HTTP.

**Pod Beta: Validation Engine & Outcome Processing**
- **Verdict aggregation** - `VerdictAggregator` combines multiple
  `OutcomeVerdict`s for the same `action_id` into one `AggregatedVerdict`
  using a best-evidence strategy (`Detected` > `Partial` > `Missed` >
  `NoData`, ties broken by confidence), with merged/renumbered causal
  chains and de-duplicated contributing rule IDs.
- **Regulatory control mapping** - `RegulatoryControlMapper` maps every
  verdict to relevant controls across **NIST CSF 2.0**, **ISO/IEC
  27001:2022**, **PCI DSS 4.0**, and **GDPR**, validated against a
  frozen control registry interface (`validate_registry()`).
- **Incremental validation** - `IncrementalValidator` re-validates only
  the evidence events affected by a changed detection rule, carrying
  forward previous verdicts for everything else instead of re-running
  the full dataset.
- **Validation result diffing** - `ValidationResultDiffer` compares an
  old and new set of verdicts and reports which action IDs changed
  verdict, changed confidence, are new, or were removed.

## Classification thresholds

| Verdict  | Confidence range | Notes                                   |
|----------|-------------------|------------------------------------------|
| Detected | 0.7 - 1.0         | Rule fired, evidence matched expectation |
| Partial  | 0.3 - 0.6         | Some but not all observables matched     |
| Missed   | 0.0 - 0.2         | No matching evidence found               |
| NoData   | N/A               | `no_data=True` always takes precedence   |

## Verdict aggregation precedence

| Priority | Verdict  | Rationale                                              |
|----------|----------|---------------------------------------------------------|
| 1 (best) | Detected | Strongest evidence of coverage                          |
| 2        | Partial  | Some observable coverage                                 |
| 3        | Missed   | Telemetry existed but nothing matched                    |
| 4        | NoData   | No telemetry was available at all - least informative    |

Ties within the winning verdict type are broken by highest confidence.

## Project layout

```
outcome_classifier/
  __init__.py
  models.py             # Pydantic models (RawValidationResult, OutcomeVerdict,
                         #   AggregatedVerdict, RegulatoryMappingResult,
                         #   IncrementalValidationResult, DiffReport, ...)
  classifier.py          # OutcomeClassifier - verdict thresholds & orchestration
  causal_chain.py         # CausalChainBuilder - step-by-step reasoning
  fidelity.py              # FidelityAssessor - high/medium/low fidelity scoring
  mttd.py                   # compute_mttd_seconds - MTTD calculation
  cache.py                   # QueryCache - Redis-backed / in-memory TTL cache
  siem_connector.py           # SIEMConnector impls + MultiSIEMConnector fan-out
  validation_engine.py         # ValidationEngine - batching, caching, classification
  aggregation.py                 # VerdictAggregator - best-evidence aggregation
  regulatory_mapping.py           # FROZEN_CONTROL_REGISTRY + RegulatoryControlMapper
  incremental.py                   # IncrementalValidator - rule-change-scoped re-validation
  diffing.py                        # ValidationResultDiffer - old vs new verdict comparison
  app.py                             # FastAPI wrapper (see Endpoints below)
scripts/
  load_test.py                       # Performance load test (1,000+ synthetic events)
tests/
  conftest.py                         # shared fixtures
  test_classifier.py
  test_causal_chain.py
  test_fidelity.py
  test_mttd.py
  test_cache.py
  test_siem_connector.py
  test_validation_engine.py
  test_aggregation.py
  test_regulatory_mapping.py
  test_incremental.py
  test_diffing.py
  test_app.py
```

## Local setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the full test suite with coverage
pytest --cov=outcome_classifier --cov-report=term-missing

# Run the service locally
uvicorn outcome_classifier.app:app --reload --port 8003
curl http://localhost:8003/health

# Optional: point at a real Redis instance for the query cache
export REDIS_URL=redis://localhost:6379/0

# Load test (in-process, no server needed)
python scripts/load_test.py --events 1000 --batch-size 50 --repeat-fraction 0.4
```

## Endpoints

| Method | Path                        | Description                                                              |
|--------|------------------------------|----------------------------------------------------------------------------|
| GET    | `/health`                    | Liveness check                                                            |
| POST   | `/classify`                  | Classify a single `RawValidationResult`                                  |
| POST   | `/validate/batch`             | Validate + classify a batch of `EvidenceEvent`s concurrently             |
| GET    | `/cache/stats`                 | Query cache hit/miss counters and active backend (`redis`/`in-memory`)   |
| POST   | `/verdicts/aggregate`           | Aggregate verdicts sharing one `action_id` into an `AggregatedVerdict`   |
| POST   | `/verdicts/aggregate/batch`      | Group verdicts by `action_id` and aggregate each group                   |
| POST   | `/regulatory/map`                 | Map a verdict to NIST CSF 2.0 / ISO 27001:2022 / PCI DSS 4.0 / GDPR controls |
| POST   | `/regulatory/map/batch`            | Map a list of verdicts to controls in one call                           |
| POST   | `/validate/incremental`             | Re-validate only events affected by `changed_rule_ids`                   |
| POST   | `/verdicts/diff`                     | Compare an old and new set of verdicts and return a `DiffReport`         |

## Example usage (library)

```python
from datetime import datetime, timezone
from outcome_classifier import OutcomeClassifier, RawValidationResult, MatchedEvent

result = RawValidationResult(
    action_id="action-001",
    technique_ref="T1486",
    rule_id="rule-ransomware-001",
    confidence=0.95,
    expected_observable="mass file encryption via vssadmin/wbadmin",
    expected_fields=["CommandLine", "Image", "host"],
    matched_events=[
        MatchedEvent(
            event_id="evt-001",
            matched_fields=["CommandLine", "Image", "host"],
            technique_ref_in_alert="T1486",
            timestamp=datetime(2026, 6, 1, 12, 0, 42, tzinfo=timezone.utc),
        )
    ],
    evidence_timestamp=datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
)

verdict = OutcomeClassifier().classify(result)
print(verdict.verdict)          # VerdictType.DETECTED
print(verdict.alert_fidelity)   # AlertFidelity.HIGH
print(verdict.mttd_seconds)     # 42.0
```

## Example usage (Pod Beta features)

```python
from outcome_classifier import (
    VerdictAggregator, RegulatoryControlMapper,
    IncrementalValidator, ValidationResultDiffer, ValidationEngine,
)

# 1. Aggregate multiple verdicts for the same action into one outcome
aggregated = VerdictAggregator().aggregate([verdict_a, verdict_b])

# 2. Map a verdict to relevant regulatory controls
mapping = RegulatoryControlMapper().map_verdict(verdict)
for control in mapping.controls:
    print(control.framework, control.control_id, control.control_name)

# 3. Re-validate only events affected by a rule change
incremental = IncrementalValidator(engine=ValidationEngine())
result = await incremental.revalidate_changed_rules(
    events, changed_rule_ids=["rule-ransomware-001"], previous_verdicts=prior_by_action_id,
)

# 4. Diff an old and new verdict set
report = ValidationResultDiffer().diff(old_verdicts, new_verdicts)
print(report.changed_count, "action(s) changed")
```

## Contract notes

- Input (`RawValidationResult`) is what Pod Beta's Validation Engine
  produces internally; it is not the published Module 2 contract.
- Output (`OutcomeVerdict`) maps onto the published Verdict Schema
  fields (`verdict`, `confidence`, `mttd`, `causal_chain`,
  `matched_evidence_ref`) that the Verdict Publisher consumes before
  emitting immutable events to `cybreach.verdicts.v2`.
- `FROZEN_CONTROL_REGISTRY` in `regulatory_mapping.py` is treated as a
  frozen interface: it is validated for shape (every `VerdictType`
  mapped to all four frameworks, each with at least one control) at
  import time via `validate_registry()`. Extend it by adding entries
  and re-running the validator - don't mutate it at runtime.
