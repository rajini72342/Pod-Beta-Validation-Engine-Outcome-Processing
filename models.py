"""Data models for the Outcome Classifier service."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class VerdictType(str, Enum):
    """The four possible outcomes of a validation run."""

    DETECTED = "Detected"
    MISSED = "Missed"
    PARTIAL = "Partial"
    NO_DATA = "NoData"


class AlertFidelity(str, Enum):
    """How specifically an alert references the underlying technique."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MatchedEvent(BaseModel):
    """A single defensive/SIEM event that matched (fully or partially)
    against the expected observable for an evidence event."""

    event_id: str
    rule_id: Optional[str] = None
    alert_name: Optional[str] = None
    matched_fields: List[str] = Field(default_factory=list)
    technique_ref_in_alert: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw: Dict = Field(default_factory=dict)


class RawValidationResult(BaseModel):
    """The raw output of the Validation Engine, before classification.

    This is the input contract the Outcome Classifier consumes.
    """

    action_id: str
    technique_ref: str
    rule_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    expected_observable: str
    expected_fields: List[str] = Field(default_factory=list)
    matched_events: List[MatchedEvent] = Field(default_factory=list)
    no_data: bool = False
    evidence_timestamp: Optional[datetime] = None
    tenant_id: Optional[str] = None


class CausalStep(BaseModel):
    """A single step in the causal chain explaining a verdict."""

    step_number: int
    description: str
    evidence_ref: Optional[str] = None


class OutcomeVerdict(BaseModel):
    """The final classified outcome for a single evidence event."""

    action_id: str
    technique_ref: str
    rule_id: str
    verdict: VerdictType
    confidence: float = Field(ge=0.0, le=1.0)
    causal_chain: List[CausalStep] = Field(default_factory=list)
    mttd_seconds: Optional[float] = None
    alert_fidelity: Optional[AlertFidelity] = None
    matched_evidence_ref: Optional[str] = None


# ---------------------------------------------------------------------------
# Pod Beta - Validation Engine & Outcome Processing
# ---------------------------------------------------------------------------


class AggregatedVerdict(BaseModel):
    """A single outcome verdict produced by combining multiple
    OutcomeVerdicts for the same action_id (e.g. several rules/runs
    validating the same simulated action)."""

    action_id: str
    technique_ref: str
    verdict: VerdictType
    confidence: float = Field(ge=0.0, le=1.0)
    contributing_rule_ids: List[str] = Field(default_factory=list)
    contributing_verdict_count: int = 0
    causal_chain: List[CausalStep] = Field(default_factory=list)
    mttd_seconds: Optional[float] = None
    alert_fidelity: Optional[AlertFidelity] = None
    matched_evidence_ref: Optional[str] = None
    aggregation_strategy: str = "best-evidence"


class RegulatoryFramework(str, Enum):
    """Regulatory / control frameworks that verdicts are mapped against."""

    NIST_CSF_2_0 = "NIST CSF 2.0"
    ISO_27001_2022 = "ISO/IEC 27001:2022"
    PCI_DSS_4_0 = "PCI DSS 4.0"
    GDPR = "GDPR"


class ControlReference(BaseModel):
    """A single control (or article) within a regulatory framework."""

    framework: RegulatoryFramework
    control_id: str
    control_name: str
    rationale: str


class RegulatoryMappingResult(BaseModel):
    """The set of regulatory controls a given verdict is relevant to."""

    action_id: str
    technique_ref: str
    rule_id: str
    verdict: VerdictType
    controls: List[ControlReference] = Field(default_factory=list)


class IncrementalValidationResult(BaseModel):
    """Result of an incremental (rule-change-scoped) validation run."""

    changed_rule_ids: List[str] = Field(default_factory=list)
    revalidated_action_ids: List[str] = Field(default_factory=list)
    skipped_action_ids: List[str] = Field(default_factory=list)
    verdicts: List[OutcomeVerdict] = Field(default_factory=list)

    @property
    def revalidated_count(self) -> int:
        return len(self.revalidated_action_ids)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_action_ids)


class VerdictDiffType(str, Enum):
    """The kind of change (if any) between an old and new verdict."""

    UNCHANGED = "unchanged"
    VERDICT_CHANGED = "verdict_changed"
    CONFIDENCE_CHANGED = "confidence_changed"
    NEW = "new"
    REMOVED = "removed"


class VerdictDiffEntry(BaseModel):
    """A single action_id's before/after comparison."""

    action_id: str
    diff_type: VerdictDiffType
    old_verdict: Optional[VerdictType] = None
    new_verdict: Optional[VerdictType] = None
    old_confidence: Optional[float] = None
    new_confidence: Optional[float] = None
    details: str


class DiffReport(BaseModel):
    """Summary of comparing an old and new set of OutcomeVerdicts."""

    total_compared: int
    changed_count: int
    unchanged_count: int
    new_count: int
    removed_count: int
    entries: List[VerdictDiffEntry] = Field(default_factory=list)
