"""
Outcome Classifier Service (Pod Beta)
CyBreach Module 2: The Validator

Converts raw validation results (rule execution vs. evidence) into
classified verdicts (Detected / Missed / Partial / NoData), with
causal chain reasoning, alert fidelity assessment, and MTTD computation.

Pod Beta additionally adds: verdict aggregation across multiple
verdicts for the same action, regulatory control mapping (NIST CSF
2.0, ISO/IEC 27001:2022, PCI DSS 4.0, GDPR), incremental validation
scoped to changed detection rules, and validation result diffing.
"""

from .models import (
    VerdictType,
    AlertFidelity,
    CausalStep,
    RawValidationResult,
    MatchedEvent,
    OutcomeVerdict,
    AggregatedVerdict,
    RegulatoryFramework,
    ControlReference,
    RegulatoryMappingResult,
    IncrementalValidationResult,
    VerdictDiffType,
    VerdictDiffEntry,
    DiffReport,
)
from .classifier import OutcomeClassifier
from .causal_chain import CausalChainBuilder
from .fidelity import FidelityAssessor
from .mttd import compute_mttd_seconds
from .cache import QueryCache
from .siem_connector import (
    MultiSIEMConnector,
    SIEMConnector,
    SplunkConnector,
    CrowdStrikeConnector,
    SentinelConnector,
)
from .validation_engine import EvidenceEvent, ValidationEngine
from .aggregation import VerdictAggregator, VerdictAggregationError
from .regulatory_mapping import (
    RegulatoryControlMapper,
    RegulatoryRegistryError,
    FROZEN_CONTROL_REGISTRY,
    validate_registry,
)
from .incremental import IncrementalValidator
from .diffing import ValidationResultDiffer

__all__ = [
    "VerdictType",
    "AlertFidelity",
    "CausalStep",
    "RawValidationResult",
    "MatchedEvent",
    "OutcomeVerdict",
    "OutcomeClassifier",
    "CausalChainBuilder",
    "FidelityAssessor",
    "compute_mttd_seconds",
    "QueryCache",
    "MultiSIEMConnector",
    "SIEMConnector",
    "SplunkConnector",
    "CrowdStrikeConnector",
    "SentinelConnector",
    "EvidenceEvent",
    "ValidationEngine",
    # Pod Beta
    "AggregatedVerdict",
    "VerdictAggregator",
    "VerdictAggregationError",
    "RegulatoryFramework",
    "ControlReference",
    "RegulatoryMappingResult",
    "RegulatoryControlMapper",
    "RegulatoryRegistryError",
    "FROZEN_CONTROL_REGISTRY",
    "validate_registry",
    "IncrementalValidationResult",
    "IncrementalValidator",
    "VerdictDiffType",
    "VerdictDiffEntry",
    "DiffReport",
    "ValidationResultDiffer",
]
