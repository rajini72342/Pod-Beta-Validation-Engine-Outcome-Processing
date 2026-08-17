"""Regulatory Control Mapping (Pod Beta, Module 2).

Maps each OutcomeVerdict to the relevant controls in four frameworks:
NIST CSF 2.0, ISO/IEC 27001:2022, PCI DSS 4.0, and GDPR.

The mapping is keyed by VerdictType (Detected / Partial / Missed /
NoData) rather than by individual technique: what a Detected vs. a
Missed outcome demonstrates about an organization's monitoring and
detection posture is the same regardless of which technique was being
validated, and that posture is exactly what these controls assess.

FROZEN_CONTROL_REGISTRY is treated as a frozen interface: its shape
(every VerdictType mapped to all four frameworks, each with at least
one control) is validated at import time via validate_registry(), and
again exposed as a callable so tests / CI can assert the registry
hasn't drifted.
"""

from __future__ import annotations

from typing import Dict, List

from .models import (
    ControlReference,
    OutcomeVerdict,
    RegulatoryFramework,
    RegulatoryMappingResult,
    VerdictType,
)

# ---------------------------------------------------------------------------
# Frozen control registry
# ---------------------------------------------------------------------------
# Do not mutate this at runtime - it is the frozen interface every verdict
# is mapped against. Add new frameworks/verdicts by extending this literal
# and re-running validate_registry().

FROZEN_CONTROL_REGISTRY: Dict[VerdictType, Dict[RegulatoryFramework, List[ControlReference]]] = {
    VerdictType.DETECTED: {
        RegulatoryFramework.NIST_CSF_2_0: [
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.CM-01",
                control_name="Networks and network services are monitored",
                rationale="Detection confirms monitoring coverage is effective for this technique.",
            ),
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.AE-02",
                control_name="Detected events are analyzed",
                rationale="A Detected verdict evidences analyzed, actionable alerting.",
            ),
        ],
        RegulatoryFramework.ISO_27001_2022: [
            ControlReference(
                framework=RegulatoryFramework.ISO_27001_2022,
                control_id="A.8.16",
                control_name="Monitoring activities",
                rationale="Successful detection demonstrates operating monitoring controls.",
            ),
        ],
        RegulatoryFramework.PCI_DSS_4_0: [
            ControlReference(
                framework=RegulatoryFramework.PCI_DSS_4_0,
                control_id="10.2.1",
                control_name="Audit logs capture user and system activity",
                rationale="Detection relies on audit logging that satisfies logging requirements.",
            ),
            ControlReference(
                framework=RegulatoryFramework.PCI_DSS_4_0,
                control_id="10.4.1",
                control_name="Audit logs are reviewed to identify anomalies",
                rationale="A firing detection rule is evidence of active log review/alerting.",
            ),
        ],
        RegulatoryFramework.GDPR: [
            ControlReference(
                framework=RegulatoryFramework.GDPR,
                control_id="Art. 33",
                control_name="Notification of a personal data breach to the supervisory authority",
                rationale="Timely detection supports meeting the 72-hour breach notification window.",
            ),
        ],
    },
    VerdictType.PARTIAL: {
        RegulatoryFramework.NIST_CSF_2_0: [
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.CM-01",
                control_name="Networks and network services are monitored",
                rationale="Partial coverage indicates monitoring exists but is incomplete for this technique.",
            ),
        ],
        RegulatoryFramework.ISO_27001_2022: [
            ControlReference(
                framework=RegulatoryFramework.ISO_27001_2022,
                control_id="A.8.16",
                control_name="Monitoring activities",
                rationale="Partial match indicates monitoring scope should be reviewed and tuned.",
            ),
        ],
        RegulatoryFramework.PCI_DSS_4_0: [
            ControlReference(
                framework=RegulatoryFramework.PCI_DSS_4_0,
                control_id="10.4.1",
                control_name="Audit logs are reviewed to identify anomalies",
                rationale="Partial coverage flags a log-review gap worth tuning before it becomes a Missed.",
            ),
        ],
        RegulatoryFramework.GDPR: [
            ControlReference(
                framework=RegulatoryFramework.GDPR,
                control_id="Art. 32",
                control_name="Security of processing",
                rationale="Incomplete detection coverage is a gap in appropriate technical measures.",
            ),
        ],
    },
    VerdictType.MISSED: {
        RegulatoryFramework.NIST_CSF_2_0: [
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.CM-01",
                control_name="Networks and network services are monitored",
                rationale="A Missed verdict is a monitoring-coverage gap against this control.",
            ),
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.AE-02",
                control_name="Detected events are analyzed",
                rationale="No alert fired, so no event was available to analyze - a detection-engineering gap.",
            ),
        ],
        RegulatoryFramework.ISO_27001_2022: [
            ControlReference(
                framework=RegulatoryFramework.ISO_27001_2022,
                control_id="A.8.16",
                control_name="Monitoring activities",
                rationale="Missed detection is a nonconformity against operating monitoring controls.",
            ),
        ],
        RegulatoryFramework.PCI_DSS_4_0: [
            ControlReference(
                framework=RegulatoryFramework.PCI_DSS_4_0,
                control_id="10.4.1",
                control_name="Audit logs are reviewed to identify anomalies",
                rationale="Missed detection indicates the review/alerting process did not surface this activity.",
            ),
        ],
        RegulatoryFramework.GDPR: [
            ControlReference(
                framework=RegulatoryFramework.GDPR,
                control_id="Art. 33",
                control_name="Notification of a personal data breach to the supervisory authority",
                rationale="Undetected activity threatens the ability to meet breach-notification timelines.",
            ),
        ],
    },
    VerdictType.NO_DATA: {
        RegulatoryFramework.NIST_CSF_2_0: [
            ControlReference(
                framework=RegulatoryFramework.NIST_CSF_2_0,
                control_id="DE.CM-01",
                control_name="Networks and network services are monitored",
                rationale="No telemetry was available at all - a coverage gap upstream of detection logic.",
            ),
        ],
        RegulatoryFramework.ISO_27001_2022: [
            ControlReference(
                framework=RegulatoryFramework.ISO_27001_2022,
                control_id="A.8.16",
                control_name="Monitoring activities",
                rationale="Absent telemetry means the monitoring scope does not currently cover this source.",
            ),
        ],
        RegulatoryFramework.PCI_DSS_4_0: [
            ControlReference(
                framework=RegulatoryFramework.PCI_DSS_4_0,
                control_id="10.2.1",
                control_name="Audit logs capture user and system activity",
                rationale="No matching telemetry suggests required audit logging is not being captured here.",
            ),
        ],
        RegulatoryFramework.GDPR: [
            ControlReference(
                framework=RegulatoryFramework.GDPR,
                control_id="Art. 32",
                control_name="Security of processing",
                rationale="Missing telemetry is a gap in the technical measures needed to assess risk.",
            ),
        ],
    },
}


class RegulatoryRegistryError(ValueError):
    """Raised when FROZEN_CONTROL_REGISTRY fails its shape validation."""


def validate_registry(
    registry: Dict[VerdictType, Dict[RegulatoryFramework, List[ControlReference]]]
    = FROZEN_CONTROL_REGISTRY,
) -> None:
    """Validate the frozen control registry's interface contract:
    every VerdictType must map to all four frameworks, and every
    framework must carry at least one control. Raises
    RegulatoryRegistryError on any violation."""
    missing_verdicts = [v for v in VerdictType if v not in registry]
    if missing_verdicts:
        raise RegulatoryRegistryError(
            f"Registry is missing VerdictType entries: {missing_verdicts}"
        )

    for verdict_type, frameworks in registry.items():
        missing_frameworks = [f for f in RegulatoryFramework if f not in frameworks]
        if missing_frameworks:
            raise RegulatoryRegistryError(
                f"Registry entry for {verdict_type} is missing frameworks: {missing_frameworks}"
            )
        for framework, controls in frameworks.items():
            if not controls:
                raise RegulatoryRegistryError(
                    f"Registry entry for {verdict_type}/{framework} has no controls"
                )
            for control in controls:
                if control.framework != framework:
                    raise RegulatoryRegistryError(
                        f"Control {control.control_id} filed under {framework} but "
                        f"declares framework={control.framework}"
                    )


# Validate at import time so a malformed registry fails fast, at import,
# rather than surfacing as a confusing KeyError deep in a validation run.
validate_registry()


class RegulatoryControlMapper:
    """Maps OutcomeVerdicts to the relevant controls across all four
    regulatory frameworks using the frozen control registry."""

    def __init__(
        self,
        registry: Dict[VerdictType, Dict[RegulatoryFramework, List[ControlReference]]]
        = None,
    ) -> None:
        self.registry = registry if registry is not None else FROZEN_CONTROL_REGISTRY
        validate_registry(self.registry)

    def map_verdict(self, verdict: OutcomeVerdict) -> RegulatoryMappingResult:
        frameworks = self.registry.get(verdict.verdict, {})
        controls: List[ControlReference] = []
        for framework in RegulatoryFramework:
            controls.extend(frameworks.get(framework, []))

        return RegulatoryMappingResult(
            action_id=verdict.action_id,
            technique_ref=verdict.technique_ref,
            rule_id=verdict.rule_id,
            verdict=verdict.verdict,
            controls=controls,
        )

    def map_verdicts(
        self, verdicts: List[OutcomeVerdict]
    ) -> List[RegulatoryMappingResult]:
        return [self.map_verdict(v) for v in verdicts]

    def controls_for_framework(
        self, verdict: OutcomeVerdict, framework: RegulatoryFramework
    ) -> List[ControlReference]:
        return list(self.registry.get(verdict.verdict, {}).get(framework, []))
