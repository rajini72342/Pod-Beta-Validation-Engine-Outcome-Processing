import pytest

from outcome_classifier.models import OutcomeVerdict, RegulatoryFramework, VerdictType
from outcome_classifier.regulatory_mapping import (
    FROZEN_CONTROL_REGISTRY,
    RegulatoryControlMapper,
    RegulatoryRegistryError,
    validate_registry,
)


def make_verdict(verdict=VerdictType.DETECTED, confidence=0.9):
    return OutcomeVerdict(
        action_id="action-001",
        technique_ref="T1486",
        rule_id="rule-ransomware-001",
        verdict=verdict,
        confidence=confidence,
    )


class TestFrozenRegistryShape:
    def test_registry_passes_validation(self):
        # Should not raise.
        validate_registry(FROZEN_CONTROL_REGISTRY)

    def test_every_verdict_type_present(self):
        for verdict_type in VerdictType:
            assert verdict_type in FROZEN_CONTROL_REGISTRY

    def test_every_framework_present_per_verdict(self):
        for verdict_type, frameworks in FROZEN_CONTROL_REGISTRY.items():
            for framework in RegulatoryFramework:
                assert framework in frameworks
                assert len(frameworks[framework]) >= 1

    def test_missing_framework_fails_validation(self):
        broken = {
            VerdictType.DETECTED: {
                fw: controls
                for fw, controls in FROZEN_CONTROL_REGISTRY[VerdictType.DETECTED].items()
                if fw != RegulatoryFramework.GDPR
            },
            VerdictType.PARTIAL: FROZEN_CONTROL_REGISTRY[VerdictType.PARTIAL],
            VerdictType.MISSED: FROZEN_CONTROL_REGISTRY[VerdictType.MISSED],
            VerdictType.NO_DATA: FROZEN_CONTROL_REGISTRY[VerdictType.NO_DATA],
        }
        with pytest.raises(RegulatoryRegistryError):
            validate_registry(broken)

    def test_missing_verdict_type_fails_validation(self):
        broken = {k: v for k, v in FROZEN_CONTROL_REGISTRY.items() if k != VerdictType.NO_DATA}
        with pytest.raises(RegulatoryRegistryError):
            validate_registry(broken)

    def test_empty_control_list_fails_validation(self):
        broken = dict(FROZEN_CONTROL_REGISTRY)
        broken[VerdictType.DETECTED] = dict(broken[VerdictType.DETECTED])
        broken[VerdictType.DETECTED][RegulatoryFramework.GDPR] = []
        with pytest.raises(RegulatoryRegistryError):
            validate_registry(broken)


class TestRegulatoryControlMapper:
    def test_maps_all_four_frameworks(self):
        mapper = RegulatoryControlMapper()
        result = mapper.map_verdict(make_verdict(VerdictType.DETECTED))
        frameworks_present = {c.framework for c in result.controls}
        assert frameworks_present == set(RegulatoryFramework)

    def test_result_carries_verdict_context(self):
        mapper = RegulatoryControlMapper()
        v = make_verdict(VerdictType.MISSED, confidence=0.1)
        result = mapper.map_verdict(v)
        assert result.action_id == v.action_id
        assert result.technique_ref == v.technique_ref
        assert result.rule_id == v.rule_id
        assert result.verdict == VerdictType.MISSED

    def test_no_data_and_detected_get_different_controls(self):
        mapper = RegulatoryControlMapper()
        detected = mapper.map_verdict(make_verdict(VerdictType.DETECTED))
        no_data = mapper.map_verdict(make_verdict(VerdictType.NO_DATA))
        detected_ids = {(c.framework, c.control_id) for c in detected.controls}
        no_data_ids = {(c.framework, c.control_id) for c in no_data.controls}
        assert detected_ids != no_data_ids

    def test_map_verdicts_batch(self):
        mapper = RegulatoryControlMapper()
        verdicts = [make_verdict(VerdictType.DETECTED), make_verdict(VerdictType.MISSED)]
        results = mapper.map_verdicts(verdicts)
        assert len(results) == 2
        assert results[0].verdict == VerdictType.DETECTED
        assert results[1].verdict == VerdictType.MISSED

    def test_controls_for_framework(self):
        mapper = RegulatoryControlMapper()
        v = make_verdict(VerdictType.DETECTED)
        gdpr_controls = mapper.controls_for_framework(v, RegulatoryFramework.GDPR)
        assert all(c.framework == RegulatoryFramework.GDPR for c in gdpr_controls)
        assert len(gdpr_controls) >= 1

    def test_mapper_rejects_malformed_registry_at_construction(self):
        broken = {k: v for k, v in FROZEN_CONTROL_REGISTRY.items() if k != VerdictType.NO_DATA}
        with pytest.raises(RegulatoryRegistryError):
            RegulatoryControlMapper(registry=broken)
