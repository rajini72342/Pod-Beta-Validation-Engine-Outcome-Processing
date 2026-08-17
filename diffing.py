"""Validation Result Diffing (Pod Beta, Module 2).

Compares an old and a new set of OutcomeVerdicts (typically: before
and after a rule change, or before and after an incremental
re-validation) and reports what changed: which action_ids flipped
verdict, which only had their confidence shift, which are newly
present, and which disappeared.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from .models import DiffReport, OutcomeVerdict, VerdictDiffEntry, VerdictDiffType

# Confidence differences at or below this are treated as noise, not a
# meaningful change, so tiny floating-point drift doesn't get flagged.
DEFAULT_CONFIDENCE_EPSILON = 1e-6


class ValidationResultDiffer:
    """Diffs two sets of OutcomeVerdicts keyed by action_id."""

    def __init__(self, confidence_epsilon: float = DEFAULT_CONFIDENCE_EPSILON) -> None:
        self.confidence_epsilon = confidence_epsilon

    def diff(
        self,
        old_verdicts: Sequence[OutcomeVerdict],
        new_verdicts: Sequence[OutcomeVerdict],
    ) -> DiffReport:
        old_by_id: Dict[str, OutcomeVerdict] = {v.action_id: v for v in old_verdicts}
        new_by_id: Dict[str, OutcomeVerdict] = {v.action_id: v for v in new_verdicts}

        # Preserve a stable order: everything from the old run first (in
        # its original order), then any brand-new action_ids from the
        # new run that weren't present before.
        ordered_action_ids: List[str] = [v.action_id for v in old_verdicts]
        for v in new_verdicts:
            if v.action_id not in old_by_id:
                ordered_action_ids.append(v.action_id)

        entries: List[VerdictDiffEntry] = []
        for action_id in ordered_action_ids:
            old_v = old_by_id.get(action_id)
            new_v = new_by_id.get(action_id)
            entries.append(self._diff_one(action_id, old_v, new_v))

        changed_count = sum(
            1
            for e in entries
            if e.diff_type
            in (
                VerdictDiffType.VERDICT_CHANGED,
                VerdictDiffType.CONFIDENCE_CHANGED,
                VerdictDiffType.NEW,
                VerdictDiffType.REMOVED,
            )
        )
        unchanged_count = sum(1 for e in entries if e.diff_type == VerdictDiffType.UNCHANGED)
        new_count = sum(1 for e in entries if e.diff_type == VerdictDiffType.NEW)
        removed_count = sum(1 for e in entries if e.diff_type == VerdictDiffType.REMOVED)

        return DiffReport(
            total_compared=len(entries),
            changed_count=changed_count,
            unchanged_count=unchanged_count,
            new_count=new_count,
            removed_count=removed_count,
            entries=entries,
        )

    def _diff_one(
        self,
        action_id: str,
        old_v: OutcomeVerdict | None,
        new_v: OutcomeVerdict | None,
    ) -> VerdictDiffEntry:
        if old_v is None and new_v is not None:
            return VerdictDiffEntry(
                action_id=action_id,
                diff_type=VerdictDiffType.NEW,
                old_verdict=None,
                new_verdict=new_v.verdict,
                old_confidence=None,
                new_confidence=new_v.confidence,
                details=f"'{action_id}' first appears in the new result set as {new_v.verdict.value}.",
            )

        if old_v is not None and new_v is None:
            return VerdictDiffEntry(
                action_id=action_id,
                diff_type=VerdictDiffType.REMOVED,
                old_verdict=old_v.verdict,
                new_verdict=None,
                old_confidence=old_v.confidence,
                new_confidence=None,
                details=f"'{action_id}' was {old_v.verdict.value} but is absent from the new result set.",
            )

        # Both present.
        assert old_v is not None and new_v is not None
        if old_v.verdict != new_v.verdict:
            return VerdictDiffEntry(
                action_id=action_id,
                diff_type=VerdictDiffType.VERDICT_CHANGED,
                old_verdict=old_v.verdict,
                new_verdict=new_v.verdict,
                old_confidence=old_v.confidence,
                new_confidence=new_v.confidence,
                details=(
                    f"'{action_id}' changed from {old_v.verdict.value} "
                    f"to {new_v.verdict.value}."
                ),
            )

        if abs(old_v.confidence - new_v.confidence) > self.confidence_epsilon:
            return VerdictDiffEntry(
                action_id=action_id,
                diff_type=VerdictDiffType.CONFIDENCE_CHANGED,
                old_verdict=old_v.verdict,
                new_verdict=new_v.verdict,
                old_confidence=old_v.confidence,
                new_confidence=new_v.confidence,
                details=(
                    f"'{action_id}' stayed {old_v.verdict.value} but confidence moved "
                    f"from {old_v.confidence} to {new_v.confidence}."
                ),
            )

        return VerdictDiffEntry(
            action_id=action_id,
            diff_type=VerdictDiffType.UNCHANGED,
            old_verdict=old_v.verdict,
            new_verdict=new_v.verdict,
            old_confidence=old_v.confidence,
            new_confidence=new_v.confidence,
            details=f"'{action_id}' unchanged: {old_v.verdict.value} @ {old_v.confidence}.",
        )
