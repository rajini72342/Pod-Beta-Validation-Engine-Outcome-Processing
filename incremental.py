"""Incremental Validation (Pod Beta, Module 2).

When a detection rule changes, re-running the full evidence dataset
through the Validation Engine is wasteful: only the evidence events
whose rule_id was actually touched by the change can possibly produce
a different verdict. IncrementalValidator re-validates just that
subset and reuses the previously-computed OutcomeVerdict for every
other event untouched by the rule change.

This is deliberately a thin layer on top of ValidationEngine rather
than a new engine: it decides *which* events need to go through
`process_batch` and stitches the re-validated verdicts back together
with the carried-over ones, in the original event order.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Set

from .models import IncrementalValidationResult, OutcomeVerdict
from .validation_engine import EvidenceEvent, ValidationEngine


class IncrementalValidator:
    """Re-validates only the evidence events affected by a set of
    changed detection rules, avoiding a full re-validation pass."""

    def __init__(self, engine: Optional[ValidationEngine] = None) -> None:
        self.engine = engine or ValidationEngine()

    @staticmethod
    def affected_events(
        events: Sequence[EvidenceEvent], changed_rule_ids: Iterable[str]
    ) -> List[EvidenceEvent]:
        """Return the subset of `events` whose rule_id was changed."""
        changed: Set[str] = set(changed_rule_ids)
        return [event for event in events if event.rule_id in changed]

    async def revalidate_changed_rules(
        self,
        events: Sequence[EvidenceEvent],
        changed_rule_ids: Iterable[str],
        previous_verdicts: Dict[str, OutcomeVerdict],
    ) -> IncrementalValidationResult:
        """Re-validate only the evidence events whose rule_id appears in
        `changed_rule_ids`.

        `previous_verdicts` maps action_id -> the OutcomeVerdict from
        the last full/incremental run, and is used to carry forward
        results for every event that was *not* affected by this rule
        change. An event with no entry in `previous_verdicts` is
        treated as never having been validated and is re-validated
        regardless of whether its rule changed, since there is nothing
        to carry forward.
        """
        changed: Set[str] = set(changed_rule_ids)

        to_revalidate: List[EvidenceEvent] = []
        carried_forward: List[OutcomeVerdict] = []
        revalidated_action_ids: List[str] = []
        skipped_action_ids: List[str] = []

        for event in events:
            needs_revalidation = (
                event.rule_id in changed or event.action_id not in previous_verdicts
            )
            if needs_revalidation:
                to_revalidate.append(event)
            else:
                carried_forward.append(previous_verdicts[event.action_id])
                skipped_action_ids.append(event.action_id)

        new_verdicts = await self.engine.process_batch(to_revalidate)
        revalidated_action_ids = [v.action_id for v in new_verdicts]

        # Re-assemble verdicts in the original event order so callers
        # can zip `events` <-> `result.verdicts` positionally.
        verdicts_by_action_id: Dict[str, OutcomeVerdict] = {
            v.action_id: v for v in list(new_verdicts) + carried_forward
        }
        ordered_verdicts = [
            verdicts_by_action_id[event.action_id]
            for event in events
            if event.action_id in verdicts_by_action_id
        ]

        return IncrementalValidationResult(
            changed_rule_ids=sorted(changed),
            revalidated_action_ids=revalidated_action_ids,
            skipped_action_ids=skipped_action_ids,
            verdicts=ordered_verdicts,
        )

    async def close(self) -> None:
        await self.engine.close()
