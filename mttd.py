"""Mean Time To Detect (MTTD) computation.

MTTD is the time, in seconds, between the simulated attack execution
(evidence event timestamp) and the first defensive/SIEM alert that
matched the expected observable. It is null/None for Missed and
NoData verdicts, since no matching alert exists to measure against.
"""

from __future__ import annotations

from typing import List, Optional

from .models import MatchedEvent, RawValidationResult


def compute_mttd_seconds(result: RawValidationResult) -> Optional[float]:
    """Compute MTTD in seconds for a validation result.

    Returns None if there is no evidence timestamp, no matched events,
    or no matched event carries a timestamp.
    """
    if result.evidence_timestamp is None or not result.matched_events:
        return None

    first_alert_ts = _earliest_timestamp(result.matched_events)
    if first_alert_ts is None:
        return None

    delta = (first_alert_ts - result.evidence_timestamp).total_seconds()

    # A negative delta would mean the alert fired before the attack was
    # executed, which indicates a timestamp/clock issue rather than a
    # valid detection latency. Guard against reporting nonsensical MTTD.
    if delta < 0:
        return None

    return delta


def _earliest_timestamp(matched_events: List[MatchedEvent]):
    timestamps = [ev.timestamp for ev in matched_events if ev.timestamp is not None]
    if not timestamps:
        return None
    return min(timestamps)
