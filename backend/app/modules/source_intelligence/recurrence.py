"""Detection of recurring behavioral patterns from returning Observed Source Profiles."""

import uuid
from datetime import datetime, timezone
from typing import Sequence
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileRecurrenceModel


DORMANCY_THRESHOLD_SECONDS = 86400  # 24 Hours


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_session_start(s: ActivitySessionModel) -> datetime | None:
    return getattr(s, "first_observed_at", getattr(s, "start_time", None))


def _get_session_end(s: ActivitySessionModel) -> datetime | None:
    return (
        getattr(s, "ended_at", None)
        or getattr(s, "last_activity_at", None)
        or getattr(s, "end_time", None)
        or _get_session_start(s)
    )


def format_duration_display(seconds: int) -> str:
    """Formats seconds into human-readable duration."""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def detect_profile_recurrences(
    profile_id: str,
    sessions: Sequence[ActivitySessionModel],
    dormancy_threshold_seconds: int = DORMANCY_THRESHOLD_SECONDS,
) -> list[SourceProfileRecurrenceModel]:
    """Detects return patterns where a source re-engages after an extended dormant interval."""
    if len(sessions) < 2:
        return []

    # Sort sessions chronologically
    sorted_sessions = sorted(
        sessions,
        key=lambda s: _ensure_utc(_get_session_start(s)) or datetime.min.replace(tzinfo=timezone.utc),
    )

    recurrences: list[SourceProfileRecurrenceModel] = []

    for i in range(1, len(sorted_sessions)):
        prev_s = sorted_sessions[i - 1]
        curr_s = sorted_sessions[i]

        prev_end = _ensure_utc(_get_session_end(prev_s))
        curr_start = _ensure_utc(_get_session_start(curr_s))

        if not prev_end or not curr_start:
            continue

        gap_seconds = int((curr_start - prev_end).total_seconds())

        if gap_seconds >= dormancy_threshold_seconds:
            duration_str = format_duration_display(gap_seconds)
            summary = (
                f"Source reactivated after {duration_str} dormancy. "
                f"Session {curr_s.session_id} targeted {curr_s.decoy_id or 'unknown'} ({curr_s.protocol or 'unknown'})."
            )
            sim_score = 1.0 if prev_s.protocol == curr_s.protocol else 0.7
            if prev_s.decoy_id == curr_s.decoy_id:
                sim_score = min(1.0, sim_score + 0.2)

            rec = SourceProfileRecurrenceModel(
                id=uuid.uuid4(),
                profile_id=profile_id,
                dormant_interval_seconds=gap_seconds,
                dormant_interval_display=duration_str,
                reactivation_at=curr_start,
                reactivation_session_id=curr_s.session_id,
                pattern_similarity=round(sim_score, 2),
                summary=summary,
                created_at=datetime.now(timezone.utc),
            )
            recurrences.append(rec)

    return recurrences
