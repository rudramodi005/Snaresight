"""Configurable Session Correlation Policy and Boundary Rules (Task P21)."""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from app.correlation.schemas import SessionStatus


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class CorrelationPolicy:
    """Manages session boundary rules, timeouts, and state evaluation."""

    DEFAULT_POLICY_VERSION = "1.0"
    DEFAULT_INACTIVITY_TIMEOUT_SECONDS = 1800  # 30 minutes
    DEFAULT_MAX_SESSION_DURATION_SECONDS = 43200  # 12 hours
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 300  # 5 minutes

    def __init__(
        self,
        policy_version: str = DEFAULT_POLICY_VERSION,
        inactivity_timeout_seconds: int = DEFAULT_INACTIVITY_TIMEOUT_SECONDS,
        max_session_duration_seconds: int = DEFAULT_MAX_SESSION_DURATION_SECONDS,
        clock_skew_tolerance_seconds: int = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
    ):
        self.policy_version = policy_version
        self.inactivity_timeout_seconds = inactivity_timeout_seconds
        self.max_session_duration_seconds = max_session_duration_seconds
        self.clock_skew_tolerance_seconds = clock_skew_tolerance_seconds

    def is_event_within_session_boundaries(
        self,
        event_observed_at: datetime,
        session_first_observed: datetime,
        session_last_activity: datetime,
        session_status: str,
    ) -> tuple[bool, str]:
        """Evaluates whether an event falls within allowable temporal bounds of an active session.
        
        Returns:
            (is_admissible, reason)
        """
        # Closed sessions cannot receive regular forward events
        if session_status == SessionStatus.CLOSED.value:
            return False, "Session explicitly closed by prior termination event."

        ev_obs = _ensure_utc(event_observed_at)
        sess_first = _ensure_utc(session_first_observed)
        sess_last = _ensure_utc(session_last_activity)

        # Maximum duration constraint from session inception
        duration_since_start = (ev_obs - sess_first).total_seconds()
        if duration_since_start > self.max_session_duration_seconds:
            return False, f"Event exceeds maximum session duration ({self.max_session_duration_seconds}s)."

        # Inactivity timeout constraint from last activity
        inactivity_gap = (ev_obs - sess_last).total_seconds()
        if inactivity_gap > self.inactivity_timeout_seconds:
            return False, f"Event exceeds inactivity window threshold ({self.inactivity_timeout_seconds}s)."

        # Backward / Late-arriving event check (clock skew)
        if (ev_obs - sess_first).total_seconds() < -self.clock_skew_tolerance_seconds:
            return False, f"Event timestamp precedes session start beyond skew tolerance ({self.clock_skew_tolerance_seconds}s)."

        return True, "Event within active session temporal boundaries."

    def evaluate_session_status(
        self,
        first_observed_at: datetime,
        last_activity_at: datetime,
        ended_at: Optional[datetime],
        current_time: Optional[datetime] = None,
    ) -> SessionStatus:
        """Determines the current lifecycle status based on temporal state."""
        now = _ensure_utc(current_time) or datetime.now(timezone.utc)
        first_obs = _ensure_utc(first_observed_at)
        last_act = _ensure_utc(last_activity_at)
        end_dt = _ensure_utc(ended_at)

        if end_dt is not None:
            return SessionStatus.CLOSED

        duration = (now - first_obs).total_seconds()
        if duration > self.max_session_duration_seconds:
            return SessionStatus.TIMED_OUT

        idle_seconds = (now - last_act).total_seconds()
        if idle_seconds > self.inactivity_timeout_seconds:
            return SessionStatus.IDLE

        return SessionStatus.ACTIVE


# Global default policy
default_correlation_policy = CorrelationPolicy()
