"""Unit tests for CorrelationPolicy and Session Boundary Rules (Task P21)."""

import unittest
from datetime import datetime, timezone, timedelta
from app.correlation.policy import CorrelationPolicy
from app.correlation.schemas import SessionStatus


class TestCorrelationPolicy(unittest.TestCase):
    """Verifies temporal boundary logic, inactivity timeouts, and max duration constraints."""

    def setUp(self):
        self.policy = CorrelationPolicy(
            policy_version="1.0",
            inactivity_timeout_seconds=1800,  # 30 min
            max_session_duration_seconds=43200,  # 12 hours
            clock_skew_tolerance_seconds=300,  # 5 min
        )
        self.t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)

    def test_event_within_normal_boundaries(self):
        """Event occurring 5 minutes after last activity is within boundaries."""
        t1 = self.t0 + timedelta(minutes=5)
        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t1,
            session_first_observed=self.t0,
            session_last_activity=self.t0,
            session_status=SessionStatus.ACTIVE.value,
        )
        self.assertTrue(admissible)
        self.assertIn("within active session", reason)

    def test_inactivity_timeout_exceeded(self):
        """Event arriving after 31 minutes of silence exceeds inactivity threshold."""
        t_late = self.t0 + timedelta(seconds=1801)
        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t_late,
            session_first_observed=self.t0,
            session_last_activity=self.t0,
            session_status=SessionStatus.ACTIVE.value,
        )
        self.assertFalse(admissible)
        self.assertIn("inactivity window threshold", reason)

    def test_max_session_duration_exceeded(self):
        """Event arriving after 12 hours + 1 second exceeds max session duration."""
        # Active events happened recently, but total session time exceeds 12h
        t_start = self.t0
        t_last = self.t0 + timedelta(hours=11, minutes=59)
        t_event = self.t0 + timedelta(hours=12, seconds=1)

        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t_event,
            session_first_observed=t_start,
            session_last_activity=t_last,
            session_status=SessionStatus.ACTIVE.value,
        )
        self.assertFalse(admissible)
        self.assertIn("maximum session duration", reason)

    def test_closed_session_rejects_new_events(self):
        """A closed session rejects incoming forward events."""
        t_next = self.t0 + timedelta(minutes=1)
        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t_next,
            session_first_observed=self.t0,
            session_last_activity=self.t0,
            session_status=SessionStatus.CLOSED.value,
        )
        self.assertFalse(admissible)
        self.assertIn("explicitly closed", reason)

    def test_clock_skew_tolerance_acceptable(self):
        """Event timestamp slightly preceding session start within 300s is allowed (late arrival)."""
        t_skewed = self.t0 - timedelta(seconds=120)  # 2 minutes prior, within 5 min tolerance
        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t_skewed,
            session_first_observed=self.t0,
            session_last_activity=self.t0,
            session_status=SessionStatus.ACTIVE.value,
        )
        self.assertTrue(admissible)

    def test_clock_skew_tolerance_exceeded(self):
        """Event timestamp preceding session start beyond 300s is rejected."""
        t_very_old = self.t0 - timedelta(seconds=301)  # 5 min 1 sec prior
        admissible, reason = self.policy.is_event_within_session_boundaries(
            event_observed_at=t_very_old,
            session_first_observed=self.t0,
            session_last_activity=self.t0,
            session_status=SessionStatus.ACTIVE.value,
        )
        self.assertFalse(admissible)
        self.assertIn("skew tolerance", reason)

    def test_evaluate_session_status(self):
        """Status evaluation returns ACTIVE, IDLE, TIMED_OUT, and CLOSED accordingly."""
        # Closed
        status = self.policy.evaluate_session_status(
            first_observed_at=self.t0,
            last_activity_at=self.t0,
            ended_at=self.t0 + timedelta(minutes=10),
            current_time=self.t0 + timedelta(minutes=20),
        )
        self.assertEqual(status, SessionStatus.CLOSED)

        # Active
        status = self.policy.evaluate_session_status(
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=10),
            ended_at=None,
            current_time=self.t0 + timedelta(minutes=15),
        )
        self.assertEqual(status, SessionStatus.ACTIVE)

        # Idle (inactivity > 1800s)
        status = self.policy.evaluate_session_status(
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=10),
            ended_at=None,
            current_time=self.t0 + timedelta(minutes=45),
        )
        self.assertEqual(status, SessionStatus.IDLE)

        # Timed out (duration > 43200s)
        status = self.policy.evaluate_session_status(
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(hours=12, minutes=5),
            ended_at=None,
            current_time=self.t0 + timedelta(hours=12, minutes=10),
        )
        self.assertEqual(status, SessionStatus.TIMED_OUT)


if __name__ == "__main__":
    unittest.main()

