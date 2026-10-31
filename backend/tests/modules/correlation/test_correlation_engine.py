"""Unit and integration tests for CorrelationEngine (Task P21)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.correlation import (
    ActivitySessionModel,
    ActivitySessionEventModel,
    SessionCorrelationHistoryModel,
)
from app.correlation.engine import CorrelationEngine
from app.correlation.policy import CorrelationPolicy
from app.correlation.schemas import SessionStatus, CorrelationMethod


class TestCorrelationEngine(unittest.TestCase):
    """Verifies event correlation, session lifecycle, idempotency, and late arrival handling."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        self.policy = CorrelationPolicy(
            policy_version="1.0",
            inactivity_timeout_seconds=1800,
            max_session_duration_seconds=43200,
            clock_skew_tolerance_seconds=300,
        )
        self.correlation_engine = CorrelationEngine(policy=self.policy)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_new_session_creation(self):
        """First event creates a new active session and logs audit history."""
        event_id = str(uuid.uuid4())
        obs_dt = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        event = {
            "event_id": event_id,
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.5",
            "source_port": 45120,
            "target_service": "SSH",
            "source_protocol": "TCP",
            "session_id": "ssh_sess_alpha",
            "event_type": "authentication",
            "event_category": "auth",
            "action": "LOGIN",
            "outcome": "FAILURE",
            "observed_at": obs_dt.isoformat(),
            "received_at": obs_dt.isoformat(),
        }

        session = self.correlation_engine.correlate_event(self.db, event)
        self.assertIsNotNone(session)
        self.assertEqual(session.session_status, SessionStatus.ACTIVE.value)
        self.assertEqual(session.event_count, 1)
        self.assertEqual(session.correlation_method, CorrelationMethod.EXPLICIT_SESSION_ID.value)
        self.assertEqual(session.decoy_id, "SSH-001")
        self.assertEqual(session.source_address, "198.51.100.5")

        # Verify association row
        assoc = self.db.query(ActivitySessionEventModel).filter_by(session_id=session.session_id).first()
        self.assertIsNotNone(assoc)
        self.assertEqual(str(assoc.event_id), event_id)
        self.assertFalse(assoc.is_late_arrival)

        # Verify audit history
        history = self.db.query(SessionCorrelationHistoryModel).filter_by(session_id=session.session_id).all()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].correlation_action, "SESSION_CREATED")

    def test_event_association_within_window(self):
        """Second event matching session within window joins existing session."""
        t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(minutes=5)

        event1 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.10",
            "target_service": "HTTP",
            "session_id": "web_sess_beta",
            "action": "REQUEST",
            "observed_at": t0.isoformat(),
        }
        event2 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.10",
            "target_service": "HTTP",
            "session_id": "web_sess_beta",
            "action": "REQUEST",
            "observed_at": t1.isoformat(),
        }

        s1 = self.correlation_engine.correlate_event(self.db, event1)
        s2 = self.correlation_engine.correlate_event(self.db, event2)

        self.assertEqual(s1.session_id, s2.session_id)
        self.assertEqual(s2.event_count, 2)
        # Verify last activity updated
        self.assertEqual(s2.last_activity_at.replace(tzinfo=timezone.utc), t1)

    def test_idempotent_reprocessing(self):
        """Correlating the exact same event twice returns existing session without duplication."""
        t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        evt_id = str(uuid.uuid4())
        event = {
            "event_id": evt_id,
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.10",
            "target_service": "HTTP",
            "session_id": "web_sess_gamma",
            "observed_at": t0.isoformat(),
        }

        s1 = self.correlation_engine.correlate_event(self.db, event)
        s2 = self.correlation_engine.correlate_event(self.db, event)

        self.assertEqual(s1.session_id, s2.session_id)
        self.assertEqual(s1.event_count, 1)

        # Check that there is only 1 event association row
        count = self.db.query(ActivitySessionEventModel).filter_by(event_id=uuid.UUID(evt_id)).count()
        self.assertEqual(count, 1)

    def test_late_arriving_event_handling(self):
        """Late-arriving event expands session inception, sets is_late_arrival=True, and logs history."""
        t1 = datetime(2026, 10, 31, 12, 10, 0, tzinfo=timezone.utc)
        t0_late = datetime(2026, 10, 31, 12, 8, 0, tzinfo=timezone.utc)  # Arrives out of order

        event1 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.15",
            "target_service": "HTTP",
            "session_id": "web_sess_late",
            "observed_at": t1.isoformat(),
        }
        event2 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.15",
            "target_service": "HTTP",
            "session_id": "web_sess_late",
            "observed_at": t0_late.isoformat(),
        }

        s1 = self.correlation_engine.correlate_event(self.db, event1)
        self.assertEqual(s1.first_observed_at.replace(tzinfo=timezone.utc), t1)

        # Correlate the out-of-order earlier event
        s2 = self.correlation_engine.correlate_event(self.db, event2)
        self.assertEqual(s2.session_id, s1.session_id)
        # first_observed_at is updated backwards to t0_late
        self.assertEqual(s2.first_observed_at.replace(tzinfo=timezone.utc), t0_late)
        self.assertEqual(s2.event_count, 2)

        # Check late arrival flag on event association
        assoc2 = self.db.query(ActivitySessionEventModel).filter_by(event_id=uuid.UUID(event2["event_id"])).first()
        self.assertTrue(assoc2.is_late_arrival)

        # Check history audit logged
        late_hist = (
            self.db.query(SessionCorrelationHistoryModel)
            .filter_by(session_id=s1.session_id, correlation_action="LATE_EVENT_ATTACHED")
            .first()
        )
        self.assertIsNotNone(late_hist)

    def test_inactivity_timeout_triggers_new_session(self):
        """Events separated by more than 1800s trigger TIMED_OUT and start a new session."""
        t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(minutes=35)  # 2100s > 1800s

        event1 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.40",
            "target_service": "SSH",
            "session_id": "ssh_sess_timeout",
            "observed_at": t0.isoformat(),
        }
        event2 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.40",
            "target_service": "SSH",
            "session_id": "ssh_sess_timeout",
            "observed_at": t1.isoformat(),
        }

        s1 = self.correlation_engine.correlate_event(self.db, event1)
        s2 = self.correlation_engine.correlate_event(self.db, event2)

        self.assertNotEqual(s1.session_id, s2.session_id)
        # Previous session is now TIMED_OUT
        db_s1 = self.db.query(ActivitySessionModel).filter_by(session_id=s1.session_id).first()
        self.assertEqual(db_s1.session_status, SessionStatus.TIMED_OUT.value)
        # New session is ACTIVE
        self.assertEqual(s2.session_status, SessionStatus.ACTIVE.value)

    def test_explicit_disconnect_closes_session(self):
        """An event with action='DISCONNECT' closes the session."""
        t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(minutes=2)

        event1 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.45",
            "target_service": "SSH",
            "session_id": "ssh_sess_disc",
            "action": "LOGIN",
            "observed_at": t0.isoformat(),
        }
        event2 = {
            "event_id": str(uuid.uuid4()),
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.45",
            "target_service": "SSH",
            "session_id": "ssh_sess_disc",
            "action": "DISCONNECT",
            "observed_at": t1.isoformat(),
        }

        s1 = self.correlation_engine.correlate_event(self.db, event1)
        s2 = self.correlation_engine.correlate_event(self.db, event2)

        self.assertEqual(s1.session_id, s2.session_id)
        self.assertEqual(s2.session_status, SessionStatus.CLOSED.value)
        self.assertEqual(s2.ended_at.replace(tzinfo=timezone.utc), t1)

    def test_standalone_isolation(self):
        """Level 4 standalone events are isolated in their own standalone session."""
        evt_id = str(uuid.uuid4())
        event = {
            "event_id": evt_id,
            "decoy_id": "WEB-001",
            "source_address": "0.0.0.0",
            "target_service": "HTTP",
            "session_id": None,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
        session = self.correlation_engine.correlate_event(self.db, event)
        self.assertEqual(session.correlation_method, CorrelationMethod.STANDALONE.value)
        self.assertTrue(session.correlation_key.startswith("standalone:"))


if __name__ == "__main__":
    unittest.main()
