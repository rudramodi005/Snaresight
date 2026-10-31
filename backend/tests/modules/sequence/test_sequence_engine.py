"""Integration tests for SequenceEngine (Task P22)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel, ActivitySessionEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.modules.correlation.sequence_engine import SequenceEngine
from app.modules.correlation.sequence_models import (
    BehavioralSequenceModel,
    BehavioralSequenceMemberModel,
    BehavioralSequenceRelationshipModel,
    SequenceAssessmentHistoryModel,
)
from app.modules.correlation.sequence_policy import CrossSessionCorrelationPolicy
from app.modules.correlation.sequence_schemas import (
    SequenceLifecycleStatus,
    SequenceMemberType,
    SequencePatternType,
)


class TestSequenceEngine(unittest.TestCase):
    """Verifies sequence discovery, member linkage, edge creation, idempotency, and attachments."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        self.policy = CrossSessionCorrelationPolicy(
            policy_version="1.0",
            max_correlation_window_seconds=86400,
            max_sequence_span_seconds=604800,
            min_sessions=2,
        )
        self.sequence_engine = SequenceEngine(policy=self.policy)
        self.t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_new_sequence_discovery_from_related_sessions(self):
        """Two related sessions matching pattern create a new BehavioralSequence."""
        # Seed Session 1: Authentication failure on WEB-001
        sess1 = ActivitySessionModel(
            session_id="act-sess-001",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.30",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k1",
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=5),
            first_ingested_at=self.t0,
            last_ingested_at=self.t0 + timedelta(minutes=5),
            session_status="CLOSED",
            event_count=2,
            detection_count=1,
            highest_severity="MEDIUM",
            metadata_summary={"initial_category": "authentication"},
        )
        # Seed Session 2: Traversal probing 2 hours later
        t1 = self.t0 + timedelta(hours=2)
        sess2 = ActivitySessionModel(
            session_id="act-sess-002",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.30",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k2",
            first_observed_at=t1,
            last_activity_at=t1 + timedelta(minutes=10),
            first_ingested_at=t1,
            last_ingested_at=t1 + timedelta(minutes=10),
            session_status="ACTIVE",
            event_count=4,
            detection_count=1,
            highest_severity="HIGH",
            metadata_summary={"initial_category": "request"},
        )
        self.db.add_all([sess1, sess2])

        # Seed detection for Session 2
        evt_id = uuid.uuid4()
        assoc2 = ActivitySessionEventModel(
            session_id="act-sess-002",
            event_id=evt_id,
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            observed_at=t1,
            ingested_at=t1,
            association_method="EXPLICIT_SESSION_ID",
            correlation_confidence=100,
            is_late_arrival=False,
        )
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="WEB-001",
            detection_rule_version="1.0",
            title="Directory Traversal",
            summary="Directory traversal probe",
            severity="HIGH",
            confidence=90,
            assessment_status="NEW",
            evidence_strength="STRONG",
            source_address="198.51.100.30",
            observed_source_id="SRC-1",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=t1,
            last_observed_at=t1,
            detection_explanation="Traversal probe detected",
            recommendations={},
        )
        evidence = AlertEvidenceModel(
            alert_id=alert_id,
            event_id=evt_id,
            evidence_role="TRIGGERING_OBSERVATION",
        )
        self.db.add_all([assoc2, alert, evidence])
        self.db.commit()

        # Execute sequence discovery evaluating session 2
        seq = self.sequence_engine.evaluate_session(self.db, "act-sess-002")

        self.assertIsNotNone(seq)
        self.assertEqual(seq.session_count, 2)
        self.assertEqual(seq.lifecycle_status, SequenceLifecycleStatus.NEW.value)
        self.assertEqual(seq.primary_source_address, "198.51.100.30")
        self.assertEqual(seq.primary_decoy_id, "WEB-001")

        # Verify members
        members = self.db.query(BehavioralSequenceMemberModel).filter_by(sequence_id=seq.sequence_id).all()
        member_types = [m.member_type for m in members]
        self.assertIn(SequenceMemberType.SESSION.value, member_types)
        self.assertIn(SequenceMemberType.DETECTION.value, member_types)

        # Verify relationships
        rels = self.db.query(BehavioralSequenceRelationshipModel).filter_by(sequence_id=seq.sequence_id).all()
        self.assertGreaterEqual(len(rels), 1)

        # Verify audit history
        hist = self.db.query(SequenceAssessmentHistoryModel).filter_by(sequence_id=seq.sequence_id).all()
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].assessment_action, "SEQUENCE_DISCOVERED")

    def test_idempotent_session_evaluation(self):
        """Evaluating an already sequenced session returns existing sequence without duplication."""
        sess1 = ActivitySessionModel(
            session_id="act-sess-idem-1",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.35",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_idem1",
            first_observed_at=self.t0,
            last_activity_at=self.t0,
            first_ingested_at=self.t0,
            last_ingested_at=self.t0,
            session_status="CLOSED",
            event_count=1,
            detection_count=0,
            metadata_summary={"initial_category": "authentication"},
        )
        sess2 = ActivitySessionModel(
            session_id="act-sess-idem-2",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.35",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_idem2",
            first_observed_at=self.t0 + timedelta(hours=1),
            last_activity_at=self.t0 + timedelta(hours=1),
            first_ingested_at=self.t0 + timedelta(hours=1),
            last_ingested_at=self.t0 + timedelta(hours=1),
            session_status="ACTIVE",
            event_count=1,
            detection_count=0,
            metadata_summary={"initial_category": "authentication"},
        )
        self.db.add_all([sess1, sess2])
        self.db.commit()

        seq1 = self.sequence_engine.evaluate_session(self.db, "act-sess-idem-2")
        seq2 = self.sequence_engine.evaluate_session(self.db, "act-sess-idem-2")

        self.assertEqual(seq1.sequence_id, seq2.sequence_id)
        # Count total sequences in db
        total_seqs = self.db.query(BehavioralSequenceModel).count()
        self.assertEqual(total_seqs, 1)

    def test_attaching_third_session_to_observing_sequence(self):
        """A third session attaches to an active sequence and transitions lifecycle to OBSERVING."""
        sess1 = ActivitySessionModel(
            session_id="act-sess-att-1",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.40",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_att1",
            first_observed_at=self.t0,
            last_activity_at=self.t0,
            first_ingested_at=self.t0,
            last_ingested_at=self.t0,
            session_status="CLOSED",
            event_count=1,
            detection_count=0,
            metadata_summary={"initial_category": "authentication"},
        )
        sess2 = ActivitySessionModel(
            session_id="act-sess-att-2",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.40",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_att2",
            first_observed_at=self.t0 + timedelta(hours=1),
            last_activity_at=self.t0 + timedelta(hours=1),
            first_ingested_at=self.t0 + timedelta(hours=1),
            last_ingested_at=self.t0 + timedelta(hours=1),
            session_status="CLOSED",
            event_count=1,
            detection_count=0,
            metadata_summary={"initial_category": "authentication"},
        )
        self.db.add_all([sess1, sess2])
        self.db.commit()

        # Step 1: Initial sequence of 2 sessions
        seq = self.sequence_engine.evaluate_session(self.db, "act-sess-att-2")
        self.assertEqual(seq.session_count, 2)

        # Step 2: Seed session 3
        sess3 = ActivitySessionModel(
            session_id="act-sess-att-3",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.40",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_att3",
            first_observed_at=self.t0 + timedelta(hours=3),
            last_activity_at=self.t0 + timedelta(hours=3),
            first_ingested_at=self.t0 + timedelta(hours=3),
            last_ingested_at=self.t0 + timedelta(hours=3),
            session_status="ACTIVE",
            event_count=2,
            detection_count=0,
            metadata_summary={"initial_category": "authentication"},
        )
        self.db.add(sess3)
        self.db.commit()

        # Step 3: Evaluate session 3
        seq_updated = self.sequence_engine.evaluate_session(self.db, "act-sess-att-3")
        self.assertEqual(seq_updated.sequence_id, seq.sequence_id)
        self.assertEqual(seq_updated.session_count, 3)
        self.assertEqual(seq_updated.lifecycle_status, SequenceLifecycleStatus.OBSERVING.value)

        # Check history has 2 records
        hist = self.db.query(SequenceAssessmentHistoryModel).filter_by(sequence_id=seq.sequence_id).all()
        self.assertEqual(len(hist), 2)
        actions = [h.assessment_action for h in hist]
        self.assertIn("SESSION_ATTACHED", actions)


if __name__ == "__main__":
    unittest.main()

