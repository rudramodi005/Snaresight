"""Integration tests for ClusteringEngine (Task P24)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel
from app.db.models.sequence import BehavioralSequenceModel, BehavioralSequenceMemberModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.modules.campaign_intelligence.clustering_engine import ClusteringEngine


class TestClusteringEngine(unittest.TestCase):
    """Verifies clustering discovery, membership binding, and idempotency."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        # Seed Honeypot decoy
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="test_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)

        t0 = datetime.now(timezone.utc) - timedelta(hours=3)

        # Seed behavioral sequence
        self.seq = BehavioralSequenceModel(
            sequence_id="SEQ-P24-001",
            title="Credential Spray against ApexCore Portal",
            sequence_pattern="AUTH_FAILURE_BURST",
            description="Repeated HTTP login failures across multiple accounts",
            lifecycle_status="OBSERVING",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(minutes=45),
            session_count=2,
            event_count=8,
            detection_count=1,
            correlation_confidence=85,
            sequence_relevance=75,
            primary_source_address="198.51.100.50",
            primary_decoy_id="WEB-001",
            metadata_summary={},
        )
        self.db.add(self.seq)

        # Seed sessions
        self.s1 = ActivitySessionModel(
            session_id="SESS-P24-01",
            decoy_id="WEB-001",
            correlation_key="ck-01",
            source_address="198.51.100.50",
            protocol="HTTP",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(minutes=20),
            ended_at=t0 + timedelta(minutes=20),
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=4,
            session_status="CLOSED",
        )
        self.s2 = ActivitySessionModel(
            session_id="SESS-P24-02",
            decoy_id="WEB-001",
            correlation_key="ck-02",
            source_address="198.51.100.50",
            protocol="HTTP",
            first_observed_at=t0 + timedelta(minutes=25),
            last_activity_at=t0 + timedelta(minutes=45),
            ended_at=t0 + timedelta(minutes=45),
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=4,
            session_status="CLOSED",
        )
        self.db.add_all([self.s1, self.s2])

        # Link sequence members
        m1 = BehavioralSequenceMemberModel(
            sequence_id="SEQ-P24-001",
            member_type="SESSION",
            member_record_id="SESS-P24-01",
            sequence_position=0,
            observed_at=t0,
            relationship_reason="Initial probe",
        )
        m2 = BehavioralSequenceMemberModel(
            sequence_id="SEQ-P24-001",
            member_type="SESSION",
            member_record_id="SESS-P24-02",
            sequence_position=1,
            observed_at=t0 + timedelta(minutes=25),
            relationship_reason="Exploitation step",
        )
        self.db.add_all([m1, m2])

        # Seed source profile
        self.prof = SourceProfileModel(
            profile_id="PROF-P24-TEST",
            display_label="Observed Source Profile: 198.51.100.50",
            source_ip="198.51.100.50",
            ip_family="IPv4",
            fingerprint="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(minutes=45),
            total_sessions=2,
            total_events=8,
            total_alerts=1,
            distinct_categories=1,
            distinct_honeypots=1,
            protocol_distribution={"HTTP": 8},
            behavioral_summary={"honeypots": ["WEB-001"]},
            profile_priority="HIGH",
            profile_status="ACTIVE",
        )
        self.db.add(self.prof)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_clustering_discovery_and_idempotency(self):
        engine = ClusteringEngine(self.db)
        clusters = engine.run_clustering(time_window_hours=24)
        self.assertEqual(len(clusters), 1)

        c = clusters[0]
        self.assertTrue(c.cluster_id.startswith("CAMP-"))
        self.assertEqual(c.lifecycle_status, "CANDIDATE")
        self.assertEqual(c.priority, "HIGH")
        self.assertEqual(len(c.members), 4)  # Sequence + 2 sessions + 1 profile
        self.assertGreaterEqual(len(c.evidence), 2)  # Sequence evidence + Decoy evidence

        # Re-run clustering (idempotency check)
        clusters_re = engine.run_clustering(time_window_hours=24)
        self.assertEqual(len(clusters_re), 1)
        self.assertEqual(clusters_re[0].cluster_id, c.cluster_id)
        # Members count remains stable
        self.assertEqual(len(clusters_re[0].members), 4)
