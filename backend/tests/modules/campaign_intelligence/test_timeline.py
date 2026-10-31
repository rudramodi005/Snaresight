"""Unit tests for InvestigationTimelineBuilder (Task P24)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterAuditLogModel,
)
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.modules.campaign_intelligence.timeline import InvestigationTimelineBuilder


class TestInvestigationTimeline(unittest.TestCase):
    """Verifies chronological timeline synthesis, event types, and ordering."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        t0 = datetime.now(timezone.utc) - timedelta(hours=3)

        self.cluster = InvestigationClusterModel(
            cluster_id="CAMP-TL-001",
            title="Timeline Test Cluster",
            description="Testing timeline",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            review_status="UNDER_REVIEW",
            analyst_owner=None,
            cluster_methodology_version="1.0",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(hours=2),
            evidence_summary={},
        )
        self.db.add(self.cluster)

        # Session at t0
        self.sess = ActivitySessionModel(
            session_id="SESS-TL-01",
            decoy_id="WEB-001",
            correlation_key="ck-tl-01",
            source_address="198.51.100.99",
            protocol="HTTP",
            first_observed_at=t0,
            last_activity_at=t0 + timedelta(minutes=10),
            ended_at=t0 + timedelta(minutes=10),
            first_ingested_at=t0,
            last_ingested_at=t0,
            event_count=5,
            session_status="CLOSED",
        )
        self.db.add(self.sess)

        # Alert at t0 + 1h
        self.alert = AlertModel(
            alert_id=uuid.uuid4(),
            detection_rule_id="RULE-BRUTE-FORCE",
            detection_rule_version="1.0",
            title="Brute-Force Login Attempt",
            summary="Multiple failed HTTP logins",
            severity="HIGH",
            confidence=90,
            assessment_status="NEW",
            evidence_strength="STRONG",
            source_address="198.51.100.99",
            observed_source_id="SRC-99",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=t0 + timedelta(hours=1),
            last_observed_at=t0 + timedelta(hours=1),
            generated_at=t0 + timedelta(hours=1),
            detection_explanation="High threshold hit",
            recommendations={},
            created_at=t0 + timedelta(hours=1),
        )
        self.db.add(self.alert)

        # Memberships
        m1 = ClusterMembershipModel(
            cluster_id="CAMP-TL-001",
            member_type="SESSION",
            member_id="SESS-TL-01",
        )
        m2 = ClusterMembershipModel(
            cluster_id="CAMP-TL-001",
            member_type="ALERT",
            member_id=str(self.alert.alert_id),
        )
        self.db.add_all([m1, m2])

        # Audit log at t0 + 2h
        audit = ClusterAuditLogModel(
            cluster_id="CAMP-TL-001",
            actor="SOC-ANALYST",
            action="NOTE_ADDED",
            reason="Confirmed malicious probe",
            timestamp=t0 + timedelta(hours=2),
        )
        self.db.add(audit)
        self.db.commit()

        self.builder = InvestigationTimelineBuilder(self.db)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_chronological_ordering(self):
        tl = self.builder.build_timeline("CAMP-TL-001", chronological=True)
        self.assertEqual(tl.total_items, 3)

        # 1. Session first (t0)
        self.assertEqual(tl.items[0].item_type, "SESSION")
        # 2. Alert second (t0 + 1h)
        self.assertEqual(tl.items[1].item_type, "ALERT")
        # 3. Audit third (t0 + 2h)
        self.assertEqual(tl.items[2].item_type, "ANALYST_ACTION")

    def test_reverse_chronological_ordering(self):
        tl = self.builder.build_timeline("CAMP-TL-001", chronological=False)
        self.assertEqual(tl.total_items, 3)
        self.assertEqual(tl.items[0].item_type, "ANALYST_ACTION")
        self.assertEqual(tl.items[2].item_type, "SESSION")

