"""Unit tests for ClusterLifecycleManager (Task P24)."""

import unittest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from app.db.base import Base
from app.db.models.campaign import InvestigationClusterModel, ClusterAuditLogModel
from app.modules.campaign_intelligence.lifecycle import ClusterLifecycleManager


class TestClusterLifecycle(unittest.TestCase):
    """Verifies state machine transitions, constraints, and audit trails."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        self.cluster = InvestigationClusterModel(
            cluster_id="CAMP-TEST-001",
            title="Test Cluster",
            description="Testing lifecycle",
            lifecycle_status="CANDIDATE",
            priority="MEDIUM",
            review_status="UNREVIEWED",
            analyst_owner=None,
            cluster_methodology_version="1.0",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            evidence_summary={},
        )
        self.db.add(self.cluster)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_valid_transitions_with_audit_trail(self):
        # 1. CANDIDATE -> UNDER_REVIEW
        ClusterLifecycleManager.transition(
            db=self.db,
            cluster=self.cluster,
            target_status="UNDER_REVIEW",
            actor="SOC-ANALYST-1",
            reason="Starting triage",
        )
        self.db.commit()
        self.assertEqual(self.cluster.lifecycle_status, "UNDER_REVIEW")

        # 2. UNDER_REVIEW -> ACTIVE
        ClusterLifecycleManager.transition(
            db=self.db,
            cluster=self.cluster,
            target_status="ACTIVE",
            actor="SOC-ANALYST-1",
            reason="Confirmed evidence supports active investigation",
        )
        self.db.commit()
        self.assertEqual(self.cluster.lifecycle_status, "ACTIVE")

        # Verify audit logs
        logs = list(self.db.scalars(self.cluster.audit_logs.statement).all()) if hasattr(self.cluster.audit_logs, 'statement') else self.cluster.audit_logs
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0].action, "LIFECYCLE_STATUS_CHANGED")

    def test_invalid_transitions_rejected(self):
        # CANDIDATE cannot transition directly to ACTIVE or MONITORING without UNDER_REVIEW
        with self.assertRaises(HTTPException) as ctx:
            ClusterLifecycleManager.validate_transition("CANDIDATE", "MONITORING")
        self.assertEqual(ctx.exception.status_code, 400)

        # Terminal MERGED cannot transition
        with self.assertRaises(HTTPException) as ctx:
            ClusterLifecycleManager.validate_transition("MERGED", "ACTIVE")
        self.assertEqual(ctx.exception.status_code, 400)

        # Terminal SPLIT cannot transition
        with self.assertRaises(HTTPException) as ctx:
            ClusterLifecycleManager.validate_transition("SPLIT", "UNDER_REVIEW")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_closed_reopening(self):
        self.cluster.lifecycle_status = "CLOSED"
        self.db.commit()

        # CLOSED -> ACTIVE is valid
        ClusterLifecycleManager.transition(
            db=self.db,
            cluster=self.cluster,
            target_status="ACTIVE",
            actor="SOC-ANALYST-2",
            reason="Reopening investigation due to new telemetry",
        )
        self.db.commit()
        self.assertEqual(self.cluster.lifecycle_status, "ACTIVE")

