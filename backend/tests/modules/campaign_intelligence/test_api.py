"""Integration tests for Campaign Intelligence REST API endpoints (Task P24)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel
from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterEvidenceModel,
)
from app.db.session import get_db
from app.main import app


class TestCampaignIntelligenceApi(unittest.TestCase):
    """Verifies all REST endpoints under /api/v1/investigations."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        t0 = datetime.now(timezone.utc) - timedelta(hours=2)

        self.cluster = InvestigationClusterModel(
            cluster_id="CAMP-API-01",
            title="API Investigation Cluster",
            description="Testing API endpoints",
            lifecycle_status="CANDIDATE",
            priority="HIGH",
            review_status="UNREVIEWED",
            analyst_owner=None,
            cluster_methodology_version="1.0",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(hours=1),
            evidence_summary={"primary_decoy": "SSH-001"},
        )
        self.cluster2 = InvestigationClusterModel(
            cluster_id="CAMP-API-02",
            title="Secondary Cluster",
            description="Second cluster for merge tests",
            lifecycle_status="CANDIDATE",
            priority="MEDIUM",
            review_status="UNREVIEWED",
            analyst_owner=None,
            cluster_methodology_version="1.0",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(hours=1),
            evidence_summary={},
        )
        self.db.add_all([self.cluster, self.cluster2])
        self.db.flush()

        # Members in cluster 1
        self.m1 = ClusterMembershipModel(
            cluster_id="CAMP-API-01",
            member_type="SESSION",
            member_id="SESS-API-1",
            membership_status="PROPOSED",
        )
        self.m2 = ClusterMembershipModel(
            cluster_id="CAMP-API-01",
            member_type="ALERT",
            member_id="ALT-API-1",
            membership_status="PROPOSED",
        )
        self.db.add_all([self.m1, self.m2])

        # Evidence in cluster 1
        ev = ClusterEvidenceModel(
            evidence_id="EVID-API-1",
            cluster_id="CAMP-API-01",
            evidence_type="DECOY_AFFINITY",
            evidence_reference="DECOY:SSH-001",
            evidence_description="SSH targeting",
            contribution_score=0.8,
            classification="SUPPORTING",
            evidence_timestamp=t0,
            methodology_version="1.0",
        )
        self.db.add(ev)
        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def test_list_investigations_and_summary(self):
        # List
        res = self.client.get("/api/v1/investigations")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["items"]), 2)

        # Summary
        res_sum = self.client.get("/api/v1/investigations/summary")
        self.assertEqual(res_sum.status_code, 200)
        summary = res_sum.json()
        self.assertEqual(summary["total_clusters"], 2)
        self.assertEqual(summary["candidate_clusters"], 2)

    def test_get_cluster_by_id(self):
        res = self.client.get("/api/v1/investigations/CAMP-API-01")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["cluster_id"], "CAMP-API-01")
        self.assertEqual(data["title"], "API Investigation Cluster")
        self.assertEqual(data["priority"], "HIGH")

    def test_get_cluster_detail(self):
        res = self.client.get("/api/v1/investigations/CAMP-API-01/detail")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("cluster", data)
        self.assertIn("members", data)
        self.assertIn("evidence", data)
        self.assertEqual(len(data["members"]), 2)
        self.assertEqual(len(data["evidence"]), 1)

    def test_get_members_and_evidence(self):
        # Members
        res_m = self.client.get("/api/v1/investigations/CAMP-API-01/members")
        self.assertEqual(res_m.status_code, 200)
        self.assertEqual(len(res_m.json()), 2)

        # Evidence
        res_e = self.client.get("/api/v1/investigations/CAMP-API-01/evidence")
        self.assertEqual(res_e.status_code, 200)
        self.assertEqual(len(res_e.json()), 1)

    def test_timeline_and_audit(self):
        # Timeline
        res_t = self.client.get("/api/v1/investigations/CAMP-API-01/timeline")
        self.assertEqual(res_t.status_code, 200)
        self.assertIn("items", res_t.json())

        # Audit
        res_a = self.client.get("/api/v1/investigations/CAMP-API-01/audit")
        self.assertEqual(res_a.status_code, 200)
        self.assertIsInstance(res_a.json(), list)

    def test_add_analyst_note_endpoint(self):
        payload = {"analyst_id": "SOC-ANALYST-1", "notes": "Investigating credential spray burst."}
        res = self.client.post("/api/v1/investigations/CAMP-API-01/notes", json=payload)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json()["success"])

    def test_lifecycle_transition_endpoint(self):
        # Transition CANDIDATE -> UNDER_REVIEW
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "target_status": "UNDER_REVIEW",
            "reason": "Beginning formal triage",
        }
        res = self.client.post("/api/v1/investigations/CAMP-API-01/review", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["lifecycle_status"], "UNDER_REVIEW")

    def test_member_decision_endpoint(self):
        payload = {"analyst_id": "SOC-ANALYST-1", "decision": "ACCEPT", "reason": "Confirmed match"}
        res = self.client.post(
            "/api/v1/investigations/CAMP-API-01/members/SESS-API-1/decision", json=payload
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["membership_status"], "ACCEPTED")

    def test_merge_clusters_endpoint(self):
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "source_cluster_id": "CAMP-API-02",
            "reason": "Consolidating duplicate groups",
        }
        res = self.client.post("/api/v1/investigations/CAMP-API-01/merge", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["cluster_id"], "CAMP-API-01")

        # Verify source is marked MERGED
        res_src = self.client.get("/api/v1/investigations/CAMP-API-02")
        self.assertEqual(res_src.json()["lifecycle_status"], "MERGED")

    def test_split_cluster_endpoint(self):
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "member_ids": ["ALT-API-1"],
            "new_cluster_title": "Split Off Alert Group",
            "new_cluster_description": "Partitioned group",
            "reason": "Different protocol vector",
        }
        res = self.client.post("/api/v1/investigations/CAMP-API-01/split", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["cluster_id"].startswith("CAMP-"))
        self.assertEqual(data["title"], "Split Off Alert Group")

    def test_close_cluster_endpoint(self):
        # Need to transition to UNDER_REVIEW then CLOSED or directly CLOSED from CANDIDATE
        payload = {
            "analyst_id": "SOC-ANALYST-1",
            "closure_reason": "Activity ceased; benign testing confirmed.",
            "resolution_status": "BENIGN_ACTIVITY",
        }
        res = self.client.post("/api/v1/investigations/CAMP-API-01/close", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["lifecycle_status"], "CLOSED")

