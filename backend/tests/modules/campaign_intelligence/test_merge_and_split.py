"""Unit and integration tests for Cluster Merge and Split operations (Task P24)."""

import unittest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from app.db.base import Base
from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterEvidenceModel,
    ClusterAuditLogModel,
)
from app.modules.campaign_intelligence.service import CampaignIntelligenceService


class TestMergeAndSplit(unittest.TestCase):
    """Verifies non-destructive merge and split mechanics, history preservation, and constraints."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

        t0 = datetime.now(timezone.utc) - timedelta(hours=5)

        # Cluster A (Destination)
        self.cA = InvestigationClusterModel(
            cluster_id="CAMP-DEST-A",
            title="Investigation Group Alpha",
            description="Alpha cluster focused on SSH decoys",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            review_status="UNDER_REVIEW",
            analyst_owner="SOC-ANALYST-1",
            cluster_methodology_version="1.0",
            first_observed_at=t0,
            last_observed_at=t0 + timedelta(hours=1),
            evidence_summary={},
        )

        # Cluster B (Source to merge)
        self.cB = InvestigationClusterModel(
            cluster_id="CAMP-SRC-B",
            title="Investigation Group Beta",
            description="Beta cluster focused on SSH decoys",
            lifecycle_status="CANDIDATE",
            priority="MEDIUM",
            review_status="UNREVIEWED",
            analyst_owner=None,
            cluster_methodology_version="1.0",
            first_observed_at=t0 + timedelta(minutes=30),
            last_observed_at=t0 + timedelta(hours=2),
            evidence_summary={},
        )
        self.db.add_all([self.cA, self.cB])
        self.db.flush()

        # Members in A
        self.mA1 = ClusterMembershipModel(
            cluster_id="CAMP-DEST-A",
            member_type="SESSION",
            member_id="SESS-01",
            membership_status="ACCEPTED",
        )
        self.mA2 = ClusterMembershipModel(
            cluster_id="CAMP-DEST-A",
            member_type="SOURCE_PROFILE",
            member_id="PROF-01",
            membership_status="ACCEPTED",
        )

        # Members in B
        self.mB1 = ClusterMembershipModel(
            cluster_id="CAMP-SRC-B",
            member_type="SESSION",
            member_id="SESS-02",
            membership_status="PROPOSED",
        )
        self.mB2 = ClusterMembershipModel(
            cluster_id="CAMP-SRC-B",
            member_type="ALERT",
            member_id="ALT-01",
            membership_status="PROPOSED",
        )
        self.db.add_all([self.mA1, self.mA2, self.mB1, self.mB2])

        # Evidence in B
        self.evB = ClusterEvidenceModel(
            evidence_id="EVID-B-01",
            cluster_id="CAMP-SRC-B",
            evidence_type="DECOY_AFFINITY",
            evidence_reference="DECOY:SSH-001",
            evidence_description="SSH targeting",
            contribution_score=0.8,
            classification="SUPPORTING",
            evidence_timestamp=t0 + timedelta(hours=1),
            methodology_version="1.0",
        )
        self.db.add(self.evB)
        self.db.commit()

        self.service = CampaignIntelligenceService(self.db)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_merge_clusters_non_destructive(self):
        # Merge B into A
        res = self.service.merge_clusters(
            destination_cluster_id="CAMP-DEST-A",
            source_cluster_id="CAMP-SRC-B",
            analyst_id="SOC-ANALYST-1",
            reason="Confirmed shared behavioral sequence across sessions",
        )

        # Verify Destination A incorporated members
        dest_members = self.service.get_cluster_members("CAMP-DEST-A")
        self.assertEqual(len(dest_members), 4)  # SESS-01, PROF-01, SESS-02, ALT-01

        # Verify Destination A incorporated evidence
        dest_evidence = self.service.get_cluster_evidence("CAMP-DEST-A")
        self.assertEqual(len(dest_evidence), 1)

        # Verify Source B is marked MERGED and points to A
        src_cluster = self.service.get_cluster("CAMP-SRC-B")
        self.assertEqual(src_cluster.lifecycle_status, "MERGED")
        self.assertEqual(src_cluster.destination_cluster_id, "CAMP-DEST-A")

        # Verify audit logs in both
        logs_A = self.service.get_cluster_audit_logs("CAMP-DEST-A")
        logs_B = self.service.get_cluster_audit_logs("CAMP-SRC-B")
        self.assertTrue(any(l.action == "MERGED_INCORPORATION" for l in logs_A))
        self.assertTrue(any(l.action == "LIFECYCLE_STATUS_CHANGED" for l in logs_B))

    def test_merge_self_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.service.merge_clusters(
                destination_cluster_id="CAMP-DEST-A",
                source_cluster_id="CAMP-DEST-A",
                analyst_id="SOC-ANALYST-1",
                reason="Invalid self merge",
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_split_cluster_non_destructive(self):
        # Split SESS-02 out of Destination A (after adding it)
        # Cluster A has 2 members initially: SESS-01 and PROF-01
        res = self.service.split_cluster(
            source_cluster_id="CAMP-DEST-A",
            member_ids=["SESS-01"],
            new_title="Partitioned Web Cluster",
            new_description="Split off due to divergent web protocol",
            analyst_id="SOC-ANALYST-1",
            reason="Divergent protocol and interaction pattern",
        )

        self.assertTrue(res.cluster_id.startswith("CAMP-"))
        self.assertEqual(res.title, "Partitioned Web Cluster")

        # Verify member was transferred
        new_members = self.service.get_cluster_members(res.cluster_id)
        self.assertEqual(len(new_members), 1)
        self.assertEqual(new_members[0].member_id, "SESS-01")

        # Verify remaining members in A
        remaining = self.service.get_cluster_members("CAMP-DEST-A")
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].member_id, "PROF-01")

    def test_split_all_members_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.service.split_cluster(
                source_cluster_id="CAMP-DEST-A",
                member_ids=["SESS-01", "PROF-01"],  # All members
                new_title="Fail Split",
                new_description="Desc",
                analyst_id="SOC-ANALYST-1",
                reason="Splitting all members",
            )
        self.assertEqual(ctx.exception.status_code, 400)

