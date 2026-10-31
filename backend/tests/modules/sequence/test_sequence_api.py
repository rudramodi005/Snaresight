"""Integration tests for Behavioral Sequence REST API endpoints (Task P22)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.db.session import get_db
from app.main import app
from app.modules.correlation.sequence_models import (
    BehavioralSequenceModel,
    BehavioralSequenceMemberModel,
    BehavioralSequenceRelationshipModel,
    SequenceAssessmentHistoryModel,
    SequenceEvidenceModel,
)
from app.modules.correlation.sequence_schemas import (
    SequenceLifecycleStatus,
    SequenceMemberType,
    SequencePatternType,
    SequenceRelationshipType,
)


class TestSequenceApi(unittest.TestCase):
    """Verifies REST endpoints for querying sequences, statistics, timelines, assessments, and lifecycle transitions."""

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

        self.t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
        self.sequence_id = "seq-test-api-001"

        # Seed master sequence
        seq = BehavioralSequenceModel(
            sequence_id=self.sequence_id,
            title="Multi-Stage ATT&CK Technique Progression",
            sequence_pattern=SequencePatternType.MULTI_TECHNIQUE_PROGRESSION.value,
            description="Automated behavioral candidate grouping across 2 sessions.",
            lifecycle_status=SequenceLifecycleStatus.NEW.value,
            first_observed_at=self.t0,
            last_observed_at=self.t0 + timedelta(hours=2),
            session_count=2,
            event_count=5,
            detection_count=1,
            correlation_confidence=80,
            sequence_relevance=75,
            aggregate_severity="HIGH",
            analyst_review_status="UNREVIEWED",
            primary_source_address="198.51.100.55",
            primary_decoy_id="WEB-001",
            correlation_policy_version="1.0",
        )
        self.db.add(seq)

        # Seed ActivitySession
        sess = ActivitySessionModel(
            session_id="act-sess-api-01",
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            source_address="198.51.100.55",
            target_service="HTTP",
            protocol="TCP",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="k_api",
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=5),
            first_ingested_at=self.t0,
            last_ingested_at=self.t0 + timedelta(minutes=5),
            session_status="CLOSED",
            event_count=2,
            detection_count=1,
        )
        self.db.add(sess)

        # Seed Member (Session)
        m_sess = BehavioralSequenceMemberModel(
            id=uuid.uuid4(),
            sequence_id=self.sequence_id,
            member_type=SequenceMemberType.SESSION.value,
            member_record_id="act-sess-api-01",
            sequence_position=0,
            observed_at=self.t0,
            relationship_reason="Session 1 on WEB-001",
            correlation_method="BEHAVIORAL_PATTERN",
        )
        self.db.add(m_sess)

        # Seed Alert & Member (Detection)
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="RULE-PROBE-01",
            detection_rule_version="1.0",
            title="Probe Alert",
            summary="Exploit probe detected",
            severity="HIGH",
            confidence=85,
            assessment_status="NEW",
            evidence_strength="STRONG",
            source_address="198.51.100.55",
            observed_source_id="SRC-1",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=self.t0,
            last_observed_at=self.t0,
            detection_explanation="Probe detected",
            recommendations={},
        )
        self.db.add(alert)

        m_det = BehavioralSequenceMemberModel(
            id=uuid.uuid4(),
            sequence_id=self.sequence_id,
            member_type=SequenceMemberType.DETECTION.value,
            member_record_id=str(alert_id),
            sequence_position=1,
            observed_at=self.t0,
            relationship_reason="Rule detection finding",
            correlation_method="DETECTION_RULE",
        )
        self.db.add(m_det)

        # Seed Relationship Edge
        rel = BehavioralSequenceRelationshipModel(
            id=uuid.uuid4(),
            sequence_id=self.sequence_id,
            source_member_id=m_sess.id,
            target_member_id=m_det.id,
            relationship_type=SequenceRelationshipType.RELATED_DETECTION_PATTERN.value,
            explanation="Detection occurred in Session 1",
            confidence_score=80,
            evidence_payload={"rule_id": "RULE-PROBE-01"},
        )
        self.db.add(rel)

        # Seed Field Evidence
        ev = SequenceEvidenceModel(
            id=uuid.uuid4(),
            sequence_id=self.sequence_id,
            evidence_record_type="SESSION",
            evidence_record_id="act-sess-api-01",
            field_name="source_address",
            field_value="198.51.100.55",
            observed_at=self.t0,
            evidence_provenance={"decoy_id": "WEB-001"},
        )
        self.db.add(ev)

        # Seed ATT&CK Mapping & Member
        map_id = uuid.uuid4()
        mapping = AttackDetectionMappingModel(
            mapping_id=map_id,
            detection_result_id="dr-01",
            alert_id=alert_id,
            mapping_definition_id="def-probe-01",
            rule_id="RULE-PROBE-01",
            rule_version="1.0",
            technique_id="T1190",
            subtechnique_id=None,
            dataset_version="v14.1",
            mapping_category="DIRECT_OBSERVATION",
            mapping_confidence=90,
            mapping_confidence_level="HIGH",
            confidence_explanation="High confidence in exploit probe",
            mapping_rationale="Exploitation of public-facing application",
            review_status="ACCEPTED",
            assessed_at=self.t0,
        )
        self.db.add(mapping)

        m_map = BehavioralSequenceMemberModel(
            id=uuid.uuid4(),
            sequence_id=self.sequence_id,
            member_type=SequenceMemberType.ATTACK_MAPPING.value,
            member_record_id=str(map_id),
            sequence_position=2,
            observed_at=self.t0,
            relationship_reason="ATT&CK technique T1190 mapping",
            correlation_method="MITRE_MAPPING",
        )
        self.db.add(m_map)

        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def test_list_sequences_endpoint(self):
        """GET /api/v1/sequences returns paginated sequence list."""
        res = self.client.get("/api/v1/sequences")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["sequence_id"], self.sequence_id)
        self.assertEqual(data["items"][0]["sequence_pattern"], "MULTI_TECHNIQUE_PROGRESSION")

    def test_list_sequences_filtering(self):
        """GET /api/v1/sequences filters by status and pattern."""
        res = self.client.get("/api/v1/sequences?status=NEW&pattern=MULTI_TECHNIQUE_PROGRESSION")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 1)

        res_none = self.client.get("/api/v1/sequences?status=CLOSED")
        self.assertEqual(res_none.status_code, 200)
        self.assertEqual(res_none.json()["total"], 0)

    def test_get_statistics_endpoint(self):
        """GET /api/v1/sequences/statistics returns summary metrics."""
        res = self.client.get("/api/v1/sequences/statistics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_sequences"], 1)
        self.assertEqual(data["new_sequences"], 1)
        self.assertIn("MULTI_TECHNIQUE_PROGRESSION", data["by_pattern"])

    def test_get_sequence_detail(self):
        """GET /api/v1/sequences/{sequence_id} returns full sequence details with members."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["sequence_id"], self.sequence_id)
        self.assertEqual(len(data["members"]), 3)
        self.assertEqual(len(data["relationships"]), 1)
        self.assertEqual(len(data["evidence_items"]), 1)

    def test_get_sequence_detail_not_found(self):
        """GET /api/v1/sequences/{sequence_id} returns 404 for unknown sequence ID."""
        res = self.client.get("/api/v1/sequences/unknown-seq-999")
        self.assertEqual(res.status_code, 404)

    def test_get_sequence_timeline(self):
        """GET /api/v1/sequences/{sequence_id}/timeline returns chronological observations."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}/timeline")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["sequence_id"], self.sequence_id)
        self.assertEqual(len(data["entries"]), 3)
        # Verify deterministic ordering: Session -> Detection -> ATT&CK Mapping
        types = [e["member_type"] for e in data["entries"]]
        self.assertEqual(types, ["SESSION", "DETECTION", "ATTACK_MAPPING"])

    def test_get_sequence_evidence(self):
        """GET /api/v1/sequences/{sequence_id}/evidence returns field-level evidence traces."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}/evidence")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["field_name"], "source_address")

    def test_get_sequence_sessions(self):
        """GET /api/v1/sequences/{sequence_id}/sessions returns linked ActivitySession records."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}/sessions")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["session_id"], "act-sess-api-01")

    def test_get_sequence_detections(self):
        """GET /api/v1/sequences/{sequence_id}/detections returns linked Alert records."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}/detections")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["title"], "Probe Alert")

    def test_get_sequence_mitre(self):
        """GET /api/v1/sequences/{sequence_id}/mitre returns linked ATT&CK mapping records."""
        res = self.client.get(f"/api/v1/sequences/{self.sequence_id}/mitre")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["technique_id"], "T1190")

    def test_record_analyst_assessment(self):
        """POST /api/v1/sequences/{sequence_id}/assessment records analyst review notes and conclusion."""
        payload = {
            "assessment_action": "CONFIRM",
            "review_notes": "Analyst verified multi-session progression against public web decoy.",
        }
        res = self.client.post(f"/api/v1/sequences/{self.sequence_id}/assessment", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["analyst_review_status"], "CONFIRMED_PROGRESSION")
        self.assertEqual(data["lifecycle_status"], "REVIEWED")

        # Verify audit history row added
        hist = self.db.query(SequenceAssessmentHistoryModel).filter_by(sequence_id=self.sequence_id).all()
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].assessment_action, "ANALYST_CONFIRM")
        self.assertIn("verified multi-session progression", hist[0].assessment_notes)

    def test_update_sequence_status(self):
        """POST /api/v1/sequences/{sequence_id}/status transitions lifecycle state with reason."""
        payload = {
            "new_status": "UNDER_REVIEW",
            "reason": "Assigned to SOC Tier-2 analyst for verification.",
        }
        res = self.client.post(f"/api/v1/sequences/{self.sequence_id}/status", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["lifecycle_status"], "UNDER_REVIEW")


if __name__ == "__main__":
    unittest.main()

