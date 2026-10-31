"""Integration tests for Activity Session REST API endpoints (Task P21)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel, ActivitySessionEventModel
from app.db.models.event import SecurityEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.db.session import get_db
from app.main import app


class TestSessionApi(unittest.TestCase):
    """Verifies REST endpoints for querying sessions, statistics, timelines, and artifacts."""

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

        self.t0 = datetime(2026, 10, 31, 15, 0, 0, tzinfo=timezone.utc)
        self.session_id = "act-sess-api-001"

        # Seed sample session
        session = ActivitySessionModel(
            session_id=self.session_id,
            decoy_id="WEB-001",
            honeypot_type="WEB_LOGIN",
            explicit_session_id="web-tok-123",
            correlation_method="EXPLICIT_SESSION_ID",
            correlation_key="WEB-001:WEB_LOGIN:web-tok-123",
            source_address="198.51.100.90",
            source_port=51234,
            target_service="HTTP",
            protocol="TCP",
            first_observed_at=self.t0,
            last_activity_at=self.t0 + timedelta(minutes=5),
            first_ingested_at=self.t0,
            last_ingested_at=self.t0 + timedelta(minutes=5),
            session_status="ACTIVE",
            event_count=2,
            detection_count=1,
            correlation_policy_version="1.0",
        )
        self.db.add(session)

        # Seed security event
        evt1_id = uuid.uuid4()
        sec_evt1 = SecurityEventModel(
            event_id=evt1_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            decoy_id="WEB-001",
            session_id="web-tok-123",
            source_address="198.51.100.90",
            source_protocol="TCP",
            target_service="HTTP",
            target_port=80,
            observed_at=self.t0,
            received_at=self.t0,
            sanitized_metadata={"http_method": "GET", "http_path": "/api/v1/status", "status_code": 200},
            provenance={"source": "test"},
            deduplication_reference=str(uuid.uuid4()),
        )
        self.db.add(sec_evt1)

        # Seed event association
        assoc1 = ActivitySessionEventModel(
            session_id=self.session_id,
            event_id=evt1_id,
            event_type="request",
            event_category="request",
            action="REQUEST",
            outcome="SUCCESS",
            observed_at=self.t0,
            ingested_at=self.t0,
            association_method="EXPLICIT_SESSION_ID",
            correlation_confidence=100,
            is_late_arrival=False,
        )
        self.db.add(assoc1)

        # Seed alert
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="RULE-PROBE-01",
            detection_rule_version="1.0",
            title="Suspicious Request",
            summary="Suspicious HTTP probe observed",
            severity="MEDIUM",
            confidence=80,
            assessment_status="NEW",
            evidence_strength="MEDIUM",
            source_address="198.51.100.90",
            observed_source_id="SRC-01",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=self.t0,
            last_observed_at=self.t0,
            detection_explanation="HTTP probe detected.",
            recommendations={"action": "Monitor traffic"},
        )
        self.db.add(alert)

        # Link alert to event
        evidence = AlertEvidenceModel(
            alert_id=alert_id,
            event_id=evt1_id,
            evidence_role="TRIGGERING_OBSERVATION",
        )
        self.db.add(evidence)

        # Seed ATT&CK mapping
        mapping = AttackDetectionMappingModel(
            mapping_id=uuid.uuid4(),
            detection_result_id="dr-02",
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
        self.db.commit()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()

    def test_list_sessions_endpoint(self):
        """GET /api/v1/sessions returns paginated list of sessions."""
        res = self.client.get("/api/v1/sessions")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["session_id"], self.session_id)
        self.assertEqual(data["items"][0]["decoy_id"], "WEB-001")

    def test_list_sessions_with_filter(self):
        """GET /api/v1/sessions filters by decoy_id and status."""
        res = self.client.get("/api/v1/sessions?decoy_id=WEB-001&status=ACTIVE")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 1)

        res_none = self.client.get("/api/v1/sessions?decoy_id=SSH-999")
        self.assertEqual(res_none.status_code, 200)
        self.assertEqual(res_none.json()["total"], 0)

    def test_get_statistics_endpoint(self):
        """GET /api/v1/sessions/statistics returns summary metrics."""
        res = self.client.get("/api/v1/sessions/statistics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_sessions"], 1)
        self.assertEqual(data["active_sessions"], 1)
        self.assertEqual(data["closed_sessions"], 0)
        self.assertEqual(data["total_events_correlated"], 2)

    def test_get_session_details(self):
        """GET /api/v1/sessions/{session_id} returns session details."""
        res = self.client.get(f"/api/v1/sessions/{self.session_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["session_id"], self.session_id)
        self.assertEqual(data["source_address"], "198.51.100.90")
        self.assertEqual(data["event_count"], 2)

    def test_get_session_details_not_found(self):
        """GET /api/v1/sessions/{session_id} returns 404 for unknown session."""
        res = self.client.get("/api/v1/sessions/unknown-session-123")
        self.assertEqual(res.status_code, 404)

    def test_get_session_timeline(self):
        """GET /api/v1/sessions/{session_id}/timeline returns chronological timeline."""
        res = self.client.get(f"/api/v1/sessions/{self.session_id}/timeline")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["session_id"], self.session_id)
        self.assertGreaterEqual(data["total_entries"], 1)
        self.assertIn("entries", data)

    def test_get_session_events(self):
        """GET /api/v1/sessions/{session_id}/events returns attached events."""
        res = self.client.get(f"/api/v1/sessions/{self.session_id}/events")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["source_address"], "198.51.100.90")
        self.assertEqual(data[0]["action"], "REQUEST")

    def test_get_session_detections(self):
        """GET /api/v1/sessions/{session_id}/detections returns associated detections."""
        res = self.client.get(f"/api/v1/sessions/{self.session_id}/detections")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["title"], "Suspicious Request")

    def test_get_session_mitre_mappings(self):
        """GET /api/v1/sessions/{session_id}/mitre-mappings returns ATT&CK mappings."""
        res = self.client.get(f"/api/v1/sessions/{self.session_id}/mitre-mappings")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["technique_id"], "T1190")


if __name__ == "__main__":
    unittest.main()
