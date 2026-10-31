"""Comprehensive integration and unit tests for Security Events Explorer & Investigation (Task P27)."""

import unittest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app

from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel, EventAuditLogModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.sequence import BehavioralSequenceModel, BehavioralSequenceMemberModel
from app.db.models.campaign import InvestigationClusterModel, ClusterMembershipModel, ClusterAuditLogModel


class TestSecurityEventsBase(unittest.TestCase):
    """Test fixture with an in-memory SQLite database initialized with all declarative models."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self.db = self.TestingSessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app.dependency_overrides.clear()

    def _seed_honeypot(self, decoy_id: str = "WEB-001") -> HoneypotModel:
        hp = HoneypotModel(
            decoy_id=decoy_id,
            name=f"Sensor {decoy_id}",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(hp)
        self.db.commit()
        return hp

    def _seed_event(
        self,
        event_id: Optional[uuid.UUID] = None,
        category: str = "AUTHENTICATION",
        event_type: str = "LOGIN_ATTEMPT",
        action: str = "LOGIN",
        outcome: str = "FAILURE",
        source_address: str = "198.51.100.10",
        sensor_id: str = "WEB-001",
        session_id: str = "SESS-001",
        observed_at: Optional[datetime] = None,
        metadata: Optional[dict] = None,
    ) -> SecurityEventModel:
        now = observed_at or datetime.now(timezone.utc)
        raw_id = uuid.uuid4()
        raw = RawEventModel(
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type=event_type,
            event_category=category,
            decoy_id=sensor_id,
            event_source_id="agent-01",
            session_id=session_id,
            observed_at=now,
            sanitized_payload={"test": "payload"},
            provenance={"source": "test"},
            validation_status="VALID",
        )
        self.db.add(raw)
        self.db.commit()

        ev_id = event_id or uuid.uuid4()
        sec = SecurityEventModel(
            event_id=ev_id,
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type=event_type,
            event_category=category,
            action=action,
            outcome=outcome,
            decoy_id=sensor_id,
            session_id=session_id,
            observed_source_id=f"SRC-{source_address}",
            source_address=source_address,
            source_port=54321,
            source_protocol="TCP",
            target_service="HTTP",
            target_port=80,
            observed_at=now,
            received_at=now,
            normalized_at=now,
            sanitized_metadata=metadata or {"user": "admin", "client": "curl/7.68.0"},
            provenance={"sensor": sensor_id},
            processing_status="PROCESSED",
            deduplication_reference=f"DEDUP-{ev_id}",
        )
        self.db.add(sec)
        self.db.commit()
        return sec


class TestSecurityEventsListingAndFiltering(TestSecurityEventsBase):
    """Tests for listing, search, multi-attribute filtering, and pagination."""

    def test_list_events_empty_database(self):
        """Empty database returns 200 OK with empty item list."""
        res = self.client.get("/api/v1/events")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(len(data["items"]), 0)

    def test_list_events_pagination_and_sorting(self):
        """Pagination and sorting return correct subsets."""
        self._seed_honeypot("WEB-001")
        now = datetime.now(timezone.utc)

        for i in range(15):
            self._seed_event(
                observed_at=now - timedelta(minutes=i),
                session_id=f"SESS-{i:03d}",
                source_address=f"198.51.100.{i}",
            )

        # Page 1 (10 items)
        res_p1 = self.client.get("/api/v1/events?page=1&page_size=10&sort_by=observed_at&sort_order=desc")
        self.assertEqual(res_p1.status_code, 200)
        data_p1 = res_p1.json()
        self.assertEqual(data_p1["total"], 15)
        self.assertEqual(len(data_p1["items"]), 10)
        self.assertEqual(data_p1["page"], 1)
        self.assertEqual(data_p1["total_pages"], 2)

        # Page 2 (5 items)
        res_p2 = self.client.get("/api/v1/events?page=2&page_size=10&sort_by=observed_at&sort_order=desc")
        self.assertEqual(res_p2.status_code, 200)
        data_p2 = res_p2.json()
        self.assertEqual(len(data_p2["items"]), 5)

    def test_multi_attribute_filters(self):
        """Filtering by category, sensor, protocol, and outcome works simultaneously."""
        self._seed_honeypot("WEB-001")
        self._seed_honeypot("SSH-001")

        e1 = self._seed_event(category="AUTHENTICATION", event_type="LOGIN_ATTEMPT", sensor_id="WEB-001", outcome="FAILURE")
        e2 = self._seed_event(category="RECONNAISSANCE", event_type="PORT_SCAN", sensor_id="SSH-001", outcome="BLOCKED")
        e3 = self._seed_event(category="EXPLOITATION", event_type="COMMAND_INJECTION", sensor_id="WEB-001", outcome="FAILURE")

        # Filter category AUTHENTICATION
        res = self.client.get("/api/v1/events?category=AUTHENTICATION")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 1)
        self.assertEqual(res.json()["items"][0]["event_id"], str(e1.event_id))

        # Filter sensor WEB-001
        res = self.client.get("/api/v1/events?sensor_id=WEB-001")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 2)

        # Filter outcome BLOCKED
        res = self.client.get("/api/v1/events?outcome=BLOCKED")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total"], 1)
        self.assertEqual(res.json()["items"][0]["event_id"], str(e2.event_id))

    def test_search_endpoint(self):
        """Free-text search finds events by source address or session."""
        self._seed_honeypot("WEB-001")
        self._seed_event(source_address="203.0.113.88", session_id="TARGET-SESSION-99")
        self._seed_event(source_address="198.51.100.12", session_id="OTHER-SESS")

        res = self.client.get("/api/v1/events/search?q=TARGET-SESSION")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["session_id"], "TARGET-SESSION-99")

        res_ip = self.client.get("/api/v1/events/search?q=203.0.113.88")
        self.assertEqual(res_ip.status_code, 200)
        self.assertEqual(res_ip.json()["total"], 1)

    def test_detection_status_and_severity_filter(self):
        """Filtering by detection_status=DETECTED and severity=CRITICAL."""
        self._seed_honeypot("WEB-001")
        e_clean = self._seed_event(source_address="10.0.0.1")
        e_alerted = self._seed_event(source_address="10.0.0.2")

        # Create alert linked to e_alerted
        now = datetime.now(timezone.utc)
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="R-TEST",
            detection_rule_version="1.0",
            title="Critical Infiltration Alert",
            summary="Test alert",
            severity="CRITICAL",
            confidence=90,
            assessment_status="NEW",
            evidence_strength="CONCLUSIVE",
            source_address="10.0.0.2",
            observed_source_id="SRC-10",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=now,
            last_observed_at=now,
            generated_at=now,
            detection_explanation="Test",
            recommendations=[],
        )
        self.db.add(alert)
        self.db.commit()

        link = AlertEvidenceModel(
            alert_id=alert_id,
            event_id=e_alerted.event_id,
            evidence_role="TRIGGERING_OBSERVATION",
        )
        self.db.add(link)
        self.db.commit()

        # Check detection_status=DETECTED
        res_det = self.client.get("/api/v1/events?detection_status=DETECTED")
        self.assertEqual(res_det.status_code, 200)
        self.assertEqual(res_det.json()["total"], 1)
        self.assertEqual(res_det.json()["items"][0]["event_id"], str(e_alerted.event_id))
        self.assertEqual(res_det.json()["items"][0]["highest_alert_severity"], "CRITICAL")

        # Check severity=CRITICAL
        res_sev = self.client.get("/api/v1/events?severity=CRITICAL")
        self.assertEqual(res_sev.status_code, 200)
        self.assertEqual(res_sev.json()["total"], 1)

        # Check detection_status=NORMAL
        res_norm = self.client.get("/api/v1/events?detection_status=NORMAL")
        self.assertEqual(res_norm.status_code, 200)
        self.assertEqual(res_norm.json()["total"], 1)
        self.assertEqual(res_norm.json()["items"][0]["event_id"], str(e_clean.event_id))


class TestSecurityEventDetailAndRedaction(TestSecurityEventsBase):
    """Tests for forensic detail, credential redaction, processing history, and provenance."""

    def test_detail_and_sensitive_field_redaction(self):
        """Zero Password Invariant: Passwords/secrets are redacted in normalized_payload."""
        self._seed_honeypot("WEB-001")
        e = self._seed_event(
            metadata={
                "username": "admin",
                "password": "SuperSecretPassword123!",
                "auth_token": "bearer-jwt-token-9999",
                "user_agent": "Mozilla/5.0",
            }
        )

        res = self.client.get(f"/api/v1/events/{e.event_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Check overview
        self.assertEqual(data["overview"]["event_id"], str(e.event_id))

        # Check redaction in normalized_payload
        payload = data["normalized_payload"]
        self.assertEqual(payload["username"], "admin")
        self.assertEqual(payload["password"], "[REDACTED_CREDENTIAL]")
        self.assertEqual(payload["auth_token"], "[REDACTED_CREDENTIAL]")
        self.assertEqual(payload["user_agent"], "Mozilla/5.0")

        # Check processing history
        history = data["processing_history"]
        self.assertGreaterEqual(len(history), 3)
        stages = [h["stage"] for h in history]
        self.assertIn("INGESTION", stages)
        self.assertIn("VALIDATION", stages)
        self.assertIn("NORMALIZATION", stages)
        self.assertIn("DEDUPLICATION", stages)

        # Check evidence provenance
        prov = data["evidence_provenance"]
        self.assertEqual(prov["decoy_id"], "WEB-001")
        self.assertEqual(prov["protocol"], "TCP")

    def test_event_not_found_returns_404(self):
        """Non-existent UUID returns 404 Not Found."""
        random_id = str(uuid.uuid4())
        res = self.client.get(f"/api/v1/events/{random_id}")
        self.assertEqual(res.status_code, 404)


class TestSecurityEventRelationshipsAndTimeline(TestSecurityEventsBase):
    """Tests for cross-entity correlation mapping and session timeline."""

    def test_event_relationships_mapping(self):
        """Relationships correctly resolve session, source profile, and investigation cluster."""
        self._seed_honeypot("WEB-001")
        now = datetime.now(timezone.utc)

        # 1. Create Session
        sess = ActivitySessionModel(
            session_id="SESS-REL-01",
            decoy_id="WEB-001",
            source_address="198.51.100.77",
            first_observed_at=now,
            last_activity_at=now,
            first_ingested_at=now,
            last_ingested_at=now,
            session_status="ACTIVE",
            event_count=5,
            highest_severity="HIGH",
            correlation_key="test-key",
        )
        self.db.add(sess)

        # 2. Create Source Profile
        profile = SourceProfileModel(
            profile_id="PROF-198-51-100-77",
            display_label="Profile 198.51.100.77",
            source_ip="198.51.100.77",
            ip_family="IPv4",
            fingerprint="FP-TEST",
            first_observed_at=now,
            last_observed_at=now,
            total_sessions=1,
            total_events=1,
            profile_priority="HIGH",
        )
        self.db.add(profile)

        # 3. Create Event
        e = self._seed_event(
            source_address="198.51.100.77",
            session_id="SESS-REL-01",
            observed_at=now,
        )

        # 4. Associate with cluster
        cluster = InvestigationClusterModel(
            cluster_id="CLUST-P27-01",
            title="Automated Scanner Cluster",
            description="Test cluster",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            first_observed_at=now,
            last_observed_at=now,
        )
        self.db.add(cluster)
        self.db.commit()

        membership = ClusterMembershipModel(
            cluster_id=cluster.cluster_id,
            member_type="EVENT",
            member_id=str(e.event_id),
            association_method="MANUAL",
            association_confidence=80,
        )
        self.db.add(membership)
        self.db.commit()

        # Query relationships endpoint
        res = self.client.get(f"/api/v1/events/{e.event_id}/relationships")
        self.assertEqual(res.status_code, 200)
        rels = res.json()

        types = [r["entity_type"] for r in rels]
        self.assertIn("RAW_EVENT", types)
        self.assertIn("SESSION", types)
        self.assertIn("SOURCE_PROFILE", types)
        self.assertIn("INVESTIGATION_CLUSTER", types)

    def test_event_timeline(self):
        """Timeline returns chronological events for the same session."""
        self._seed_honeypot("WEB-001")
        now = datetime.now(timezone.utc)

        e1 = self._seed_event(session_id="SESS-TIME-01", observed_at=now - timedelta(minutes=10))
        e2 = self._seed_event(session_id="SESS-TIME-01", observed_at=now - timedelta(minutes=5))
        e3 = self._seed_event(session_id="SESS-TIME-01", observed_at=now)

        res = self.client.get(f"/api/v1/events/{e2.event_id}/timeline")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["context_type"], "SESSION_TIMELINE")
        self.assertEqual(data["total_events"], 3)
        entries = data["timeline"]
        self.assertEqual(entries[0]["event_id"], str(e1.event_id))
        self.assertEqual(entries[1]["event_id"], str(e2.event_id))
        self.assertTrue(entries[1]["is_current_event"])
        self.assertEqual(entries[2]["event_id"], str(e3.event_id))


class TestSecurityEventComparisonAndAudit(TestSecurityEventsBase):
    """Tests for multi-event comparison and analyst notes/review audit logging."""

    def test_event_comparison(self):
        """Comparison identifies matching attributes and differing attributes across events."""
        self._seed_honeypot("WEB-001")
        e1 = self._seed_event(
            category="AUTHENTICATION",
            event_type="LOGIN_ATTEMPT",
            source_address="198.51.100.1",
            outcome="FAILURE",
        )
        e2 = self._seed_event(
            category="AUTHENTICATION",
            event_type="LOGIN_ATTEMPT",
            source_address="198.51.100.2",
            outcome="FAILURE",
        )

        req = {"event_ids": [str(e1.event_id), str(e2.event_id)]}
        res = self.client.post("/api/v1/events/compare", json=req)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("caveat_notice", data)
        self.assertGreater(data["matching_fields_count"], 0)
        self.assertGreater(data["differing_fields_count"], 0)

        cat_field = next(f for f in data["fields"] if f["field_name"] == "Event Category")
        self.assertTrue(cat_field["is_match"])

        src_field = next(f for f in data["fields"] if f["field_name"] == "Source Address")
        self.assertFalse(src_field["is_match"])

    def test_analyst_notes_and_review_status(self):
        """Analyst notes and status reviews are recorded without modifying original evidence."""
        self._seed_honeypot("WEB-001")
        e = self._seed_event()

        # 1. Add note
        note_req = {"note": "Suspicious login burst observed from Tor exit node", "analyst_id": "soc_lead"}
        res_note = self.client.post(f"/api/v1/events/{e.event_id}/notes", json=note_req)
        self.assertEqual(res_note.status_code, 201)
        data_note = res_note.json()
        self.assertEqual(data_note["action_type"], "NOTE")
        self.assertEqual(data_note["notes"], "Suspicious login burst observed from Tor exit node")
        self.assertEqual(data_note["analyst_id"], "soc_lead")

        # 2. Update review status
        rev_req = {"review_status": "ESCALATED", "note": "Escalated for deeper correlation", "analyst_id": "soc_lead"}
        res_rev = self.client.post(f"/api/v1/events/{e.event_id}/review", json=rev_req)
        self.assertEqual(res_rev.status_code, 200)
        data_rev = res_rev.json()
        self.assertEqual(data_rev["action_type"], "REVIEW_STATUS_CHANGE")
        self.assertEqual(data_rev["review_status"], "ESCALATED")

        # 3. Verify event detail shows both audit logs
        res_detail = self.client.get(f"/api/v1/events/{e.event_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(len(detail["audit_logs"]), 2)
        self.assertEqual(detail["overview"]["review_status"], "ESCALATED")

    def test_associate_event_with_investigation(self):
        """Associating an event with an investigation updates memberships and audit logs."""
        self._seed_honeypot("WEB-001")
        e = self._seed_event()
        now = datetime.now(timezone.utc)

        cluster = InvestigationClusterModel(
            cluster_id="CLUST-ASSOC-01",
            title="Credential Stuffing Campaign",
            description="Test cluster",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            first_observed_at=now,
            last_observed_at=now,
        )
        self.db.add(cluster)
        self.db.commit()

        assoc_req = {"cluster_id": cluster.cluster_id, "reason": "Correlated credential attack pattern", "analyst_id": "soc_lead"}
        res = self.client.post(f"/api/v1/events/{e.event_id}/investigations/{cluster.cluster_id}", json=assoc_req)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["cluster_code"], "CLUST-ASSOC-01")

        # Check event detail overview reflects investigation
        res_detail = self.client.get(f"/api/v1/events/{e.event_id}")
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()["overview"]["investigation_cluster_id"], cluster.cluster_id)
        self.assertEqual(res_detail.json()["overview"]["investigation_code"], cluster.cluster_id)

    def test_events_summary_endpoint(self):
        """Summary endpoint aggregates counts across categories and sensors."""
        self._seed_honeypot("WEB-001")
        self._seed_honeypot("SSH-001")

        self._seed_event(category="AUTHENTICATION", sensor_id="WEB-001")
        self._seed_event(category="AUTHENTICATION", sensor_id="WEB-001")
        self._seed_event(category="RECONNAISSANCE", sensor_id="SSH-001")

        res = self.client.get("/api/v1/events/summary")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_events"], 3)
        self.assertEqual(data["clean_events"], 3)
        self.assertEqual(data["detected_events"], 0)
        self.assertEqual(data["distinct_sensors"], 2)
        self.assertEqual(data["categories_breakdown"]["AUTHENTICATION"], 2)
        self.assertEqual(data["categories_breakdown"]["RECONNAISSANCE"], 1)


if __name__ == "__main__":
    unittest.main()
