"""Unit and integration tests for SOC Alert Management and Triage Center (Task P28)."""

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
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.alert import AlertModel, AlertEvidenceModel, AlertAuditLogModel, AlertNoteModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.sequence import BehavioralSequenceModel, BehavioralSequenceMemberModel
from app.db.models.campaign import InvestigationClusterModel, ClusterMembershipModel
from app.db.models.intelligence import AttackDetectionMappingModel, AttackTechniqueModel
from app.services.alert_service import alert_service
from app.modules.alerts.prioritization import default_prioritizer


class TestAlertsBase(unittest.TestCase):
    """Base test fixture for Alert Management tests using an in-memory SQLite database."""

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
        alert_service.clear()

    def _seed_honeypot(self, decoy_id: str = "WEB-001") -> HoneypotModel:
        hp = HoneypotModel(
            decoy_id=decoy_id,
            name=f"Decoy {decoy_id}",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(hp)
        self.db.commit()
        return hp

    def _seed_rule(self, rule_id: str = "RULE-BF-001", category: str = "BRUTE_FORCE", severity: str = "HIGH") -> DetectionRuleModel:
        r = DetectionRuleModel(
            rule_id=rule_id,
            rule_name=f"Test Rule {rule_id}",
            rule_version="1.0.0",
            category=category,
            severity=severity,
            description="Testing alert rule",
            enabled=True,
            configuration={"conditions": []},
        )
        self.db.add(r)
        self.db.commit()
        return r

    def _seed_event(self, decoy_id: str = "WEB-001", source_ip: str = "192.168.10.45", session_id: str = "sess-100") -> SecurityEventModel:
        now_utc = datetime.now(timezone.utc)
        raw = RawEventModel(
            raw_event_id=uuid.uuid4(),
            event_type="AUTH_FAILED",
            event_category="AUTHENTICATION",
            decoy_id=decoy_id,
            event_source_id="collector-01",
            session_id=session_id,
            observed_at=now_utc,
            sanitized_payload={"test": "payload"},
            provenance={"environment": "isolated_lab"},
            validation_status="VALID",
        )
        self.db.add(raw)
        self.db.flush()

        ev = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=raw.raw_event_id,
            decoy_id=decoy_id,
            event_type="AUTH_FAILED",
            event_category="AUTHENTICATION",
            action="LOGIN_ATTEMPT",
            outcome="FAILURE",
            source_address=source_ip,
            source_port=54321,
            source_protocol="HTTP",
            target_service="WEB_LOGIN",
            target_port=80,
            session_id=session_id,
            observed_at=now_utc,
            received_at=now_utc,
            sanitized_metadata={"user": "admin"},
            provenance={"environment": "isolated_lab"},
            processing_status="PROCESSED",
            deduplication_reference=str(uuid.uuid4()),
        )
        self.db.add(ev)
        self.db.commit()
        return ev

    def _seed_alert(
        self,
        rule_id: str = "RULE-BF-001",
        decoy_id: str = "WEB-001",
        severity: str = "HIGH",
        confidence: int = 85,
        status: str = "NEW",
        source_address: str = "192.168.10.45",
        assigned_analyst: str = None,
        generated_at: datetime = None,
    ) -> AlertModel:
        alt_id = uuid.uuid4()
        now_utc = generated_at or datetime.now(timezone.utc)
        alert = AlertModel(
            alert_id=alt_id,
            schema_version="1.0",
            detection_rule_id=rule_id,
            detection_rule_version="1.0.0",
            title=f"Alert for {rule_id}",
            summary="Test alert summary",
            severity=severity,
            confidence=confidence,
            assessment_status=status,
            evidence_strength="STRONG",
            source_address=source_address,
            observed_source_id="obs-src-1",
            decoy_id=decoy_id,
            target_service="WEB_LOGIN",
            first_observed_at=now_utc,
            last_observed_at=now_utc,
            generated_at=now_utc,
            detection_explanation="Triggered by brute force burst threshold.",
            recommendations={"action": "Triage immediately"},
            assigned_analyst=assigned_analyst,
            priority_score=75.0 if severity == "HIGH" else 40.0,
            priority_level="P2_HIGH" if severity == "HIGH" else "P3_MEDIUM",
        )
        self.db.add(alert)
        self.db.commit()
        return alert


class TestAlertsQueueAndFiltering(TestAlertsBase):
    """Tests for the paginated alert queue, multi-attribute filtering, and search."""

    def test_list_alerts_empty_db(self):
        """Empty database returns 200 OK with total=0 and empty items."""
        resp = self.client.get("/api/v1/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["items"], [])

    def test_list_alerts_pagination_and_sorting(self):
        """Validates limit, offset, and stable sorting on generated_at."""
        self._seed_honeypot()
        self._seed_rule()
        now = datetime.now(timezone.utc)

        # Seed 5 alerts with staggered timestamps
        for i in range(5):
            self._seed_alert(
                generated_at=now - timedelta(minutes=i * 10),
                severity="HIGH" if i % 2 == 0 else "MEDIUM",
            )

        # Test limit=2, page=1
        resp = self.client.get("/api/v1/alerts?limit=2&page=1&sort_by=generated_at&sort_order=desc")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 5)
        self.assertEqual(len(data["items"]), 2)
        # First item should be the most recent (i=0)
        self.assertTrue(data["items"][0]["generated_at"] >= data["items"][1]["generated_at"])

        # Page 2
        resp2 = self.client.get("/api/v1/alerts?limit=2&page=2&sort_by=generated_at&sort_order=desc")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertEqual(len(data2["items"]), 2)
        self.assertNotEqual(data["items"][0]["alert_id"], data2["items"][0]["alert_id"])

    def test_filtering_by_severity_and_status(self):
        """Filters accurately by severity (CRITICAL/HIGH/MEDIUM) and lifecycle status (NEW/ACKNOWLEDGED/CLOSED)."""
        self._seed_honeypot()
        self._seed_rule()

        self._seed_alert(severity="CRITICAL", status="NEW")
        self._seed_alert(severity="HIGH", status="ACKNOWLEDGED")
        self._seed_alert(severity="LOW", status="CLOSED")

        # Filter severity=CRITICAL
        resp = self.client.get("/api/v1/alerts?severity=CRITICAL")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["severity"], "CRITICAL")

        # Filter status=ACKNOWLEDGED
        resp = self.client.get("/api/v1/alerts?status=ACKNOWLEDGED")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["assessment_status"], "ACKNOWLEDGED")

    def test_filtering_by_category_and_analyst(self):
        """Filters alerts by detection rule category and assigned analyst."""
        self._seed_honeypot()
        self._seed_rule(rule_id="RULE-BF-001", category="BRUTE_FORCE")
        self._seed_rule(rule_id="RULE-REC-001", category="RECONNAISSANCE")

        self._seed_alert(rule_id="RULE-BF-001", assigned_analyst="analyst_alice")
        self._seed_alert(rule_id="RULE-REC-001", assigned_analyst="analyst_bob")
        self._seed_alert(rule_id="RULE-REC-001", assigned_analyst=None)

        # Filter category=BRUTE_FORCE
        resp = self.client.get("/api/v1/alerts?category=BRUTE_FORCE")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["total"], 1)

        # Filter analyst=analyst_alice
        resp2 = self.client.get("/api/v1/alerts?assigned_analyst=analyst_alice")
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["total"], 1)

        # Filter unassigned_only=true
        resp3 = self.client.get("/api/v1/alerts?unassigned_only=true")
        self.assertEqual(resp3.status_code, 200)
        self.assertEqual(resp3.json()["total"], 1)

    def test_search_endpoint(self):
        """Free-text search finds alerts by title, source IP, or rule ID."""
        self._seed_honeypot()
        self._seed_rule(rule_id="RULE-BF-001")
        self._seed_alert(rule_id="RULE-BF-001", source_address="10.240.0.99")
        self._seed_alert(rule_id="RULE-BF-001", source_address="172.16.5.12")

        resp = self.client.get("/api/v1/alerts?search=10.240.0.99")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["source_address"], "10.240.0.99")


class TestAlertsSummaryAndPrioritization(TestAlertsBase):
    """Tests for aggregated metrics summary and transparent prioritization scoring."""

    def test_summary_aggregation(self):
        """Verifies summary metrics: lifecycle counts, severities, priority breakdown, and attention flags."""
        self._seed_honeypot()
        self._seed_rule()

        # Seed 1 NEW CRITICAL, 1 ACKNOWLEDGED HIGH, 1 ESCALATED MEDIUM, 1 RESOLVED LOW
        self._seed_alert(severity="CRITICAL", status="NEW", assigned_analyst=None)
        self._seed_alert(severity="HIGH", status="ACKNOWLEDGED", assigned_analyst="analyst_1")
        self._seed_alert(severity="MEDIUM", status="ESCALATED", assigned_analyst=None)
        self._seed_alert(severity="LOW", status="RESOLVED", assigned_analyst="analyst_2")

        resp = self.client.get("/api/v1/alerts/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["total_matching"], 4)
        self.assertEqual(data["new_alerts"], 1)
        self.assertEqual(data["acknowledged_alerts"], 1)
        self.assertEqual(data["escalated_alerts"], 1)
        self.assertEqual(data["resolved_alerts"], 1)
        self.assertEqual(data["closed_alerts"], 0)
        # Active unassigned = NEW (unassigned) + ESCALATED (unassigned) = 2
        self.assertEqual(data["unassigned_alerts"], 2)
        # Requiring attention: NEW, ESCALATED, and ACKNOWLEDGED CRITICAL/HIGH
        self.assertTrue(data["requiring_attention"] >= 3)
        self.assertIn("CRITICAL", data["severity_breakdown"])
        self.assertIn("P1_CRITICAL", data["priority_breakdown"])

    def test_prioritization_engine_transparency(self):
        """Verifies that priority score calculation is deterministic, explainable, and distinct from severity."""
        res_critical = default_prioritizer.calculate_priority(
            severity="CRITICAL",
            confidence=95,
            evidence_strength="DEFINITIVE",
            supporting_events_count=3,
            has_investigation_or_sequence=True,
            generated_at=datetime.now(timezone.utc),
        )
        self.assertEqual(res_critical.priority_level, "P1_CRITICAL")
        self.assertTrue(res_critical.priority_score >= 80.0)
        self.assertTrue(res_critical.severity_component == 40.0)
        self.assertIn("Severity contribution", res_critical.rationale)
        self.assertIn("Formula Version", f"Formula Version {res_critical.formula_version}")

        # High confidence but LOW severity -> should NOT become critical
        res_low_sev = default_prioritizer.calculate_priority(
            severity="LOW",
            confidence=100,
            evidence_strength="CORROBORATED",
            supporting_events_count=1,
            has_investigation_or_sequence=False,
            generated_at=datetime.now(timezone.utc) - timedelta(days=2),
        )
        self.assertTrue(res_low_sev.priority_score < 50.0)
        self.assertIn(res_low_sev.priority_level, ["P3_MEDIUM", "P4_LOW"])


class TestAlertDetailEvidenceAndRelationships(TestAlertsBase):
    """Tests for detail view, evidence linking, and cross-subsystem correlation resolution."""

    def test_alert_detail_and_404(self):
        """Verifies full detail retrieval and proper 404 for non-existent alerts."""
        self._seed_honeypot()
        self._seed_rule()
        alt = self._seed_alert(severity="HIGH", confidence=90)

        resp = self.client.get(f"/api/v1/alerts/{alt.alert_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["alert_id"], str(alt.alert_id))
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["confidence"], 90)
        self.assertIn("prioritization", data)
        self.assertIn("recommendations", data)

        # Non-existent ID returns 404
        fake_id = uuid.uuid4()
        resp404 = self.client.get(f"/api/v1/alerts/{fake_id}")
        self.assertEqual(resp404.status_code, 404)

    def test_alert_evidence_retrieval(self):
        """Verifies retrieval of supporting security events and Security Events Explorer URLs."""
        hp = self._seed_honeypot()
        rule = self._seed_rule()
        ev = self._seed_event()
        alt = self._seed_alert()

        # Link event as evidence
        link = AlertEvidenceModel(
            alert_id=alt.alert_id,
            event_id=ev.event_id,
            evidence_role="TRIGGERING_OBSERVATION",
            evidence_summary="Triggering failed auth payload",
        )
        self.db.add(link)
        self.db.commit()

        resp = self.client.get(f"/api/v1/alerts/{alt.alert_id}/evidence")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["event_id"], str(ev.event_id))
        self.assertEqual(data[0]["evidence_role"], "TRIGGERING_OBSERVATION")
        self.assertEqual(data[0]["investigation_url"], f"/events?event_id={ev.event_id}")

    def test_alert_relationships_resolution(self):
        """Verifies cross-subsystem relationship resolution: Session, Profile, and MITRE mapping."""
        hp = self._seed_honeypot()
        rule = self._seed_rule()
        ev = self._seed_event(source_ip="192.168.10.45", session_id="sess-xyz")
        alt = self._seed_alert(source_address="192.168.10.45")

        link = AlertEvidenceModel(
            alert_id=alt.alert_id,
            event_id=ev.event_id,
            evidence_role="TRIGGERING_OBSERVATION",
        )
        self.db.add(link)

        # Seed Source Profile
        profile = SourceProfileModel(
            profile_id="prof-123",
            display_label="Attacker 192.168.10.45",
            source_ip="192.168.10.45",
            fingerprint="fp-test-123",
            profile_priority="HIGH",
            total_sessions=3,
            total_events=12,
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
        )
        self.db.add(profile)

        # Seed Activity Session
        now_dt = datetime.now(timezone.utc)
        act_sess = ActivitySessionModel(
            session_id="sess-xyz",
            source_address="192.168.10.45",
            decoy_id="WEB-001",
            protocol="HTTP",
            session_status="ACTIVE",
            correlation_key="ck-192.168.10.45-WEB-001",
            event_count=5,
            first_observed_at=now_dt,
            last_activity_at=now_dt,
            first_ingested_at=now_dt,
            last_ingested_at=now_dt,
        )
        self.db.add(act_sess)

        # Seed MITRE mapping
        tech = AttackTechniqueModel(
            technique_id="T1110.001",
            technique_name="Password Guessing",
            description="Brute force authentication guessing",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            is_subtechnique=True,
        )
        self.db.add(tech)
        self.db.flush()

        mapping = AttackDetectionMappingModel(
            mapping_id=uuid.uuid4(),
            detection_result_id="det-123",
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            technique_id="T1110.001",
            dataset_version="v14.1",
            mapping_definition_id="def-123",
            mapping_category="SUPPORTED",
            mapping_confidence=90,
            confidence_explanation="High confidence password guessing match",
            mapping_rationale="Failed auth burst indicates credential guessing",
            assessed_at=now_dt,
        )
        self.db.add(mapping)
        self.db.commit()

        resp = self.client.get(f"/api/v1/alerts/{alt.alert_id}/relationships")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIsNotNone(data["session"])
        self.assertEqual(data["session"]["session_id"], "sess-xyz")
        self.assertIsNotNone(data["source_profile"])
        self.assertEqual(data["source_profile"]["profile_id"], "prof-123")
        self.assertEqual(len(data["mitre_techniques"]), 1)
        self.assertEqual(data["mitre_techniques"][0]["technique_id"], "T1110.001")


class TestAlertTriageWorkflowAndAudit(TestAlertsBase):
    """Tests for the complete auditable lifecycle: Acknowledge, Assign, Investigate, Escalate, Resolve, Close, Notes."""

    def test_full_lifecycle_and_audit_trail(self):
        """Simulates full workflow: NEW -> ACKNOWLEDGED -> INVESTIGATING -> ESCALATED -> RESOLVED -> CLOSED."""
        self._seed_honeypot()
        self._seed_rule()
        alt = self._seed_alert(status="NEW", assigned_analyst=None)

        # 1. Acknowledge
        resp_ack = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/acknowledge",
            json={"analyst_id": "analyst_alice", "notes": "Alert acknowledged for investigation."},
        )
        self.assertEqual(resp_ack.status_code, 200)
        self.assertEqual(resp_ack.json()["assessment_status"], "ACKNOWLEDGED")
        self.assertEqual(resp_ack.json()["assigned_analyst"], "analyst_alice")

        # 2. Assign / Reassign
        resp_assign = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/assign",
            json={"analyst_id": "analyst_bob", "assigned_by": "analyst_alice", "notes": "Reassigned to Bob for SSH review."},
        )
        self.assertEqual(resp_assign.status_code, 200)
        self.assertEqual(resp_assign.json()["assigned_analyst"], "analyst_bob")

        # 3. Start Investigation
        resp_inv = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/investigate",
            json={"analyst_id": "analyst_bob", "notes": "Commencing deep forensic correlation."},
        )
        self.assertEqual(resp_inv.status_code, 200)
        self.assertEqual(resp_inv.json()["assessment_status"], "INVESTIGATING")

        # 4. Escalate
        resp_esc = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/escalate",
            json={
                "analyst_id": "analyst_bob",
                "reason": "Pattern matches persistent credential stuffing attempt across sensors.",
                "escalation_role": "INCIDENT_RESPONSE_LEAD",
            },
        )
        self.assertEqual(resp_esc.status_code, 200)
        self.assertEqual(resp_esc.json()["assessment_status"], "ESCALATED")
        self.assertEqual(resp_esc.json()["escalation_role"], "INCIDENT_RESPONSE_LEAD")

        # 5. Resolve
        resp_res = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/resolve",
            json={
                "analyst_id": "lead_carol",
                "resolution_category": "BENIGN_SCANNER",
                "resolution_reason": "Automated internet scanner hitting decoy; no lateral movement possible.",
            },
        )
        self.assertEqual(resp_res.status_code, 200)
        self.assertEqual(resp_res.json()["assessment_status"], "RESOLVED")

        # 6. Close
        resp_close = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/close",
            json={
                "analyst_id": "lead_carol",
                "closure_reason": "Case concluded. Honeypot decoy operated properly.",
            },
        )
        self.assertEqual(resp_close.status_code, 200)
        self.assertEqual(resp_close.json()["assessment_status"], "CLOSED")

        # 7. Verify Audit History
        resp_hist = self.client.get(f"/api/v1/alerts/{alt.alert_id}/history")
        self.assertEqual(resp_hist.status_code, 200)
        history = resp_hist.json()
        self.assertTrue(len(history) >= 6)
        action_types = [h["action_type"] for h in history]
        self.assertIn("ACKNOWLEDGE", action_types)
        self.assertIn("ASSIGN", action_types)
        self.assertIn("START_INVESTIGATION", action_types)
        self.assertIn("ESCALATE", action_types)
        self.assertIn("RESOLVE", action_types)
        self.assertIn("CLOSE", action_types)

    def test_invalid_status_transition_rejection(self):
        """Attempting an invalid lifecycle jump (e.g. CLOSED -> ACKNOWLEDGED) returns HTTP 400."""
        self._seed_honeypot()
        self._seed_rule()
        alt = self._seed_alert(status="CLOSED")

        resp = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/acknowledge",
            json={"analyst_id": "analyst_alice"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid lifecycle transition", resp.json()["detail"])

    def test_mandatory_reason_validations(self):
        """Empty or whitespace reason fields on Escalate, Resolve, or Close return HTTP 422."""
        self._seed_honeypot()
        self._seed_rule()
        alt = self._seed_alert(status="INVESTIGATING")

        # Escalate with empty reason
        resp_esc = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/escalate",
            json={"analyst_id": "analyst_1", "reason": "   ", "escalation_role": "IR_LEAD"},
        )
        self.assertEqual(resp_esc.status_code, 422)

        # Resolve with empty explanation
        resp_res = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/resolve",
            json={"analyst_id": "analyst_1", "resolution_category": "FALSE_POSITIVE", "resolution_reason": ""},
        )
        self.assertEqual(resp_res.status_code, 422)

        # Close with empty reason
        resp_close = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/close",
            json={"analyst_id": "analyst_1", "closure_reason": ""},
        )
        self.assertEqual(resp_close.status_code, 422)

    def test_analyst_notes_and_triage_decision(self):
        """Verifies adding notes and recording structured triage decision with justification."""
        self._seed_honeypot()
        self._seed_rule()
        alt = self._seed_alert(status="INVESTIGATING")

        # 1. Add Note
        resp_note = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/notes",
            json={"author_id": "analyst_alice", "author_role": "SOC_ANALYST", "content": "Verified source IP in honeypot logs."},
        )
        self.assertEqual(resp_note.status_code, 201)
        note_data = resp_note.json()
        self.assertEqual(note_data["author_id"], "analyst_alice")
        self.assertEqual(note_data["content"], "Verified source IP in honeypot logs.")

        # Read back notes
        resp_notes = self.client.get(f"/api/v1/alerts/{alt.alert_id}/notes")
        self.assertEqual(resp_notes.status_code, 200)
        self.assertEqual(len(resp_notes.json()), 1)

        # 2. Record Triage Decision
        resp_dec = self.client.post(
            f"/api/v1/alerts/{alt.alert_id}/triage-decision",
            json={
                "analyst_id": "analyst_alice",
                "decision": "LIKELY_TRUE_POSITIVE",
                "justification": "Attack pattern matches automated password-spraying script hitting web login decoy.",
            },
        )
        self.assertEqual(resp_dec.status_code, 200)
        detail = resp_dec.json()
        self.assertEqual(detail["triage_decision"], "LIKELY_TRUE_POSITIVE")
        self.assertEqual(detail["triage_justification"], "Attack pattern matches automated password-spraying script hitting web login decoy.")


class TestAlertSuppressionAndIdempotency(TestAlertsBase):
    """Tests for alert suppression, cooldown tracking, and audit log."""

    def test_suppression_rule_and_history(self):
        """Verifies registering a suppression rule, checking matches, and querying suppression history."""
        # Add suppression rule
        rule = alert_service.add_suppression_rule(
            suppression_id="supp-01",
            rule_id="RULE-BF-001",
            reason="Suppress test automated scanner on decoy",
        )
        self.assertIsNotNone(rule)

        # Verify matching
        matched, reason = alert_service.is_suppressed(rule_id="RULE-BF-001")
        self.assertTrue(matched)
        self.assertEqual(reason, "Suppress test automated scanner on decoy")

        # Non-matching rule
        matched2, _ = alert_service.is_suppressed(rule_id="RULE-OTHER-999")
        self.assertFalse(matched2)

        # Query endpoint
        resp = self.client.get("/api/v1/alerts/suppression/history")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)


if __name__ == "__main__":
    unittest.main()
