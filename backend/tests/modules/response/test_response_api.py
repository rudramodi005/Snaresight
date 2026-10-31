"""Automated unit and integration test suite for Defensive Response and Incident Handling (Task P32).

Verifies case management, recommendation engine, playbooks, approval gates,
evidence preservation holds, and audit logging.
"""

import unittest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app

from app.db.models.honeypot import HoneypotModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.alert import AlertModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.campaign import InvestigationClusterModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.security import UserModel, SystemAuditLogModel
from app.db.models.response import (
    ResponseCaseModel,
    ResponseRecommendationModel,
    PlaybookDefinitionModel,
    PlaybookExecutionModel,
    ResponseApprovalModel,
    ResponseActionModel,
    EvidencePreservationHoldModel,
)
from app.modules.security.crypto import hash_password, create_access_token


class TestDefensiveResponseSuite(unittest.TestCase):
    """Automated test fixture for Defensive Response module."""

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

        # 1. Create honeypot
        self.decoy = HoneypotModel(
            id=uuid.uuid4(),
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)

        # 2. Create rule
        self.rule = DetectionRuleModel(
            id=uuid.uuid4(),
            rule_id="RULE-AUTH-BRUTE",
            rule_name="Brute Force Credential Attack",
            description="Repeated authentication failures",
            severity="HIGH",
            category="CREDENTIAL_ACCESS",
            rule_version="1.0",
            enabled=True,
            configuration={"threshold": 5},
        )
        self.db.add(self.rule)

        # 3. Create alert
        self.alert_id = uuid.uuid4()
        self.alert = AlertModel(
            id=uuid.uuid4(),
            alert_id=self.alert_id,
            title="Credential Brute-Force against Decoy Portal",
            summary="Repeated credential failures detected on WEB-001",
            severity="HIGH",
            confidence=85,
            assessment_status="NEW",
            evidence_strength="HIGH",
            source_address="198.51.100.42",
            observed_source_id="SRC-198.51.100.42",
            decoy_id="WEB-001",
            target_service="HTTP",
            detection_rule_id="RULE-AUTH-BRUTE",
            detection_rule_version="1.0",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            generated_at=datetime.now(timezone.utc),
            detection_explanation="5 failed login attempts in 60s",
            recommendations={"action": "Review auth logs"},
        )
        self.db.add(self.alert)

        # 4. Create campaign cluster
        self.cluster = InvestigationClusterModel(
            id=uuid.uuid4(),
            cluster_id="CAMP-2026-0001",
            title="Operation ShadowProbe",
            description="Coordinated reconnaissance campaign",
            lifecycle_status="ACTIVE",
            priority="HIGH",
            cluster_methodology_version="1.0",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
        )
        self.db.add(self.cluster)

        # 5. Create source profile
        self.profile = SourceProfileModel(
            id=uuid.uuid4(),
            profile_id="PROF-198-51-100-42",
            display_label="Profile 198.51.100.42",
            fingerprint="fp-198-51-100-42",
            source_ip="198.51.100.42",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            total_sessions=3,
            total_events=45,
            total_alerts=2,
            profile_priority="HIGH",
            profile_status="ACTIVE",
        )
        self.db.add(self.profile)

        # 6. Create users
        self.admin = UserModel(
            id=str(uuid.uuid4()),
            username="resp_admin",
            email="admin@resp.local",
            hashed_password=hash_password("AdminPass123!"),
            role="ADMIN",
            is_active=True,
        )
        self.analyst = UserModel(
            id=str(uuid.uuid4()),
            username="resp_analyst",
            email="analyst@resp.local",
            hashed_password=hash_password("AnalystPass123!"),
            role="ANALYST",
            is_active=True,
        )
        self.viewer = UserModel(
            id=str(uuid.uuid4()),
            username="resp_viewer",
            email="viewer@resp.local",
            hashed_password=hash_password("ViewerPass123!"),
            role="VIEWER",
            is_active=True,
        )
        self.db.add_all([self.admin, self.analyst, self.viewer])
        self.db.commit()

        # Auth tokens
        t_admin, _ = create_access_token({"sub": "resp_admin", "user_id": self.admin.id, "role": "ADMIN"})
        self.admin_headers = {"Authorization": f"Bearer {t_admin}"}

        t_analyst, _ = create_access_token({"sub": "resp_analyst", "user_id": self.analyst.id, "role": "ANALYST"})
        self.analyst_headers = {"Authorization": f"Bearer {t_analyst}"}

        t_viewer, _ = create_access_token({"sub": "resp_viewer", "user_id": self.viewer.id, "role": "VIEWER"})
        self.viewer_headers = {"Authorization": f"Bearer {t_viewer}"}

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_01_create_response_case(self):
        """TEST RESP-001: Verifies response case creation, ID generation, entity linking, and recommendations."""
        payload = {
            "title": "Investigate Brute-Force Activity on WEB-001",
            "description": "Repeated credential stuffing against portal decoy.",
            "priority": "P2_HIGH",
            "severity": "HIGH",
            "primary_alert_id": str(self.alert_id),
            "primary_cluster_id": "CAMP-2026-0001",
            "initial_note": "Case opened following SOC triage review.",
        }
        resp = self.client.post("/api/v1/response/cases", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["case_id"].startswith(f"CASE-{datetime.now(timezone.utc).year}-"))
        self.assertEqual(data["status"], "OPEN")
        self.assertEqual(data["priority"], "P2_HIGH")

        # Verify linked relationships
        case_id = data["case_id"]
        detail_resp = self.client.get(f"/api/v1/response/cases/{case_id}", headers=self.analyst_headers)
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(len(detail["relationships"]), 2)
        self.assertEqual(len(detail["notes"]), 1)

    def test_02_case_status_transitions(self):
        """TEST RESP-002: Verifies valid lifecycle state transitions and rejects illegal transitions."""
        # Create case
        payload = {"title": "Lifecycle Test Case", "description": "Testing status changes", "priority": "P3_MEDIUM"}
        r_create = self.client.post("/api/v1/response/cases", json=payload, headers=self.analyst_headers)
        case_id = r_create.json()["case_id"]

        # 1. Valid: OPEN -> UNDER_REVIEW
        r1 = self.client.post(
            f"/api/v1/response/cases/{case_id}/status",
            json={"new_status": "UNDER_REVIEW", "reason": "Analyst assigned for preliminary review"},
            headers=self.analyst_headers,
        )
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["status"], "UNDER_REVIEW")

        # 2. Valid: UNDER_REVIEW -> INVESTIGATING
        r2 = self.client.post(
            f"/api/v1/response/cases/{case_id}/status",
            json={"new_status": "INVESTIGATING", "reason": "Full telemetry correlation underway"},
            headers=self.analyst_headers,
        )
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["status"], "INVESTIGATING")

        # 3. Invalid: INVESTIGATING -> OPEN (not in allowed transition map)
        r3 = self.client.post(
            f"/api/v1/response/cases/{case_id}/status",
            json={"new_status": "OPEN", "reason": "Illegal revert"},
            headers=self.analyst_headers,
        )
        self.assertEqual(r3.status_code, 400)
        self.assertIn("Invalid status transition", r3.json()["detail"])

    def test_03_case_notes_and_linking(self):
        """TEST RESP-003: Verifies adding analyst notes and linking additional forensic entities."""
        r_create = self.client.post(
            "/api/v1/response/cases",
            json={"title": "Notes & Linking Case", "description": "Testing notes and links"},
            headers=self.analyst_headers,
        )
        case_id = r_create.json()["case_id"]

        # Add analyst note
        r_note = self.client.post(
            f"/api/v1/response/cases/{case_id}/notes",
            json={"note_type": "ANALYST_NOTE", "content": "Evidence corroborates single IP origin."},
            headers=self.analyst_headers,
        )
        self.assertEqual(r_note.status_code, 201)
        self.assertEqual(r_note.json()["author_username"], "resp_analyst")

        # Link source profile
        r_link = self.client.post(
            f"/api/v1/response/cases/{case_id}/links",
            json={
                "related_entity_type": "SOURCE_PROFILE",
                "related_entity_id": "PROF-198-51-100-42",
                "relationship_reason": "Source IP address observed across multiple sessions",
                "confidence_score": 0.95,
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(r_link.status_code, 201)
        self.assertEqual(r_link.json()["related_entity_type"], "SOURCE_PROFILE")

    def test_04_recommendation_engine_evaluation(self):
        """TEST RESP-004: Verifies rule-based recommendation generation for authentication & campaign evidence."""
        payload = {
            "title": "Auth Brute Case",
            "description": "Auth brute case with primary alert and campaign",
            "primary_alert_id": str(self.alert_id),
            "primary_cluster_id": "CAMP-2026-0001",
        }
        r_create = self.client.post("/api/v1/response/cases", json=payload, headers=self.analyst_headers)
        case_id = r_create.json()["case_id"]

        r_recs = self.client.get(f"/api/v1/response/cases/{case_id}/recommendations", headers=self.analyst_headers)
        self.assertEqual(r_recs.status_code, 200)
        recs = r_recs.json()
        self.assertGreaterEqual(len(recs), 2)

        rule_ids = [rec["rule_id"] for rec in recs]
        self.assertIn("REC-RULE-AUTH-01", rule_ids)
        self.assertIn("REC-RULE-CAMP-05", rule_ids)

    def test_05_recommendation_acceptance_and_approval_generation(self):
        """TEST RESP-005: Verifies accepting an approval-required recommendation generates a pending approval."""
        payload = {
            "title": "Approval Case",
            "description": "Testing approval generation on recommendation accept",
            "primary_alert_id": str(self.alert_id),
        }
        r_create = self.client.post("/api/v1/response/cases", json=payload, headers=self.analyst_headers)
        case_id = r_create.json()["case_id"]

        r_recs = self.client.get(f"/api/v1/response/cases/{case_id}/recommendations", headers=self.analyst_headers)
        rec = r_recs.json()[0]
        rec_id = rec["recommendation_id"]

        # Accept recommendation
        r_decide = self.client.post(
            f"/api/v1/response/recommendations/{rec_id}/decision",
            json={"decision": "ACCEPT", "reason": "Analyst concurs with authentication evidence hold"},
            headers=self.analyst_headers,
        )
        self.assertEqual(r_decide.status_code, 200)
        self.assertEqual(r_decide.json()["status"], "ACCEPTED")

        # Verify case status transitioned to AWAITING_APPROVAL if approval was required
        if rec["requires_approval"]:
            r_detail = self.client.get(f"/api/v1/response/cases/{case_id}", headers=self.analyst_headers)
            self.assertEqual(r_detail.json()["status"], "AWAITING_APPROVAL")

            # Verify pending approval request exists
            r_apps = self.client.get("/api/v1/response/approvals", headers=self.analyst_headers)
            self.assertEqual(r_apps.status_code, 200)
            app_list = r_apps.json()
            matching = [a for a in app_list if a["recommendation_id"] == rec_id]
            self.assertEqual(len(matching), 1)

    def test_06_human_approval_workflow(self):
        """TEST RESP-006: Verifies authorized decision on pending approval request."""
        # Create approval directly
        approval = ResponseApprovalModel(
            id=uuid.uuid4(),
            approval_id=f"APP-{uuid.uuid4().hex[:8].upper()}",
            case_id="CASE-TEST",
            action_type="ELEVATE_MONITORING",
            requested_by="resp_analyst",
            status="PENDING",
            justification="Elevate decoy monitoring priority",
        )
        self.db.add(approval)
        self.db.commit()

        # Approve using ADMIN role
        r_approve = self.client.post(
            f"/api/v1/response/approvals/{approval.approval_id}/decision",
            json={"decision": "APPROVE", "reason": "Concur with increased monitoring priority"},
            headers=self.admin_headers,
        )
        self.assertEqual(r_approve.status_code, 200)
        self.assertEqual(r_approve.json()["status"], "APPROVED")
        self.assertEqual(r_approve.json()["approved_by"], "resp_admin")

    def test_07_playbook_catalogue_and_execution(self):
        """TEST RESP-007: Verifies 5 default playbooks seeded and initiates step-by-step execution."""
        r_list = self.client.get("/api/v1/response/playbooks", headers=self.analyst_headers)
        self.assertEqual(r_list.status_code, 200)
        playbooks = r_list.json()
        self.assertEqual(len(playbooks), 5)

        pb_ids = [pb["playbook_id"] for pb in playbooks]
        self.assertIn("PB-AUTH-FAILURES", pb_ids)
        self.assertIn("PB-WEB-ENUM", pb_ids)
        self.assertIn("PB-MULTI-SESSION", pb_ids)
        self.assertIn("PB-CAMPAIGN-INVESTIGATION", pb_ids)
        self.assertIn("PB-EVIDENCE-PRESERVE", pb_ids)

        # Create case and execute playbook
        r_case = self.client.post(
            "/api/v1/response/cases",
            json={"title": "Playbook Case", "description": "Testing playbook execution"},
            headers=self.analyst_headers,
        )
        case_id = r_case.json()["case_id"]

        r_exec = self.client.post(
            f"/api/v1/response/playbooks/PB-AUTH-FAILURES/execute/{case_id}",
            json={"inputs": {"analyst_notes": "Starting initial auth review"}},
            headers=self.analyst_headers,
        )
        self.assertEqual(r_exec.status_code, 201)
        exec_data = r_exec.json()
        self.assertEqual(exec_data["status"], "IN_PROGRESS")
        self.assertEqual(exec_data["playbook_id"], "PB-AUTH-FAILURES")

    def test_08_defensive_action_execution(self):
        """TEST RESP-008: Verifies executing a safe application action records in response_actions and updates case."""
        r_case = self.client.post(
            "/api/v1/response/cases",
            json={"title": "Action Execution Case", "description": "Testing defensive action catalogue"},
            headers=self.analyst_headers,
        )
        case_id = r_case.json()["case_id"]

        # Execute CHANGE_PRIORITY action
        r_act = self.client.post(
            f"/api/v1/response/cases/{case_id}/actions",
            json={"action_type": "CHANGE_PRIORITY", "parameters": {"priority": "P1_CRITICAL"}},
            headers=self.analyst_headers,
        )
        self.assertEqual(r_act.status_code, 201)
        self.assertEqual(r_act.json()["execution_status"], "SUCCESS")

        # Verify case priority updated
        detail = self.client.get(f"/api/v1/response/cases/{case_id}", headers=self.analyst_headers).json()
        self.assertEqual(detail["priority"], "P1_CRITICAL")

    def test_09_evidence_preservation_holds(self):
        """TEST RESP-009: Verifies applying and releasing an evidence preservation hold."""
        r_case = self.client.post(
            "/api/v1/response/cases",
            json={"title": "Evidence Hold Case", "description": "Testing preservation hold"},
            headers=self.analyst_headers,
        )
        case_id = r_case.json()["case_id"]

        # Apply hold
        r_hold = self.client.post(
            f"/api/v1/response/cases/{case_id}/holds",
            json={
                "evidence_type": "ALERT",
                "evidence_identifier": str(self.alert_id),
                "hold_reason": "Preserve alert and evidence junction links for case investigation",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(r_hold.status_code, 201)
        hold_data = r_hold.json()
        hold_id = hold_data["hold_id"]
        self.assertEqual(hold_data["retention_hold_status"], "ACTIVE")
        self.assertIsNotNone(hold_data["integrity_hash_sha256"])

        # Release hold
        r_rel = self.client.post(
            f"/api/v1/response/holds/{hold_id}/release",
            json={"release_justification": "Investigation concluded; forensic hold no longer required."},
            headers=self.analyst_headers,
        )
        self.assertEqual(r_rel.status_code, 200)
        self.assertEqual(r_rel.json()["retention_hold_status"], "RELEASED")

    def test_10_dashboard_summary_metrics(self):
        """TEST RESP-010: Verifies live dashboard summary metrics aggregation."""
        resp = self.client.get("/api/v1/response/summary", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_active_cases", data)
        self.assertIn("open_cases", data)
        self.assertIn("cases_by_status", data)
        self.assertIn("cases_by_priority", data)

    def test_11_rbac_permission_rejection(self):
        """TEST RESP-011: Verifies VIEWER role receives 403 Forbidden for state-mutating endpoints."""
        # Viewer attempting to transition case status
        resp = self.client.post(
            "/api/v1/response/cases/CASE-0001/status",
            json={"new_status": "INVESTIGATING", "reason": "Unauthorized"},
            headers=self.viewer_headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Insufficient privileges", resp.json()["detail"])

    def test_12_audit_trail_verification(self):
        """TEST RESP-012: Verifies response actions record in system_audit_logs."""
        self.client.post(
            "/api/v1/response/cases",
            json={"title": "Audit Verify Case", "description": "Checking audit trail"},
            headers=self.analyst_headers,
        )
        log = self.db.query(SystemAuditLogModel).filter(
            SystemAuditLogModel.action == "RESPONSE_CASE_CREATED",
            SystemAuditLogModel.actor_username == "resp_analyst",
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.outcome, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
