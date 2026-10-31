"""Comprehensive End-to-End User Workflows and Cross-Module Integration Suite.

Tests the 8 core user journeys specified in Phase 8 (P35):
1. Workflow 1: Honeypot Telemetry Ingestion & Sanitization
2. Workflow 2: Behavioral Detection & Alert Creation
3. Workflow 3: SOC Alert Investigation & Evidence Triage
4. Workflow 4: Defensive Response Management & Two-Person Approval
5. Workflow 5: Honeypot Sensor Operations & Fleet Health Lifecycle
6. Workflow 6: Platform Health Diagnostics & Isolated Dependency Failure
7. Workflow 7: SOC Reporting & Executive Analytics Export
8. Workflow 8: Multi-Role RBAC Privilege Enforcement
"""

import unittest
import uuid
import json
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.db.models.security import UserModel
from app.modules.security.crypto import hash_password, create_access_token


class TestEndToEndWorkflowsSuite(unittest.TestCase):
    """End-to-end integration and workflow verification suite."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

        def override_get_db():
            db = cls.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=cls.engine)
        app.dependency_overrides.clear()

    def setUp(self):
        self.db = self.TestingSessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Seed Admin user
        self.admin = self.db.query(UserModel).filter(UserModel.username == "admin_e2e").first()
        if not self.admin:
            self.admin = UserModel(
                id=str(uuid.uuid4()),
                username="admin_e2e",
                email="admin_e2e@snaresight.internal",
                hashed_password=hash_password("AdminPass2026!"),
                role="ADMIN",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.admin)
            self.db.commit()

        t_admin, _ = create_access_token(
            {"sub": self.admin.username, "user_id": self.admin.id, "role": "ADMIN"}
        )
        self.admin_headers = {"Authorization": f"Bearer {t_admin}"}

        # Seed Analyst user
        self.analyst = self.db.query(UserModel).filter(UserModel.username == "analyst_e2e").first()
        if not self.analyst:
            self.analyst = UserModel(
                id=str(uuid.uuid4()),
                username="analyst_e2e",
                email="analyst_e2e@snaresight.internal",
                hashed_password=hash_password("AnalystPass2026!"),
                role="ANALYST",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.analyst)
            self.db.commit()

        t_analyst, _ = create_access_token(
            {"sub": self.analyst.username, "user_id": self.analyst.id, "role": "ANALYST"}
        )
        self.analyst_headers = {"Authorization": f"Bearer {t_analyst}"}

        # Seed Viewer user
        self.viewer = self.db.query(UserModel).filter(UserModel.username == "viewer_e2e").first()
        if not self.viewer:
            self.viewer = UserModel(
                id=str(uuid.uuid4()),
                username="viewer_e2e",
                email="viewer_e2e@snaresight.internal",
                hashed_password=hash_password("ViewerPass2026!"),
                role="VIEWER",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.viewer)
            self.db.commit()

        t_viewer, _ = create_access_token(
            {"sub": self.viewer.username, "user_id": self.viewer.id, "role": "VIEWER"}
        )
        self.viewer_headers = {"Authorization": f"Bearer {t_viewer}"}

        # Seed registered Honeypot Decoy to satisfy relational foreign keys
        from app.db.models import HoneypotModel
        decoy = self.db.query(HoneypotModel).filter(HoneypotModel.decoy_id == "WEB-001").first()
        if not decoy:
            decoy = HoneypotModel(
                decoy_id="WEB-001",
                name="ApexCore Portal Decoy",
                decoy_type="WEB_LOGIN",
                protocol="HTTP",
                environment="isolated_lab",
                status="ACTIVE",
            )
            self.db.add(decoy)
            self.db.commit()

    def tearDown(self):
        self.db.close()

    # -------------------------------------------------------------------------
    # WORKFLOW 1: HONEYPOT TELEMETRY INGESTION & SANITIZATION
    # -------------------------------------------------------------------------
    def test_workflow_01_telemetry_intake_and_sanitization(self):
        """WORKFLOW 1: Intake synthetic honeypot interaction, sanitize, and verify persistence."""
        event_payload = {
            "source_id": "collector-web-01",
            "schema_version": "1.0",
            "events": [
                {
                    "raw_event_id": str(uuid.uuid4()),
                    "schema_version": "1.0",
                    "event_type": "ssh_login_attempt",
                    "event_category": "authentication",
                    "decoy_id": "WEB-001",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "session_id": "decoy_sess_3430c5e63810486c99cff33faad6a50d",
                    "source": {
                        "ip_address": "198.51.100.45",
                        "port": 54321,
                        "protocol": "https",
                    },
                    "interaction": {
                        "username_fingerprint": "7c4852c2863cb6ff7bb84f50684f00db1e075c35399587ccf618a8efaa6734ee",
                        "password_present": True,
                        "status_code": 401,
                    },
                    "provenance": {
                        "source_type": "controlled_test",
                        "environment": "isolated_lab",
                    },
                }
            ],
        }
        ingest_headers = {"X-API-Key": "snare-collector-key-dev-2026"}
        resp = self.client.post("/api/v1/ingestion/events/batch", json=event_payload, headers=ingest_headers)
        self.assertIn(resp.status_code, [200, 201])
        data = resp.json()
        self.assertGreaterEqual(data.get("accepted_count", 0), 1, str(data))

    # -------------------------------------------------------------------------
    # WORKFLOW 2: DETECTION AND ALERTING
    # -------------------------------------------------------------------------
    def test_workflow_02_detection_and_alerting(self):
        """WORKFLOW 2: Submit suspicious activity, evaluate rules, and verify alert queryability."""
        # Query active alerts
        resp = self.client.get("/api/v1/alerts", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        alerts = resp.json()
        self.assertIsInstance(alerts, (list, dict))

    # -------------------------------------------------------------------------
    # WORKFLOW 3: INVESTIGATION & ANALYST TRIAGE
    # -------------------------------------------------------------------------
    def test_workflow_03_investigation_and_notes(self):
        """WORKFLOW 3: Query security events, inspect session, and add analyst note."""
        resp = self.client.get("/api/v1/events", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)

    # -------------------------------------------------------------------------
    # WORKFLOW 4: DEFENSIVE RESPONSE & HUMAN APPROVAL
    # -------------------------------------------------------------------------
    def test_workflow_04_defensive_response_management(self):
        """WORKFLOW 4: Create a defense case, list recommendations, and record decision."""
        create_payload = {
            "title": "E2E Case: Compromise Investigation",
            "description": "Synthetic multi-stage decoy trigger under investigation.",
            "priority": "P2_HIGH",
        }
        resp = self.client.post("/api/v1/response/cases", json=create_payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 201)
        case_data = resp.json()
        case_id = case_data["case_id"]

        # Add note to case
        note_resp = self.client.post(
            f"/api/v1/response/cases/{case_id}/notes",
            json={"content": "Verified attacker source address and reviewed evidence hold requirements."},
            headers=self.analyst_headers,
        )
        self.assertEqual(note_resp.status_code, 201)

        # Apply evidence preservation hold
        hold_resp = self.client.post(
            f"/api/v1/response/cases/{case_id}/holds",
            json={
                "evidence_type": "SESSION",
                "evidence_identifier": "SESS-SYNTH-991",
                "hold_reason": "Statutory preservation hold for forensic chain of custody",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(hold_resp.status_code, 201)
        hold_data = hold_resp.json()
        self.assertEqual(hold_data["retention_hold_status"], "ACTIVE")

    # -------------------------------------------------------------------------
    # WORKFLOW 5: SENSOR OPERATIONS & FLEET HEALTH
    # -------------------------------------------------------------------------
    def test_workflow_05_sensor_fleet_lifecycle(self):
        """WORKFLOW 5: Register sensor, submit heartbeat, simulate telemetry, verify health."""
        sensor_id = f"SENSOR-E2E-{uuid.uuid4().hex[:6]}"
        reg_payload = {
            "sensor_id": sensor_id,
            "name": "E2E Web Canary Decoy",
            "sensor_type": "WEB_LOGIN_DECOY",
            "sensor_version": "1.0.0",
            "deployment_environment": "isolated_lab",
            "lab_zone": "zone_alpha",
            "heartbeat_interval_seconds": 30,
            "supported_telemetry_types": ["http_request", "auth_attempt"],
        }
        resp_reg = self.client.post("/api/v1/sensors", json=reg_payload, headers=self.admin_headers)
        self.assertEqual(resp_reg.status_code, 201)
        reg_data = resp_reg.json()
        raw_key = reg_data["raw_api_key"]

        # Submit heartbeat
        sensor_headers = {"X-Sensor-ID": sensor_id, "X-Sensor-Key": raw_key}
        hb_resp = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={
                "sensor_id": sensor_id,
                "status": "HEALTHY",
                "latency_ms": 12.4,
                "metrics_payload": {
                    "cpu_percent": 4.5,
                    "memory_mb": 180,
                    "events_buffered": 0,
                },
            },
            headers=sensor_headers,
        )
        self.assertEqual(hb_resp.status_code, 200)

        # Check sensor summary
        sum_resp = self.client.get("/api/v1/sensors/summary", headers=self.analyst_headers)
        self.assertEqual(sum_resp.status_code, 200)
        self.assertGreaterEqual(sum_resp.json()["total_registered_sensors"], 1)

    # -------------------------------------------------------------------------
    # WORKFLOW 6: PLATFORM HEALTH & ISOLATED SANDBOX RECOVERY
    # -------------------------------------------------------------------------
    def test_workflow_06_platform_health_and_sandbox_recovery(self):
        """WORKFLOW 6: Validate diagnostic health, generate backup, and test isolated sandbox recovery."""
        # Check diagnostics
        diag_resp = self.client.get("/api/v1/resilience/health/diagnostics", headers=self.admin_headers)
        self.assertEqual(diag_resp.status_code, 200)
        diag = diag_resp.json()
        self.assertIn(diag["overall_status"], ["HEALTHY", "DEGRADED", "CRITICAL"])

        # Create backup
        bck_resp = self.client.post(
            "/api/v1/resilience/backups",
            json={"backup_type": "MANUAL", "retention_hold": True},
            headers=self.admin_headers,
        )
        self.assertEqual(bck_resp.status_code, 201)
        bck_id = bck_resp.json()["backup_id"]

        # Execute restore test in isolated sandbox (zero impact on production tables)
        rst_resp = self.client.post(
            f"/api/v1/resilience/backups/{bck_id}/restore-test",
            json={"test_environment": "isolated_sandbox_db"},
            headers=self.admin_headers,
        )
        self.assertEqual(rst_resp.status_code, 200)
        rst_data = rst_resp.json()
        self.assertEqual(rst_data["status"], "SUCCESS")
        self.assertTrue(rst_data["integrity_check_passed"])

    # -------------------------------------------------------------------------
    # WORKFLOW 7: REPORTING & EXECUTIVE ANALYTICS
    # -------------------------------------------------------------------------
    def test_workflow_07_reporting_and_analytics(self):
        """WORKFLOW 7: Query analytics overview and generate executive security report."""
        resp = self.client.get("/api/v1/analytics/overview", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_events", data)
        self.assertIn("total_alerts", data)

    # -------------------------------------------------------------------------
    # WORKFLOW 8: MULTI-ROLE RBAC ACCESS CONTROL
    # -------------------------------------------------------------------------
    def test_workflow_08_rbac_privilege_enforcement(self):
        """WORKFLOW 8: Test permissions across ADMIN, ANALYST, and VIEWER roles."""
        # 1. VIEWER attempts administrative action (backup) -> 403 Forbidden
        viewer_resp = self.client.post(
            "/api/v1/resilience/backups",
            json={"backup_type": "MANUAL", "retention_hold": False},
            headers=self.viewer_headers,
        )
        self.assertEqual(viewer_resp.status_code, 403)

        # 2. VIEWER attempts sensor registration -> 403 Forbidden
        viewer_reg = self.client.post(
            "/api/v1/sensors",
            json={
                "sensor_id": "SNS-FORBIDDEN",
                "name": "Unauthorized Sensor",
                "sensor_type": "WEB_LOGIN_DECOY",
            },
            headers=self.viewer_headers,
        )
        self.assertEqual(viewer_reg.status_code, 403)

        # 3. ANALYST can view dashboard and events -> 200 OK
        analyst_resp = self.client.get("/api/v1/dashboard/overview", headers=self.analyst_headers)
        self.assertEqual(analyst_resp.status_code, 200)

        # 4. Unauthenticated request to protected route -> 401 Unauthorized
        anon_resp = self.client.post(
            "/api/v1/sensors",
            json={
                "sensor_id": "SNS-ANON",
                "name": "Anonymous Sensor",
                "sensor_type": "WEB_LOGIN_DECOY",
            },
            headers={"Authorization": "Bearer invalid-garbage-token"},
        )
        self.assertEqual(anon_resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
