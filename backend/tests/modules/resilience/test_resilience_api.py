"""Automated unit and integration test suite for Platform Security, Health, Backup, and Resilience (Task P34).

Verifies:
- Liveness and readiness diagnostic probes.
- Subsystem health overview and component monitoring.
- Audit trail cryptographic verification.
- Internal control-plane security events and 7-rule detection engine.
- Controlled database backup creation with SHA-256 checksums and safe storage refs.
- Isolated sandbox backup restore verification (zero production data impact).
- Disaster recovery RPO/RTO target monitoring and 5 failure scenario runbooks.
- Internal security incident management with containment workflows and notes.
- RBAC privilege enforcement.
"""

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
from app.db.models.resilience import (
    InternalSecurityEventModel,
    InternalSecurityAlertModel,
    ComponentHealthRecordModel,
    DatabaseBackupModel,
    RestoreTestRecordModel,
    DisasterRecoveryConfigModel,
    DisasterRecoveryChecklistModel,
    InternalIncidentModel,
    InternalIncidentNoteModel,
)
from app.db.models.security import UserModel
from app.modules.security.crypto import hash_password, create_access_token


class TestResilienceModuleSuite(unittest.TestCase):
    """Integration test suite verifying Platform Resilience, Backup, and Internal Security."""

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
        self.admin_user = (
            self.db.query(UserModel).filter(UserModel.username == "admin_resilience_lead").first()
        )
        if not self.admin_user:
            self.admin_user = UserModel(
                id=str(uuid.uuid4()),
                username="admin_resilience_lead",
                email="admin_resilience_lead@snaresight.internal",
                hashed_password=hash_password("SuperSecretResiliencePass2026!"),
                role="ADMIN",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.admin_user)
            self.db.commit()

        t_admin, _ = create_access_token(
            {"sub": self.admin_user.username, "user_id": self.admin_user.id, "role": "ADMIN"}
        )
        self.admin_headers = {"Authorization": f"Bearer {t_admin}"}

        # Seed Viewer user for RBAC tests
        self.viewer_user = (
            self.db.query(UserModel).filter(UserModel.username == "viewer_resilience_user").first()
        )
        if not self.viewer_user:
            self.viewer_user = UserModel(
                id=str(uuid.uuid4()),
                username="viewer_resilience_user",
                email="viewer@snaresight.internal",
                hashed_password=hash_password("ViewerPass2026!"),
                role="VIEWER",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.viewer_user)
            self.db.commit()

        t_viewer, _ = create_access_token(
            {"sub": self.viewer_user.username, "user_id": self.viewer_user.id, "role": "VIEWER"}
        )
        self.viewer_headers = {"Authorization": f"Bearer {t_viewer}"}

    def tearDown(self):
        self.db.close()

    # -------------------------------------------------------------------------
    # Tests
    # -------------------------------------------------------------------------

    def test_01_liveness_and_readiness_probes(self):
        """TEST RES-001: Liveness and readiness endpoints return HTTP 200 and valid states."""
        # Liveness
        resp_live = self.client.get("/api/v1/resilience/health/live")
        self.assertEqual(resp_live.status_code, 200)
        data_live = resp_live.json()
        self.assertEqual(data_live["status"], "UP")
        self.assertIn("timestamp", data_live)

        # Readiness
        resp_ready = self.client.get("/api/v1/resilience/health/ready")
        self.assertEqual(resp_ready.status_code, 200)
        data_ready = resp_ready.json()
        self.assertEqual(data_ready["status"], "READY")
        self.assertEqual(data_ready["database"], "CONNECTED")

    def test_02_detailed_diagnostics(self):
        """TEST RES-002: Detailed diagnostic health returns multi-component overview."""
        resp = self.client.get("/api/v1/resilience/health/diagnostics", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["overall_status"], ["HEALTHY", "DEGRADED", "CRITICAL"])
        self.assertGreaterEqual(len(data["components"]), 6)
        comp_names = [c["name"] for c in data["components"]]
        self.assertIn("FastAPI Core Engine", comp_names)
        self.assertIn("Database Subsystem", comp_names)
        self.assertIn("Detection & Correlation Engine", comp_names)

    def test_03_audit_chain_verification(self):
        """TEST RES-003: Cryptographic audit chain verification endpoint."""
        resp = self.client.post("/api/v1/resilience/audit/verify", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verified", data)
        self.assertIn("total_records", data)
        self.assertIn("details", data)

    def test_04_record_internal_event_and_rule_trigger(self):
        """TEST RES-004: Record internal security events and trigger RULE-INT-AUTH-01."""
        # Record 5 consecutive auth failures to trigger RULE-INT-AUTH-01
        for i in range(5):
            payload = {
                "event_type": "AUTH_FAILURE",
                "actor_username": "target_admin_account",
                "source_component": "FastAPI_Auth",
                "outcome": "FAILURE",
                "severity": "HIGH",
                "metadata_payload": {"failed_attempts": i + 1, "client_ip": "10.0.0.99"},
            }
            resp = self.client.post("/api/v1/resilience/events", json=payload, headers=self.admin_headers)
            self.assertEqual(resp.status_code, 201)

        # Check internal alerts
        resp_alerts = self.client.get("/api/v1/resilience/alerts", headers=self.admin_headers)
        self.assertEqual(resp_alerts.status_code, 200)
        alerts = resp_alerts.json()
        self.assertGreaterEqual(len(alerts), 1)

        rule_ids = [a["rule_id"] for a in alerts]
        self.assertIn("RULE-INT-AUTH-01", rule_ids)
        auth_alert = next(a for a in alerts if a["rule_id"] == "RULE-INT-AUTH-01")
        self.assertEqual(auth_alert["status"], "OPEN")
        self.assertEqual(auth_alert["severity"], "HIGH")

    def test_05_internal_alert_lifecycle(self):
        """TEST RES-005: Acknowledge and resolve an internal security alert."""
        # Find an open alert
        resp_alerts = self.client.get("/api/v1/resilience/alerts", headers=self.admin_headers)
        alerts = resp_alerts.json()
        self.assertGreater(len(alerts), 0)
        alert_id = alerts[0]["alert_id"]

        # Acknowledge
        resp_ack = self.client.post(
            f"/api/v1/resilience/alerts/{alert_id}/acknowledge",
            json={"notes": "Investigating brute-force attack originating from internal subnet."},
            headers=self.admin_headers,
        )
        self.assertEqual(resp_ack.status_code, 200)
        data_ack = resp_ack.json()
        self.assertEqual(data_ack["status"], "ACKNOWLEDGED")
        self.assertEqual(data_ack["acknowledged_by"], self.admin_user.username)

        # Resolve
        resp_res = self.client.post(
            f"/api/v1/resilience/alerts/{alert_id}/resolve",
            json={"resolution_notes": "Source workstation isolated; administrative credentials rotated."},
            headers=self.admin_headers,
        )
        self.assertEqual(resp_res.status_code, 200)
        data_res = resp_res.json()
        self.assertEqual(data_res["status"], "RESOLVED")
        self.assertEqual(data_res["resolved_by"], self.admin_user.username)

    def test_06_database_backup_generation(self):
        """TEST RES-006: Generate a managed database backup with SHA-256 and safe storage ref."""
        payload = {"backup_type": "MANUAL", "retention_hold": True}
        resp = self.client.post("/api/v1/resilience/backups", json=payload, headers=self.admin_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        self.assertTrue(data["backup_id"].startswith("BCK-"))
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(len(data["checksum_sha256"]), 64)
        self.assertTrue(data["storage_location_ref"].startswith("safe://backups/"))
        self.assertTrue(data["retention_hold"])
        self.assertFalse(data["restore_verified"])

    def test_07_isolated_sandbox_restore_test(self):
        """TEST RES-007: Run isolated sandbox restore test without modifying live tables."""
        # Create a fresh backup
        resp_bck = self.client.post(
            "/api/v1/resilience/backups",
            json={"backup_type": "PRE_MIGRATION", "retention_hold": False},
            headers=self.admin_headers,
        )
        bck_id = resp_bck.json()["backup_id"]

        # Trigger isolated restore test
        resp_test = self.client.post(
            f"/api/v1/resilience/backups/{bck_id}/restore-test",
            json={"test_environment": "isolated_sandbox_db"},
            headers=self.admin_headers,
        )
        self.assertEqual(resp_test.status_code, 200)
        test_data = resp_test.json()

        self.assertEqual(test_data["status"], "SUCCESS")
        self.assertTrue(test_data["schema_compatibility_verified"])
        self.assertTrue(test_data["integrity_check_passed"])
        self.assertGreaterEqual(test_data["table_count_verified"], 20)
        self.assertEqual(test_data["verified_by"], self.admin_user.username)

        # Confirm backup status was updated to restore_verified=True
        resp_list = self.client.get("/api/v1/resilience/backups", headers=self.admin_headers)
        backups = resp_list.json()
        target_bck = next(b for b in backups if b["backup_id"] == bck_id)
        self.assertTrue(target_bck["restore_verified"])
        self.assertIsNotNone(target_bck["restore_verified_at"])

    def test_08_disaster_recovery_config_and_rpo_rto(self):
        """TEST RES-008: Retrieve and update Disaster Recovery RPO/RTO configuration."""
        resp_get = self.client.get("/api/v1/resilience/dr/config", headers=self.admin_headers)
        self.assertEqual(resp_get.status_code, 200)
        cfg = resp_get.json()
        self.assertEqual(cfg["config_name"], "default")
        self.assertEqual(cfg["rpo_target_minutes"], 60)
        self.assertEqual(cfg["rto_target_minutes"], 30)

        # Update targets
        payload = {
            "rpo_target_minutes": 45,
            "rto_target_minutes": 20,
            "backup_frequency_hours": 12,
            "backup_retention_days": 45,
            "cold_archive_retention_days": 730,
            "auto_restore_test_frequency_days": 5,
        }
        resp_put = self.client.put("/api/v1/resilience/dr/config", json=payload, headers=self.admin_headers)
        self.assertEqual(resp_put.status_code, 200)
        updated_cfg = resp_put.json()
        self.assertEqual(updated_cfg["rpo_target_minutes"], 45)
        self.assertEqual(updated_cfg["rto_target_minutes"], 20)

    def test_09_disaster_recovery_checklists_and_five_scenarios(self):
        """TEST RES-009: Verify all 5 failure scenarios are seeded and actionable."""
        resp = self.client.get("/api/v1/resilience/dr/checklists", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        scenarios = resp.json()
        self.assertEqual(len(scenarios), 5)

        scenario_ids = [s["scenario_id"] for s in scenarios]
        expected_scenarios = [
            "DB_UNAVAILABLE",
            "APP_RESTART",
            "SENSOR_DISCONNECT",
            "BACKUP_RESTORE",
            "COMPROMISE_SUSPECTED",
        ]
        for expected in expected_scenarios:
            self.assertIn(expected, scenario_ids)

        # Toggle an item in DB_UNAVAILABLE scenario
        toggle_payload = {
            "item_id": "DB-01",
            "completed": True,
            "notes": "Verified TCP port 5432 responded in 12ms during drill.",
        }
        resp_toggle = self.client.post(
            "/api/v1/resilience/dr/checklists/DB_UNAVAILABLE/items/toggle",
            json=toggle_payload,
            headers=self.admin_headers,
        )
        self.assertEqual(resp_toggle.status_code, 200)
        scenario_data = resp_toggle.json()
        item = next(i for i in scenario_data["checklist_items"] if i["item_id"] == "DB-01")
        self.assertTrue(item["completed"])
        self.assertEqual(item["notes"], toggle_payload["notes"])

    def test_10_internal_security_incident_management(self):
        """TEST RES-010: Manage internal security incidents with containment and notes."""
        create_payload = {
            "title": "Suspected Admin Session Hijacking Probe",
            "description": "High frequency of access denied anomalies on /resilience/backups from external IP.",
            "severity": "HIGH",
            "affected_components": ["FastAPI_Auth", "Database_Subsystem"],
            "linked_alert_ids": ["INT-ALT-AUTH-01"],
            "assigned_administrator": self.admin_user.username,
        }
        resp_create = self.client.post(
            "/api/v1/resilience/incidents", json=create_payload, headers=self.admin_headers
        )
        self.assertEqual(resp_create.status_code, 201)
        inc_data = resp_create.json()
        incident_id = inc_data["incident_id"]

        self.assertTrue(incident_id.startswith("INT-INC-"))
        self.assertEqual(inc_data["status"], "OPEN")

        # Append note
        note_payload = {
            "content": "Administrative IP address block applied at ingress boundary; token revoked.",
            "note_type": "CONTAINMENT",
        }
        resp_note = self.client.post(
            f"/api/v1/resilience/incidents/{incident_id}/notes",
            json=note_payload,
            headers=self.admin_headers,
        )
        self.assertEqual(resp_note.status_code, 201)

        # Update incident to CONTAINED
        patch_payload = {
            "status": "CONTAINED",
            "containment_notes": "Session tokens invalidated and firewall rule established.",
            "recovery_actions_taken": "Credentials rotated for target user.",
        }
        resp_patch = self.client.patch(
            f"/api/v1/resilience/incidents/{incident_id}",
            json=patch_payload,
            headers=self.admin_headers,
        )
        self.assertEqual(resp_patch.status_code, 200)
        updated_inc = resp_patch.json()
        self.assertEqual(updated_inc["status"], "CONTAINED")

        # Get details including notes
        resp_get = self.client.get(
            f"/api/v1/resilience/incidents/{incident_id}", headers=self.admin_headers
        )
        self.assertEqual(resp_get.status_code, 200)
        fetched_inc = resp_get.json()
        self.assertEqual(len(fetched_inc["notes"]), 1)
        self.assertEqual(fetched_inc["notes"][0]["note_type"], "CONTAINMENT")

    def test_11_rbac_enforcement(self):
        """TEST RES-011: Verify non-admin (VIEWER) cannot mutate resilience configurations or backups."""
        # Initiate backup with viewer credentials -> 403 Forbidden
        resp_bck = self.client.post(
            "/api/v1/resilience/backups",
            json={"backup_type": "MANUAL", "retention_hold": False},
            headers=self.viewer_headers,
        )
        self.assertEqual(resp_bck.status_code, 403)

        # Update DR config with viewer credentials -> 403 Forbidden
        resp_cfg = self.client.put(
            "/api/v1/resilience/dr/config",
            json={
                "rpo_target_minutes": 10,
                "rto_target_minutes": 10,
                "backup_frequency_hours": 1,
                "backup_retention_days": 1,
                "cold_archive_retention_days": 1,
                "auto_restore_test_frequency_days": 1,
            },
            headers=self.viewer_headers,
        )
        self.assertEqual(resp_cfg.status_code, 403)


if __name__ == "__main__":
    unittest.main()

