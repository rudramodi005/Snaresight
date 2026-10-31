"""Automated unit and integration test suite for Honeypot Sensor Management (Task P33).

Verifies sensor inventory, per-sensor authentication, anti-impersonation,
heartbeat processing, health engine state transitions, versioned configuration,
maintenance mode, and segregated operational alerts.
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
from app.db.models.sensor import (
    SensorModel,
    SensorCredentialModel,
    SensorHeartbeatModel,
    SensorConfigurationModel,
    OperationalAlertModel,
    SensorMaintenanceHistoryModel,
)
from app.db.models.security import UserModel
from app.modules.security.crypto import hash_password, create_access_token
from app.modules.sensors.health_engine import SensorHealthEngine


class TestSensorManagementSuite(unittest.TestCase):
    """Integration test suite verifying Honeypot Sensor Operations and Health Monitoring."""

    @classmethod
    def setUpClass(cls):
        # Configure in-memory SQLite database
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

        # Seed test admin user
        self.admin_user = (
            self.db.query(UserModel).filter(UserModel.username == "admin_sensor_lead").first()
        )
        if not self.admin_user:
            self.admin_user = UserModel(
                id=str(uuid.uuid4()),
                username="admin_sensor_lead",
                email="admin_sensor_lead@snaresight.internal",
                hashed_password=hash_password("SuperSecretSensorPass2026!"),
                role="ADMIN",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            self.db.add(self.admin_user)
            self.db.commit()

        t_admin, _ = create_access_token(
            {"sub": self.admin_user.username, "user_id": self.admin_user.id, "role": "ADMIN"}
        )
        self.auth_headers = {"Authorization": f"Bearer {t_admin}"}

    def tearDown(self):
        self.db.close()

    def test_01_register_sensor_and_credentials(self):
        """TEST SENS-001: Register a new sensor and verify unrecoverable API key is returned."""
        payload = {
            "sensor_id": "SENSOR-WEB-001",
            "name": "ApexCore SSO Portal Decoy",
            "sensor_type": "WEB_LOGIN_DECOY",
            "sensor_version": "1.0.0",
            "deployment_environment": "isolated_lab",
            "lab_zone": "dmz_zone_alpha",
            "heartbeat_interval_seconds": 30,
            "supported_telemetry_types": ["http_request", "auth_attempt"],
            "admin_notes": "Primary deceptive login portal for enterprise SSO honeynet.",
        }

        res = self.client.post("/api/v1/sensors", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 201)
        data = res.json()

        self.assertIn("raw_api_key", data)
        self.assertTrue(data["raw_api_key"].startswith("snr_live_"))
        self.assertEqual(data["sensor"]["sensor_id"], "SENSOR-WEB-001")
        self.assertEqual(data["sensor"]["operational_status"], "REGISTERED")
        self.assertEqual(data["credential"]["status"], "ACTIVE")
        self.assertTrue(data["credential"]["key_prefix"].startswith("snr_live_"))

    def test_02_duplicate_sensor_registration_rejected(self):
        """TEST SENS-002: Verifies registering existing sensor ID returns 400 Bad Request."""
        payload = {
            "sensor_id": "SENSOR-WEB-001",
            "name": "Duplicate Sensor",
            "sensor_type": "WEB_LOGIN_DECOY",
        }
        res = self.client.post("/api/v1/sensors", json=payload, headers=self.auth_headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("already registered", res.json()["detail"])

    def test_03_query_sensor_inventory_and_detail(self):
        """TEST SENS-003: Query sensor inventory list and individual detail workspace."""
        # Query list
        res = self.client.get("/api/v1/sensors", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total"], 1)

        # Query detail
        res_detail = self.client.get("/api/v1/sensors/SENSOR-WEB-001", headers=self.auth_headers)
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(detail["sensor_id"], "SENSOR-WEB-001")
        self.assertEqual(len(detail["credentials"]), 1)
        # Verify raw secret is NOT leaked in detail response
        self.assertNotIn("raw_api_key", detail["credentials"][0])
        self.assertNotIn("hashed_api_key", detail["credentials"][0])
        self.assertIn("key_prefix", detail["credentials"][0])

    def test_04_sensor_heartbeat_processing(self):
        """TEST SENS-004: Submit authenticated heartbeat via X-Sensor-Key and verify health update."""
        # First register a dedicated sensor to get raw key
        reg_payload = {
            "sensor_id": "SENSOR-COWRIE-01",
            "name": "Linux SSH Decoy Node",
            "sensor_type": "COWRIE_SSH",
            "heartbeat_interval_seconds": 60,
        }
        reg_res = self.client.post("/api/v1/sensors", json=reg_payload, headers=self.auth_headers)
        raw_key = reg_res.json()["raw_api_key"]

        # Submit heartbeat
        hb_payload = {
            "sensor_id": "SENSOR-COWRIE-01",
            "status": "HEALTHY",
            "latency_ms": 14.5,
            "metrics_payload": {
                "cpu_percent": 8.2,
                "memory_mb": 185.0,
                "events_buffered": 0,
            },
        }
        hb_res = self.client.post(
            "/api/v1/sensors/heartbeat",
            json=hb_payload,
            headers={"X-Sensor-Key": raw_key},
        )
        self.assertEqual(hb_res.status_code, 200)
        hb_data = hb_res.json()
        self.assertEqual(hb_data["sensor_id"], "SENSOR-COWRIE-01")
        self.assertEqual(hb_data["status"], "HEALTHY")

        # Verify sensor record now ACTIVE and HEALTHY
        det_res = self.client.get("/api/v1/sensors/SENSOR-COWRIE-01", headers=self.auth_headers)
        det = det_res.json()
        self.assertEqual(det["operational_status"], "ACTIVE")
        self.assertEqual(det["health_status"], "HEALTHY")
        self.assertEqual(det["missed_heartbeat_count"], 0)
        self.assertIsNotNone(det["last_heartbeat_at"])

    def test_05_anti_impersonation_enforcement(self):
        """TEST SENS-005: Prohibit sensor A from submitting heartbeats claiming to be sensor B."""
        # Get key for SENSOR-COWRIE-01
        creds = (
            self.db.query(SensorCredentialModel)
            .filter(SensorCredentialModel.sensor_id == "SENSOR-COWRIE-01")
            .first()
        )
        # Attempt to spoof SENSOR-WEB-001 using COWRIE key
        # We need the raw key; let's rotate SENSOR-COWRIE-01 to get fresh key
        rot = self.client.post("/api/v1/sensors/SENSOR-COWRIE-01/credentials/rotate", headers=self.auth_headers)
        cowrie_key = rot.json()["raw_api_key"]

        spoof_payload = {
            "sensor_id": "SENSOR-WEB-001",  # Spoofed identity
            "status": "HEALTHY",
        }
        res = self.client.post(
            "/api/v1/sensors/heartbeat",
            json=spoof_payload,
            headers={"X-Sensor-Key": cowrie_key},
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("impersonation prohibited", res.json()["detail"])

    def test_06_credential_rotation_and_revocation(self):
        """TEST SENS-006: Rotate credentials, verify old key rejected and new key accepted."""
        # 1. Rotate credentials for SENSOR-WEB-001
        rot_res = self.client.post(
            "/api/v1/sensors/SENSOR-WEB-001/credentials/rotate", headers=self.auth_headers
        )
        self.assertEqual(rot_res.status_code, 200)
        new_key = rot_res.json()["raw_api_key"]
        new_key_id = rot_res.json()["credential"]["key_id"]

        # 2. Test new key works
        hb_payload = {"sensor_id": "SENSOR-WEB-001", "status": "HEALTHY"}
        res_ok = self.client.post(
            "/api/v1/sensors/heartbeat", json=hb_payload, headers={"X-Sensor-Key": new_key}
        )
        self.assertEqual(res_ok.status_code, 200)

        # 3. Explicitly revoke the new credential
        revoke_res = self.client.post(
            f"/api/v1/sensors/SENSOR-WEB-001/credentials/{new_key_id}/revoke?reason=Emergency+Containment",
            headers=self.auth_headers,
        )
        self.assertEqual(revoke_res.status_code, 200)
        self.assertEqual(revoke_res.json()["status"], "REVOKED")

        # 4. Now the revoked key must be rejected with 401
        res_revoked = self.client.post(
            "/api/v1/sensors/heartbeat", json=hb_payload, headers={"X-Sensor-Key": new_key}
        )
        self.assertEqual(res_revoked.status_code, 401)
        self.assertIn("Invalid or revoked", res_revoked.json()["detail"])

    def test_07_health_classification_and_operational_alerts(self):
        """TEST SENS-007: Simulate missed heartbeats triggering DEGRADED and OFFLINE operational alerts."""
        # Register a test sensor
        reg = self.client.post(
            "/api/v1/sensors",
            json={
                "sensor_id": "SENSOR-HEALTH-TEST",
                "name": "Health Test Sensor",
                "heartbeat_interval_seconds": 20,
            },
            headers=self.auth_headers,
        )
        raw_key = reg.json()["raw_api_key"]

        # Send initial heartbeat at T0
        t0 = datetime.now(timezone.utc) - timedelta(seconds=70)  # 3.5 intervals ago (> 2.5x)
        sensor = self.db.query(SensorModel).filter(SensorModel.sensor_id == "SENSOR-HEALTH-TEST").first()
        sensor.last_heartbeat_at = t0
        self.db.commit()

        # Run health evaluation
        op_stat, h_stat = SensorHealthEngine.evaluate_sensor_health(self.db, sensor)
        self.db.commit()

        # Should be DEGRADED with SENSOR_HEARTBEAT_OVERDUE alert
        self.assertEqual(op_stat, "DEGRADED")
        self.assertEqual(h_stat, "DEGRADED")

        alerts_res = self.client.get(
            "/api/v1/sensors/alerts/operational?sensor_id=SENSOR-HEALTH-TEST",
            headers=self.auth_headers,
        )
        self.assertEqual(alerts_res.status_code, 200)
        alerts = alerts_res.json()["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_category"], "SENSOR_HEARTBEAT_OVERDUE")
        self.assertEqual(alerts[0]["status"], "OPEN")

        # Now simulate elapsed > 5x interval (e.g. 150s ago for 20s interval)
        sensor.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(seconds=150)
        self.db.commit()

        op_stat, h_stat = SensorHealthEngine.evaluate_sensor_health(self.db, sensor)
        self.db.commit()
        self.assertEqual(op_stat, "OFFLINE")
        self.assertEqual(h_stat, "CRITICAL")

        # Now restore heartbeat and verify recovery
        rec_res = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={"sensor_id": "SENSOR-HEALTH-TEST", "status": "HEALTHY"},
            headers={"X-Sensor-Key": raw_key},
        )
        self.assertEqual(rec_res.status_code, 200)

        # Confirm operational alert was auto-resolved
        alert_rec = (
            self.db.query(OperationalAlertModel)
            .filter(
                OperationalAlertModel.sensor_id == "SENSOR-HEALTH-TEST",
                OperationalAlertModel.alert_category == "SENSOR_OFFLINE",
            )
            .first()
        )
        self.assertIsNotNone(alert_rec)
        self.assertEqual(alert_rec.status, "RESOLVED")
        self.assertIn("reconnected", alert_rec.resolution_notes)

    def test_08_versioned_configuration_and_rollback(self):
        """TEST SENS-008: Commit versioned configuration and test rollback."""
        # Commit v1.1.0
        cfg_payload = {
            "version": "1.1.0",
            "config_payload": {
                "heartbeat_interval_seconds": 45,
                "log_level": "DEBUG",
                "deception_latency_ms": 250,
            },
            "change_reason": "Enable debug logging for active reconnaissance investigation",
        }
        res = self.client.post(
            "/api/v1/sensors/SENSOR-HEALTH-TEST/configurations",
            json=cfg_payload,
            headers=self.auth_headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["version"], "1.1.0")
        self.assertTrue(res.json()["is_current"])

        # Rollback to v1.0.0
        rb_payload = {
            "target_version": "1.0.0",
            "change_reason": "Investigation completed, restoring baseline config",
        }
        rb_res = self.client.post(
            "/api/v1/sensors/SENSOR-HEALTH-TEST/configurations/rollback",
            json=rb_payload,
            headers=self.auth_headers,
        )
        self.assertEqual(rb_res.status_code, 200)
        self.assertEqual(rb_res.json()["version"], "1.0.0")
        self.assertTrue(rb_res.json()["is_current"])

    def test_09_maintenance_mode_lifecycle(self):
        """TEST SENS-009: Toggle maintenance mode and verify maintenance audit history."""
        # Enter maintenance
        m_on = self.client.post(
            "/api/v1/sensors/SENSOR-HEALTH-TEST/maintenance",
            json={"enabled": True, "reason": "Applying security patch to host OS"},
            headers=self.auth_headers,
        )
        self.assertEqual(m_on.status_code, 200)
        self.assertEqual(m_on.json()["operational_status"], "MAINTENANCE")

        # Exit maintenance
        m_off = self.client.post(
            "/api/v1/sensors/SENSOR-HEALTH-TEST/maintenance",
            json={"enabled": False, "reason": "Patch applied successfully"},
            headers=self.auth_headers,
        )
        self.assertEqual(m_off.status_code, 200)
        self.assertEqual(m_off.json()["operational_status"], "ACTIVE")

    def test_10_operational_alert_acknowledgement_and_resolution(self):
        """TEST SENS-010: Manual analyst acknowledgement and resolution of operational alerts."""
        # Create an operational alert manually
        alert = SensorHealthEngine.create_or_update_operational_alert(
            db=self.db,
            sensor_id="SENSOR-WEB-001",
            alert_category="TELEMETRY_INGESTION_FAILURE",
            severity="HIGH",
            evidence={"failed_batches": 3, "last_error": "JSON schema validation error"},
            recommended_action="Inspect forwarder daemon logs for malformed payload.",
        )
        self.db.commit()

        # Acknowledge
        ack_res = self.client.post(
            f"/api/v1/sensors/alerts/{alert.alert_id}/acknowledge",
            headers=self.auth_headers,
        )
        self.assertEqual(ack_res.status_code, 200)
        self.assertEqual(ack_res.json()["status"], "ACKNOWLEDGED")

        # Resolve
        res_res = self.client.post(
            f"/api/v1/sensors/alerts/{alert.alert_id}/resolve",
            json={"resolution_notes": "Upgraded forwarder schema adapter, all batches valid."},
            headers=self.auth_headers,
        )
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "RESOLVED")
        self.assertEqual(res_res.json()["resolution_notes"], "Upgraded forwarder schema adapter, all batches valid.")

    def test_11_sensor_operations_summary(self):
        """TEST SENS-011: Retrieve operations summary metrics."""
        res = self.client.get("/api/v1/sensors/summary", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        summary = res.json()
        self.assertGreaterEqual(summary["total_registered_sensors"], 1)
        self.assertIn("active_sensors", summary)
        self.assertIn("open_operational_alerts_count", summary)
        self.assertIn("sensors_by_type", summary)
        self.assertIn("sensors_by_environment", summary)

    def test_12_unauthorized_access_rejected(self):
        """TEST SENS-012: Enforce RBAC permissions on sensor management endpoints."""
        # Create viewer user without MANAGE_SENSORS permission
        viewer_user = UserModel(
            id=str(uuid.uuid4()),
            username="sensor_viewer_only",
            email="sensor_viewer@snaresight.internal",
            hashed_password=hash_password("ViewerPass123!"),
            role="VIEWER",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(viewer_user)
        self.db.commit()

        t_viewer, _ = create_access_token(
            {"sub": viewer_user.username, "user_id": viewer_user.id, "role": "VIEWER"}
        )
        viewer_headers = {"Authorization": f"Bearer {t_viewer}"}

        # Attempt to register sensor as viewer -> 403 Forbidden
        reg_res = self.client.post(
            "/api/v1/sensors",
            json={"sensor_id": "SENSOR-FORBIDDEN", "name": "Illegal Sensor"},
            headers=viewer_headers,
        )
        self.assertEqual(reg_res.status_code, 403)

    def test_13_end_to_end_sensor_reliability_lifecycle(self):
        """TEST SENS-013: Complete end-to-end sensor registration, heartbeat, degradation, recovery, and rotation."""
        # 1. Register synthetic sensor
        reg_res = self.client.post(
            "/api/v1/sensors",
            json={
                "sensor_id": "SENSOR-E2E-RELIABILITY",
                "name": "E2E Deception Sensor",
                "sensor_type": "WEB_LOGIN_DECOY",
                "heartbeat_interval_seconds": 30,
            },
            headers=self.auth_headers,
        )
        self.assertEqual(reg_res.status_code, 201)
        cred1 = reg_res.json()["raw_api_key"]

        # 2. Authenticate and send initial heartbeat
        hb1 = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={"sensor_id": "SENSOR-E2E-RELIABILITY", "status": "HEALTHY", "latency_ms": 12.0},
            headers={"X-Sensor-Key": cred1},
        )
        self.assertEqual(hb1.status_code, 200)

        # 3. Verify status ACTIVE
        det1 = self.client.get("/api/v1/sensors/SENSOR-E2E-RELIABILITY", headers=self.auth_headers)
        self.assertEqual(det1.json()["operational_status"], "ACTIVE")
        self.assertEqual(det1.json()["health_status"], "HEALTHY")

        # 4. Simulate heartbeat timeout (3.0x interval -> 90s)
        sensor = self.db.query(SensorModel).filter(SensorModel.sensor_id == "SENSOR-E2E-RELIABILITY").first()
        sensor.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(seconds=90)
        self.db.commit()

        # Run health check
        SensorHealthEngine.evaluate_sensor_health(self.db, sensor)
        self.db.commit()

        # 5. Verify degraded
        det2 = self.client.get("/api/v1/sensors/SENSOR-E2E-RELIABILITY", headers=self.auth_headers)
        self.assertEqual(det2.json()["operational_status"], "DEGRADED")
        self.assertEqual(det2.json()["health_status"], "DEGRADED")

        # 6. Restore heartbeat -> verify recovery
        hb2 = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={"sensor_id": "SENSOR-E2E-RELIABILITY", "status": "HEALTHY", "latency_ms": 8.0},
            headers={"X-Sensor-Key": cred1},
        )
        self.assertEqual(hb2.status_code, 200)

        det3 = self.client.get("/api/v1/sensors/SENSOR-E2E-RELIABILITY", headers=self.auth_headers)
        self.assertEqual(det3.json()["operational_status"], "ACTIVE")
        self.assertEqual(det3.json()["health_status"], "HEALTHY")

        # 7. Rotate credential -> verify old key rejected and new key active
        rot = self.client.post(
            "/api/v1/sensors/SENSOR-E2E-RELIABILITY/credentials/rotate", headers=self.auth_headers
        )
        self.assertEqual(rot.status_code, 200)
        cred2 = rot.json()["raw_api_key"]

        # Old key rejected
        hb_old = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={"sensor_id": "SENSOR-E2E-RELIABILITY", "status": "HEALTHY"},
            headers={"X-Sensor-Key": cred1},
        )
        self.assertEqual(hb_old.status_code, 401)

        # New key accepted
        hb_new = self.client.post(
            "/api/v1/sensors/heartbeat",
            json={"sensor_id": "SENSOR-E2E-RELIABILITY", "status": "HEALTHY"},
            headers={"X-Sensor-Key": cred2},
        )
        self.assertEqual(hb_new.status_code, 200)


if __name__ == "__main__":
    unittest.main()
