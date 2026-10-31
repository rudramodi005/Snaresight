"""Automated tests for SnareSight Demonstration Lab & Synthetic Evaluation Subsystem."""

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
from app.db.models.security import UserModel
from app.db.models.honeypot import HoneypotModel
from app.db.models.response import ResponseCaseModel, EvidencePreservationHoldModel
from app.modules.security.crypto import hash_password, create_access_token


class TestDemoLabSuite(unittest.TestCase):
    """Test suite covering demonstration scenarios, quality metrics, and safe cleanup."""

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
        self.admin = self.db.query(UserModel).filter(UserModel.username == "admin_demo").first()
        if not self.admin:
            self.admin = UserModel(
                id=str(uuid.uuid4()),
                username="admin_demo",
                email="admin_demo@snaresight.internal",
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
        self.analyst = self.db.query(UserModel).filter(UserModel.username == "analyst_demo").first()
        if not self.analyst:
            self.analyst = UserModel(
                id=str(uuid.uuid4()),
                username="analyst_demo",
                email="analyst_demo@snaresight.internal",
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
        self.viewer = self.db.query(UserModel).filter(UserModel.username == "viewer_demo").first()
        if not self.viewer:
            self.viewer = UserModel(
                id=str(uuid.uuid4()),
                username="viewer_demo",
                email="viewer_demo@snaresight.internal",
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

        # Seed target decoy
        decoy = self.db.query(HoneypotModel).filter(HoneypotModel.decoy_id == "WEB-001").first()
        if not decoy:
            decoy = HoneypotModel(
                decoy_id="WEB-001",
                name="ApexCore Web Application Decoy",
                decoy_type="WEB_LOGIN",
                protocol="HTTP",
                environment="isolated_lab",
                status="ACTIVE",
            )
            self.db.add(decoy)
            self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_01_list_scenarios_catalog(self):
        """Test retrieving the scenario catalog with metadata and MITRE mappings."""
        resp = self.client.get("/api/v1/demo/scenarios", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 6)
        scenario_ids = [s["scenario_id"] for s in data]
        self.assertIn("SCENARIO_A", scenario_ids)
        self.assertIn("SCENARIO_B", scenario_ids)
        self.assertIn("SCENARIO_C", scenario_ids)
        self.assertIn("SCENARIO_D", scenario_ids)
        self.assertIn("SCENARIO_E", scenario_ids)
        self.assertIn("SCENARIO_F", scenario_ids)

    def test_02_run_scenario_a_repeated_login_failures(self):
        """Test executing Scenario A (AUTH-001 credential guessing)."""
        payload = {
            "scenario_type": "SCENARIO_A",
            "size": "SMALL",
            "seed": 42,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_A")
        self.assertEqual(res["events_generated"], 25)
        self.assertGreaterEqual(res["events_accepted"], 25)
        self.assertEqual(res["events_rejected"], 0)
        self.assertGreater(res["duration_ms"], 0)
        self.assertIn("AUTH-001", str(res))

    def test_03_run_scenario_b_username_enumeration(self):
        """Test executing Scenario B (AUTH-003 username enumeration)."""
        payload = {
            "scenario_type": "SCENARIO_B",
            "size": "SMALL",
            "seed": 101,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_B")
        self.assertEqual(res["events_generated"], 25)

    def test_04_run_scenario_c_path_traversal(self):
        """Test executing Scenario C (WEB-001 & WEB-002 path traversal)."""
        payload = {
            "scenario_type": "SCENARIO_C",
            "size": "SMALL",
            "seed": 202,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_C")

    def test_05_run_scenario_d_multi_session(self):
        """Test executing Scenario D (BEHAV-001 multi-session correlation)."""
        payload = {
            "scenario_type": "SCENARIO_D",
            "size": "SMALL",
            "seed": 303,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_D")
        self.assertGreaterEqual(res["sessions_created"], 2)

    def test_06_run_scenario_e_analyst_investigation(self):
        """Test executing Scenario E (Analyst case escalation & evidence preservation hold)."""
        payload = {
            "scenario_type": "SCENARIO_E",
            "size": "SMALL",
            "seed": 404,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_E")
        self.assertIn("escalated_case_id", res["details"])
        self.assertIn("evidence_hold_id", res["details"])

    def test_07_run_scenario_f_resilience_and_recovery(self):
        """Test executing Scenario F (Platform resilience & isolated sandbox restore)."""
        payload = {
            "scenario_type": "SCENARIO_F",
            "size": "SMALL",
            "seed": 505,
            "target_decoy_id": "WEB-001",
        }
        resp = self.client.post("/api/v1/demo/scenarios/run", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertEqual(res["scenario_type"], "SCENARIO_F")
        self.assertIn("resilience", res["details"])

    def test_08_get_detection_evaluation_metrics(self):
        """Test retrieving precision, recall, and F1 scores."""
        resp = self.client.get("/api/v1/demo/evaluation", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("overall_precision", data)
        self.assertIn("overall_recall", data)
        self.assertIn("overall_f1_score", data)
        self.assertIn("average_processing_latency_ms", data)
        self.assertIsInstance(data["rules_evaluated"], list)

    def test_09_export_demonstration_data(self):
        """Test exporting synthetic records with watermark."""
        resp = self.client.get("/api/v1/demo/export", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("SYNTHETIC DEMONSTRATION DATA", data["watermark"])
        self.assertIsInstance(data["events"], list)

    def test_10_cleanup_safety_and_retention_hold_protection(self):
        """Test dry-run cleanup and confirmed cleanup verifying retention holds are preserved."""
        # Dry-run
        dry_resp = self.client.post(
            "/api/v1/demo/cleanup", json={"dry_run": True}, headers=self.admin_headers
        )
        self.assertEqual(dry_resp.status_code, 200)
        dry_data = dry_resp.json()
        self.assertTrue(dry_data["dry_run"])
        self.assertGreater(dry_data["synthetic_events_found"], 0)
        self.assertGreaterEqual(dry_data["events_protected_by_hold"], 1)  # Protected by Scenario E hold
        self.assertEqual(dry_data["events_deleted"], 0)

        # Confirmed execution
        exec_resp = self.client.post(
            "/api/v1/demo/cleanup", json={"dry_run": False}, headers=self.admin_headers
        )
        self.assertEqual(exec_resp.status_code, 200)
        exec_data = exec_resp.json()
        self.assertFalse(exec_data["dry_run"])
        self.assertGreater(exec_data["events_deleted"], 0)
        # Held events must NOT be deleted
        self.assertGreaterEqual(exec_data["events_protected_by_hold"], 1)

    def test_11_rbac_privilege_enforcement(self):
        """Test that VIEWER role is forbidden from running scenarios or executing cleanup."""
        # Viewer cannot run scenario
        viewer_run = self.client.post(
            "/api/v1/demo/scenarios/run",
            json={"scenario_type": "SCENARIO_A", "size": "SMALL"},
            headers=self.viewer_headers,
        )
        self.assertEqual(viewer_run.status_code, 403)

        # Viewer cannot execute cleanup
        viewer_clean = self.client.post(
            "/api/v1/demo/cleanup",
            json={"dry_run": False},
            headers=self.viewer_headers,
        )
        self.assertEqual(viewer_clean.status_code, 403)


if __name__ == "__main__":
    unittest.main()

