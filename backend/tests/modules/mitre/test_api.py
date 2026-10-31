"""Integration tests for FastAPI MITRE ATT&CK catalogue exploration and admin endpoints."""

import json
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.modules.mitre.importer import MitreImporter


class TestMitreApi(unittest.TestCase):
    """Test suite covering REST endpoints for MITRE ATT&CK catalogue."""

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

        # Load verified sample STIX bundle fixture
        fixture_path = Path(__file__).resolve().parent.parent.parent.parent / "app" / "modules" / "mitre" / "data" / "enterprise-attack-v14.1.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.sample_bundle_dict = json.loads(f.read())

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()

    def test_get_status_empty_catalogue(self):
        """API-01: Status endpoint returns catalogue_available=False before import."""
        res = self.client.get("/api/v1/mitre/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["catalogue_available"])
        self.assertEqual(data["health_status"], "EMPTY")
        self.assertEqual(data["total_tactics"], 0)

    def test_import_and_query_status(self):
        """API-02: After successful import, status reports HEALTHY with accurate counts."""
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            dataset_version="14.1",
            activate_immediately=True,
        )
        res = self.client.get("/api/v1/mitre/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["catalogue_available"])
        self.assertEqual(data["active_version"], "14.1")
        self.assertEqual(data["total_tactics"], 8)
        self.assertGreaterEqual(data["total_techniques"], 10)

    def test_list_tactics_and_detail(self):
        """API-03: Listing and retrieving tactics succeeds."""
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            dataset_version="14.1",
            activate_immediately=True,
        )
        res = self.client.get("/api/v1/mitre/tactics")
        self.assertEqual(res.status_code, 200)
        tactics = res.json()
        self.assertEqual(len(tactics), 8)

        # Detail query by TA0006
        res_det = self.client.get("/api/v1/mitre/tactics/TA0006")
        self.assertEqual(res_det.status_code, 200)
        self.assertEqual(res_det.json()["short_name"], "credential-access")

        # Non-existent tactic returns 404
        res_404 = self.client.get("/api/v1/mitre/tactics/TA9999")
        self.assertEqual(res_404.status_code, 404)

    def test_list_techniques_with_pagination_and_search(self):
        """API-04: Techniques query supports pagination, search, and tactic filter."""
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            dataset_version="14.1",
            activate_immediately=True,
        )
        # Search for T1110
        res = self.client.get("/api/v1/mitre/techniques?search=Brute")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["technique_id"], "T1110")

        # Filter by tactic Initial Access
        res_tac = self.client.get("/api/v1/mitre/techniques?tactic=Initial Access")
        self.assertEqual(res_tac.status_code, 200)
        self.assertGreaterEqual(res_tac.json()["total"], 1)

    def test_get_technique_and_subtechniques(self):
        """API-05: Technique detail includes sub-techniques."""
        MitreImporter.execute_import(
            db=self.db,
            raw_content=self.sample_bundle_dict,
            dataset_version="14.1",
            activate_immediately=True,
        )
        res = self.client.get("/api/v1/mitre/techniques/T1110")
        self.assertEqual(res.status_code, 200)
        tech = res.json()
        self.assertEqual(tech["technique_name"], "Brute Force")
        self.assertGreaterEqual(len(tech["subtechniques"]), 2)

        # Subtechniques list endpoint
        res_sub = self.client.get("/api/v1/mitre/techniques/T1110/subtechniques")
        self.assertEqual(res_sub.status_code, 200)
        self.assertGreaterEqual(len(res_sub.json()), 2)

        # Subtechnique direct endpoint
        res_sub_item = self.client.get("/api/v1/mitre/subtechniques/T1110.001")
        self.assertEqual(res_sub_item.status_code, 200)
        self.assertEqual(res_sub_item.json()["subtechnique_name"], "Password Guessing")

    def test_administrative_access_control(self):
        """API-06: Administrative endpoints require authorized credentials."""
        # Unauthenticated request is rejected with 403
        res_dry = self.client.post("/api/v1/mitre/import/dry-run", json=self.sample_bundle_dict)
        self.assertEqual(res_dry.status_code, 403)

        res_app = self.client.post("/api/v1/mitre/import/approve", json=self.sample_bundle_dict)
        self.assertEqual(res_app.status_code, 403)

        res_imp = self.client.get("/api/v1/mitre/imports")
        self.assertEqual(res_imp.status_code, 403)

        # Authorized request with Bearer token succeeds
        headers = {"Authorization": "Bearer snare-collector-key-dev-2026"}
        res_dry_auth = self.client.post("/api/v1/mitre/import/dry-run", json=self.sample_bundle_dict, headers=headers)
        self.assertEqual(res_dry_auth.status_code, 200)
        self.assertTrue(res_dry_auth.json()["is_valid"])

        res_imp_auth = self.client.get("/api/v1/mitre/imports", headers=headers)
        self.assertEqual(res_imp_auth.status_code, 200)


if __name__ == "__main__":
    unittest.main()
