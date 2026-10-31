"""Integration tests for MITRE ATT&CK Mapping REST API endpoints (Task P20)."""

import json
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel
from app.db.models.honeypot import HoneypotModel
from app.db.models.rule import DetectionRuleModel
from app.db.session import get_db
from app.main import app
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.mapping.evaluator import MappingEvaluator
from app.modules.mitre.mapping.registry import mapping_registry


class TestMappingApi(unittest.TestCase):
    """Verifies REST endpoints for querying mappings, reviews, statistics, and access control."""

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

        # Seed baseline ATT&CK catalogue
        fixture_path = Path(__file__).resolve().parent.parent.parent.parent / "app" / "modules" / "mitre" / "data" / "enterprise-attack-v14.1.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            bundle_dict = json.loads(f.read())
        MitreImporter.execute_import(
            db=self.db,
            raw_content=bundle_dict,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
            activate_immediately=True,
        )

        decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="Decoy Web",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="test_lab",
            status="ACTIVE",
        )
        self.db.add(decoy)

        rule = DetectionRuleModel(
            rule_id="AUTH-001",
            rule_name="Repeated Failures",
            rule_version="1.0",
            description="desc",
            category="AUTH",
            enabled=True,
            severity="MEDIUM",
            configuration={},
        )
        self.db.add(rule)

        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id="AUTH-001",
            detection_rule_version="1.0",
            title="Alert",
            summary="Summary",
            severity="MEDIUM",
            confidence=80,
            assessment_status="NEW",
            evidence_strength="MODERATE",
            source_address="192.168.1.5",
            observed_source_id="src-5",
            decoy_id="WEB-001",
            target_service="HTTP",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            generated_at=datetime.now(timezone.utc),
            detection_explanation="Explanation",
            recommendations={},
        )
        self.db.add(alert)
        self.db.commit()

        # Generate a test mapping
        evaluator = MappingEvaluator(registry=mapping_registry)
        event = {"event_category": "authentication", "outcome": "FAILURE"}
        mappings = evaluator.evaluate_alert(db=self.db, alert=alert, event=event)
        self.mapping = mappings[0]
        self.alert_id = alert_id

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()

    def test_list_mappings_paginated(self):
        """API-MAP-01: GET /api/v1/mitre/mappings returns paginated mappings."""
        res = self.client.get("/api/v1/mitre/mappings")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["technique_id"], "T1110")
        self.assertEqual(data["items"][0]["subtechnique_id"], "T1110.001")

    def test_get_mapping_detail_with_evidence(self):
        """API-MAP-02: GET /api/v1/mitre/mappings/{id} returns full mapping details with evidence items."""
        res = self.client.get(f"/api/v1/mitre/mappings/{self.mapping.mapping_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["technique_id"], "T1110")
        self.assertEqual(data["mapping_category"], "DIRECTLY_SUPPORTED")
        self.assertTrue(len(data["evidence"]) >= 1)

    def test_get_mappings_for_detection_endpoint(self):
        """API-MAP-03: GET /api/v1/detections/{detection_id}/mitre-mappings returns associated mappings."""
        res = self.client.get(f"/api/v1/detections/{self.alert_id}/mitre-mappings")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["rule_id"], "AUTH-001")

    def test_get_technique_detections_endpoint(self):
        """API-MAP-04: GET /api/v1/mitre/techniques/{technique_id}/detections returns mapped detections."""
        res = self.client.get("/api/v1/mitre/techniques/T1110/detections")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["technique_id"], "T1110")

    def test_get_statistics_endpoint(self):
        """API-MAP-05: GET /api/v1/mitre/mappings/statistics returns aggregated operational metrics."""
        res = self.client.get("/api/v1/mitre/mappings/statistics")
        self.assertEqual(res.status_code, 200)
        stats = res.json()
        self.assertEqual(stats["total_mappings"], 1)
        self.assertEqual(stats["directly_supported"], 1)
        self.assertEqual(stats["not_mapped_count"], 5)
        self.assertIn("T1110", stats["by_technique"])

    def test_review_mapping_authorization_enforced(self):
        """API-MAP-06: POST /api/v1/mitre/mappings/{id}/review requires analyst credentials."""
        review_body = {
            "action": "ACCEPT",
            "comment": "Confirmed brute-force attempts from telemetry.",
        }

        # Unauthorized request without headers is rejected with 403
        res_unauth = self.client.post(
            f"/api/v1/mitre/mappings/{self.mapping.mapping_id}/review",
            json=review_body,
        )
        self.assertEqual(res_unauth.status_code, 403)

        # Authorized request with Bearer token succeeds
        headers = {"Authorization": "Bearer snare-collector-key-dev-2026"}
        res_auth = self.client.post(
            f"/api/v1/mitre/mappings/{self.mapping.mapping_id}/review",
            json=review_body,
            headers=headers,
        )
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.json()
        self.assertEqual(data["new_status"], "ACCEPTED")


if __name__ == "__main__":
    unittest.main()

