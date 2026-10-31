"""Unit and integration tests for MITRE ATT&CK Threat Intelligence & Mapping Dashboard (Task P29)."""

import json
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app

from app.db.models.intelligence import (
    AttackDatasetVersionModel,
    AttackTacticModel,
    AttackTechniqueModel,
    AttackSubtechniqueModel,
    AttackDetectionMappingModel,
    AttackMappingReviewModel,
    AttackMappingHistoryModel,
)
from app.db.models.rule import DetectionRuleModel
from app.db.models.alert import AlertModel
from app.db.models.honeypot import HoneypotModel
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.dashboard_service import AttackDashboardService


class TestAttackDashboardBase(unittest.TestCase):
    """Base fixture initializing an in-memory SQLite database seeded with ATT&CK STIX bundle."""

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

        # Import sample STIX 2.1 bundle
        bundle_path = Path(__file__).resolve().parent.parent.parent.parent / "app" / "modules" / "mitre" / "data" / "enterprise-attack-v14.1.json"
        with open(bundle_path, "r", encoding="utf-8") as f:
            content = f.read()

        MitreImporter.execute_import(
            db=self.db,
            raw_content=content,
            source_filename="enterprise-attack-v14.1.json",
            dataset_version="14.1",
            dataset_domain="enterprise-attack",
            activate_immediately=True,
        )

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app.dependency_overrides.clear()

    def _seed_detection_rule(self, rule_id: str = "AUTH-001", rule_name: str = "Repeated Auth Failure") -> DetectionRuleModel:
        r = DetectionRuleModel(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_version="1.0.0",
            category="BRUTE_FORCE",
            severity="HIGH",
            description="Brute force authentication guessing rule",
            enabled=True,
            configuration={"conditions": []},
        )
        self.db.add(r)
        self.db.commit()
        return r

    def _seed_alert_and_mapping(
        self,
        rule_id: str = "AUTH-001",
        technique_id: str = "T1110",
        review_status: str = "ACCEPTED",
    ) -> Tuple[AlertModel, AttackDetectionMappingModel]:
        hp = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(hp)
        self.db.flush()

        now_utc = datetime.now(timezone.utc)
        alt = AlertModel(
            alert_id=uuid.uuid4(),
            schema_version="1.0",
            detection_rule_id=rule_id,
            detection_rule_version="1.0.0",
            title=f"Alert for {rule_id}",
            summary="Brute force login observed on decoy",
            severity="HIGH",
            confidence=85,
            assessment_status="NEW",
            evidence_strength="STRONG",
            source_address="192.168.10.45",
            observed_source_id="obs-src-1",
            decoy_id="WEB-001",
            target_service="WEB_LOGIN",
            first_observed_at=now_utc,
            last_observed_at=now_utc,
            generated_at=now_utc,
            detection_explanation="Exceeded burst threshold",
            recommendations={"action": "Triage"},
        )
        self.db.add(alt)
        self.db.flush()

        mapping = AttackDetectionMappingModel(
            mapping_id=uuid.uuid4(),
            detection_result_id="det-001",
            alert_id=alt.alert_id,
            rule_id=rule_id,
            rule_version="1.0.0",
            technique_id=technique_id,
            dataset_version="14.1",
            mapping_definition_id="MAP-AUTH-001-T1110",
            mapping_category="DIRECTLY_SUPPORTED",
            mapping_confidence=85,
            mapping_confidence_level="HIGH",
            confidence_explanation="High confidence credential guessing pattern",
            mapping_rationale="Failed auth burst matches password guessing",
            review_status=review_status,
            assessed_at=now_utc,
        )
        self.db.add(mapping)
        self.db.commit()
        return alt, mapping


class TestAttackCatalogueAndSummary(TestAttackDashboardBase):
    """Tests for metadata, summary aggregation, and Enterprise tactic overviews."""

    def test_catalogue_metadata(self):
        """GET /api/v1/attack/catalogue/metadata returns active release version and provenance."""
        resp = self.client.get("/api/v1/attack/catalogue/metadata")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["domain"], "enterprise-attack")
        self.assertIn("14.1", data["version"])
        self.assertEqual(data["stix_version"], "2.1")
        self.assertTrue(data["is_active"])
        self.assertGreater(data["total_objects"], 0)

    def test_dashboard_summary_aggregation(self):
        """GET /api/v1/attack/summary aggregates catalogue counts, mappings, and live alert evidence."""
        self._seed_detection_rule(rule_id="AUTH-001")
        self._seed_detection_rule(rule_id="UNMAPPED-RULE-999")
        self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110")

        resp = self.client.get("/api/v1/attack/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["total_catalogue_techniques"], 0)
        self.assertGreater(data["total_catalogue_tactics"], 0)
        self.assertGreaterEqual(data["techniques_mapped_to_detections"], 1)
        self.assertGreaterEqual(data["techniques_with_alert_evidence"], 1)
        self.assertTrue(data["detection_rules_mapped"] >= 1)
        self.assertTrue(data["detection_rules_unmapped"] >= 1)

    def test_tactics_overview(self):
        """GET /api/v1/attack/tactics returns Enterprise tactics in canonical order with mapped counts."""
        self._seed_detection_rule(rule_id="AUTH-001")
        self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110")

        resp = self.client.get("/api/v1/attack/tactics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total_tactics"], 8)
        # Check Credential Access tactic has our mapped alert
        cred_tactic = next((t for t in data["tactics"] if t["tactic_id"] == "TA0006" or "Credential" in t["tactic_name"]), None)
        if cred_tactic:
            self.assertTrue(cred_tactic["mapped_techniques_count"] >= 1)


class TestInteractiveMatrixAndExplorer(TestAttackDashboardBase):
    """Tests for interactive matrix generation, visual states, and searchable technique explorer."""

    def test_matrix_structure_and_visual_states(self):
        """GET /api/v1/attack/matrix arranges techniques under tactics with accurate visual states."""
        self._seed_detection_rule(rule_id="AUTH-001")
        self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110", review_status="ACCEPTED")

        resp = self.client.get("/api/v1/attack/matrix")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("columns", data)
        self.assertIn("legend", data)
        self.assertIn("non_attribution_notice", data)

        # Locate cell for T1110
        all_cells = [cell for col in data["columns"] for cell in col["techniques"]]
        cell_t1110 = next((c for c in all_cells if c["technique_id"] == "T1110"), None)
        self.assertIsNotNone(cell_t1110)
        self.assertEqual(cell_t1110["mapping_status"], "ALERT_EVIDENCE")
        self.assertGreaterEqual(cell_t1110["alert_count"], 1)

    def test_techniques_explorer_search_and_pagination(self):
        """GET /api/v1/attack/techniques provides keyword search, status filtering, and pagination."""
        resp = self.client.get("/api/v1/attack/techniques?page=1&limit=5&sort_by=technique_id&sort_order=asc")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["total"], 0)
        self.assertEqual(len(data["items"]), min(5, data["total"]))

        # Keyword search
        resp_search = self.client.get("/api/v1/attack/techniques?search=Brute")
        self.assertEqual(resp_search.status_code, 200)
        search_data = resp_search.json()
        self.assertTrue(any("Brute" in item["technique_name"] or "T1110" in item["technique_id"] for item in search_data["items"]))

    def test_technique_detail_and_404(self):
        """GET /api/v1/attack/techniques/{id} returns full official details, mappings, and evidence."""
        self._seed_detection_rule(rule_id="AUTH-001")
        alt, mapping = self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110")

        resp = self.client.get("/api/v1/attack/techniques/T1110")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["technique_id"], "T1110")
        self.assertIn("mappings", data)
        self.assertIn("supporting_evidence", data)
        self.assertIn("limitations", data)
        self.assertTrue(len(data["supporting_evidence"]) >= 1)
        self.assertEqual(data["supporting_evidence"][0]["navigation_url"], f"/alerts?alert_id={alt.alert_id}")

        # 404 for non-existent technique
        resp_404 = self.client.get("/api/v1/attack/techniques/T999999")
        self.assertEqual(resp_404.status_code, 404)


class TestCoverageTraceabilityAndReview(TestAttackDashboardBase):
    """Tests for coverage analytics, end-to-end traceability chains, and analyst review workflow."""

    def test_coverage_analytics(self):
        """GET /api/v1/attack/coverage returns valid coverage percentages and tactic breakdowns."""
        self._seed_detection_rule(rule_id="AUTH-001")
        self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110")

        resp = self.client.get("/api/v1/attack/coverage")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["total_catalogue_techniques"], 0)
        self.assertGreater(data["total_mapped_techniques"], 0)
        self.assertTrue(data["overall_mapping_coverage_pct"] >= 0.0)
        self.assertIn("tactic_breakdown", data)
        self.assertGreater(len(data["tactic_breakdown"]), 0)

    def test_traceability_chain(self):
        """GET /api/v1/attack/traceability connects technique -> mapping -> rule -> alert -> navigation."""
        self._seed_detection_rule(rule_id="AUTH-001")
        alt, _ = self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110")

        resp = self.client.get("/api/v1/attack/traceability")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["total_traces"], 0)
        trace_t1110 = next((t for t in data["traces"] if t["technique_id"] == "T1110" and t["has_live_alert"]), None)
        self.assertIsNotNone(trace_t1110)
        self.assertEqual(trace_t1110["rule_id"], "AUTH-001")
        self.assertEqual(trace_t1110["alert_id"], str(alt.alert_id))

    def test_mapping_review_approval_and_rejection(self):
        """POST /api/v1/attack/mappings/{id}/approve & reject updates status and audit log."""
        self._seed_detection_rule(rule_id="AUTH-001")
        _, mapping = self._seed_alert_and_mapping(rule_id="AUTH-001", technique_id="T1110", review_status="PENDING")

        # 1. Approve mapping
        resp_app = self.client.post(
            f"/api/v1/attack/mappings/{mapping.mapping_id}/approve?analyst_id=analyst_sarah&comment=Approved+credential+guessing+evidence"
        )
        self.assertEqual(resp_app.status_code, 200)
        data_app = resp_app.json()
        self.assertEqual(data_app["new_status"], "ACCEPTED")

        # Verify audit record
        audit = self.db.query(AttackMappingReviewModel).filter(
            AttackMappingReviewModel.mapping_id == mapping.id
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.review_action, "ACCEPT")
        self.assertEqual(audit.reviewer_id, "analyst_sarah")

        # 2. Reject mapping
        resp_rej = self.client.post(
            f"/api/v1/attack/mappings/{mapping.mapping_id}/reject?analyst_id=analyst_sarah&comment=Evidence+insufficient"
        )
        self.assertEqual(resp_rej.status_code, 200)
        self.assertEqual(resp_rej.json()["new_status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()

