"""Integration tests for MITRE ATT&CK Mapping Evaluation Engine (Task P20)."""

import json
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.honeypot import HoneypotModel
from app.db.models.intelligence import (
    AttackDatasetVersionModel,
    AttackDetectionMappingModel,
    AttackMappingEvidenceModel,
    AttackMappingHistoryModel,
    AttackTechniqueModel,
)
from app.db.models.rule import DetectionRuleModel
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.mapping.evaluator import MappingEvaluator
from app.modules.mitre.mapping.registry import mapping_registry


class TestMappingEvaluator(unittest.TestCase):
    """Verifies mapping evaluation, idempotency, evidence protection, and database persistence."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed verified baseline ATT&CK catalogue
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

        # Seed Honeypot & Detection Rule in DB
        decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="Decoy Web",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="test_lab",
            status="ACTIVE",
        )
        self.db.add(decoy)

        rule_auth = DetectionRuleModel(
            rule_id="AUTH-001",
            rule_name="Repeated Authentication Failures",
            rule_version="1.0",
            description="Auth failures",
            category="AUTHENTICATION",
            enabled=True,
            severity="MEDIUM",
            configuration={},
        )
        self.db.add(rule_auth)
        self.db.commit()

        self.evaluator = MappingEvaluator(registry=mapping_registry)

    def tearDown(self):
        self.db.close()

    def _create_test_alert(self, rule_id: str = "AUTH-001") -> AlertModel:
        """Helper to create and commit a test AlertModel."""
        alert_id = uuid.uuid4()
        alert = AlertModel(
            alert_id=alert_id,
            schema_version="1.0",
            detection_rule_id=rule_id,
            detection_rule_version="1.0",
            title=f"Test Alert {rule_id}",
            summary="Test summary",
            severity="MEDIUM",
            confidence=85,
            assessment_status="NEW",
            evidence_strength="MODERATE",
            source_address="192.168.1.100",
            observed_source_id="src-test-01",
            decoy_id="WEB-001",
            target_service="HTTP_LOGIN",
            first_observed_at=datetime.now(timezone.utc),
            last_observed_at=datetime.now(timezone.utc),
            generated_at=datetime.now(timezone.utc),
            detection_explanation="Test detection",
            recommendations={},
        )
        self.db.add(alert)
        self.db.commit()
        return alert

    def test_evaluate_auth_001_generates_evidence_backed_mapping(self):
        """EVAL-01: Evaluating AUTH-001 finding creates T1110 mapping and evidence records."""
        alert = self._create_test_alert("AUTH-001")
        event = {
            "event_id": str(uuid.uuid4()),
            "event_category": "authentication",
            "event_type": "web_login",
            "outcome": "FAILURE",
            "source_ip": "192.168.1.100",
            "session_id": "sess-test-01",
            "metadata": {"username_fingerprint": "abc123sha", "http_path": "/login"},
        }
        related = [str(uuid.uuid4()), str(uuid.uuid4())]

        mappings = self.evaluator.evaluate_alert(
            db=self.db,
            alert=alert,
            event=event,
            related_event_ids=related,
        )

        self.assertEqual(len(mappings), 1)
        m = mappings[0]
        self.assertEqual(m.technique_id, "T1110")
        self.assertEqual(m.subtechnique_id, "T1110.001")
        self.assertEqual(m.rule_id, "AUTH-001")
        self.assertEqual(m.mapping_category, "DIRECTLY_SUPPORTED")
        self.assertEqual(m.review_status, "PENDING")
        self.assertTrue(m.mapping_confidence >= 80)

        # Check evidence records
        ev_count = self.db.query(AttackMappingEvidenceModel).filter(AttackMappingEvidenceModel.mapping_id == m.id).count()
        self.assertEqual(ev_count, 3)  # 1 triggering + 2 corroborating

        # Check history record
        hist = self.db.query(AttackMappingHistoryModel).filter(AttackMappingHistoryModel.mapping_id == m.id).first()
        self.assertIsNotNone(hist)
        self.assertEqual(hist.change_reason, "INITIAL_EVALUATION")

    def test_repeated_evaluation_is_idempotent(self):
        """EVAL-02: Repeated evaluation of identical alert returns existing mapping without row duplication."""
        alert = self._create_test_alert("AUTH-001")
        event = {
            "event_id": str(uuid.uuid4()),
            "event_category": "authentication",
            "outcome": "FAILURE",
        }

        # First evaluation
        m1 = self.evaluator.evaluate_alert(db=self.db, alert=alert, event=event)
        self.assertEqual(len(m1), 1)
        count1 = self.db.query(AttackDetectionMappingModel).count()

        # Repeated evaluation
        m2 = self.evaluator.evaluate_alert(db=self.db, alert=alert, event=event)
        self.assertEqual(len(m2), 1)
        count2 = self.db.query(AttackDetectionMappingModel).count()

        self.assertEqual(count1, count2)
        self.assertEqual(m1[0].id, m2[0].id)

    def test_missing_required_evidence_skips_mapping(self):
        """EVAL-03: Event missing required evidence field (e.g. outcome) is not mapped."""
        alert = self._create_test_alert("AUTH-001")
        # Missing 'outcome'
        bad_event = {
            "event_id": str(uuid.uuid4()),
            "event_category": "authentication",
        }

        mappings = self.evaluator.evaluate_alert(db=self.db, alert=alert, event=bad_event)
        self.assertEqual(len(mappings), 0)

    def test_exclusion_condition_prevents_mapping(self):
        """EVAL-04: Event matching exclusion criteria (e.g. outcome=SUCCESS for AUTH-001) is not mapped to T1110."""
        alert = self._create_test_alert("AUTH-001")
        # Outcome is SUCCESS, which contradicts brute-force failure requirement
        success_event = {
            "event_id": str(uuid.uuid4()),
            "event_category": "authentication",
            "outcome": "SUCCESS",
        }

        mappings = self.evaluator.evaluate_alert(db=self.db, alert=alert, event=success_event)
        self.assertEqual(len(mappings), 0)

    def test_zero_passwords_stored_in_mapping_evidence(self):
        """EVAL-05: Invariant check - Prohibited password fields are omitted from mapping evidence fields."""
        alert = self._create_test_alert("AUTH-001")
        event_with_creds = {
            "event_id": str(uuid.uuid4()),
            "event_category": "authentication",
            "outcome": "FAILURE",
            "metadata": {
                "password": "PROHIBITED_PLAINTEXT_SECRET",
                "auth_token": "TOKEN_SECRET",
                "http_path": "/login",
            },
        }

        mappings = self.evaluator.evaluate_alert(db=self.db, alert=alert, event=event_with_creds)
        self.assertEqual(len(mappings), 1)

        ev = self.db.query(AttackMappingEvidenceModel).filter(AttackMappingEvidenceModel.mapping_id == mappings[0].id).first()
        self.assertNotIn("password", ev.evidence_fields.get("metadata", {}))
        self.assertNotIn("auth_token", ev.evidence_fields.get("metadata", {}))
        self.assertIn("http_path", ev.evidence_fields.get("metadata", {}))


if __name__ == "__main__":
    unittest.main()

