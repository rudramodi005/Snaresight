"""Unit tests for Analyst Review Workflow (Task P20)."""

import json
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.alert import AlertModel
from app.db.models.honeypot import HoneypotModel
from app.db.models.intelligence import (
    AttackDetectionMappingModel,
    AttackMappingHistoryModel,
    AttackMappingReviewModel,
)
from app.db.models.rule import DetectionRuleModel
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.mapping.evaluator import MappingEvaluator
from app.modules.mitre.mapping.registry import mapping_registry
from app.modules.mitre.mapping.schemas import MappingReviewRequest, ReviewAction, ReviewStatus
from app.modules.mitre.mapping.service import MappingService


class TestMappingReview(unittest.TestCase):
    """Verifies analyst review state transitions, comment recording, and historical audit preservation."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed minimal fixtures
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

        alert = AlertModel(
            alert_id=uuid.uuid4(),
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

        evaluator = MappingEvaluator(registry=mapping_registry)
        event = {"event_category": "authentication", "outcome": "FAILURE"}
        mappings = evaluator.evaluate_alert(db=self.db, alert=alert, event=event)
        self.mapping = mappings[0]

    def tearDown(self):
        self.db.close()

    def test_analyst_accepts_mapping(self):
        """REV-01: Analyst review with ACCEPT action transitions status to ACCEPTED and records audit entry."""
        req = MappingReviewRequest(
            action=ReviewAction.ACCEPT,
            comment="Confirmed brute force pattern consistent with dictionary guessing telemetry.",
        )
        res = MappingService.submit_review(
            db=self.db,
            mapping_id=str(self.mapping.mapping_id),
            req=req,
            reviewer_id="analyst_alice",
        )

        self.assertEqual(res.new_status, ReviewStatus.ACCEPTED)
        self.assertEqual(res.reviewed_by, "analyst_alice")

        # Verify DB model
        row = self.db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.id == self.mapping.id).first()
        self.assertEqual(row.review_status, "ACCEPTED")
        self.assertEqual(row.reviewed_by, "analyst_alice")
        self.assertIn("Confirmed brute force", row.review_comment)

        # Verify audit review record
        review_rec = self.db.query(AttackMappingReviewModel).filter(AttackMappingReviewModel.mapping_id == self.mapping.id).first()
        self.assertIsNotNone(review_rec)
        self.assertEqual(review_rec.review_action, "ACCEPT")

        # Verify history trace
        hist = self.db.query(AttackMappingHistoryModel).filter(
            AttackMappingHistoryModel.mapping_id == self.mapping.id,
            AttackMappingHistoryModel.change_reason == "ANALYST_REVIEW",
        ).first()
        self.assertIsNotNone(hist)
        self.assertEqual(hist.new_status, "ACCEPTED")

    def test_analyst_rejects_mapping(self):
        """REV-02: Analyst review with REJECT action transitions status to REJECTED."""
        req = MappingReviewRequest(
            action=ReviewAction.REJECT,
            comment="Telemetry reflects client misconfiguration rather than malicious adversary behavior.",
        )
        res = MappingService.submit_review(
            db=self.db,
            mapping_id=str(self.mapping.mapping_id),
            req=req,
            reviewer_id="senior_analyst_bob",
        )

        self.assertEqual(res.new_status, ReviewStatus.REJECTED)
        row = self.db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.id == self.mapping.id).first()
        self.assertEqual(row.review_status, "REJECTED")

    def test_analyst_requests_more_evidence(self):
        """REV-03: Analyst review with REQUEST_MORE_EVIDENCE transitions status to NEEDS_MORE_EVIDENCE."""
        req = MappingReviewRequest(
            action=ReviewAction.REQUEST_MORE_EVIDENCE,
            comment="Need verification of user agent headers and external IP reputation.",
        )
        res = MappingService.submit_review(
            db=self.db,
            mapping_id=str(self.mapping.mapping_id),
            req=req,
            reviewer_id="analyst_charlie",
        )

        self.assertEqual(res.new_status, ReviewStatus.NEEDS_MORE_EVIDENCE)
        row = self.db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.id == self.mapping.id).first()
        self.assertEqual(row.review_status, "NEEDS_MORE_EVIDENCE")


if __name__ == "__main__":
    unittest.main()

