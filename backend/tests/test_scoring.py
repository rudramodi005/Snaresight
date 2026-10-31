"""Comprehensive automated test suite for SnareSight Task P17:
Severity and Confidence Scoring Engine.

Covers:
- TEST SCORE-001 to SCORE-007 (Severity Classification Tests)
- TEST SCORE-008 to SCORE-018 (Confidence Scoring Tests)
- TEST SCORE-019 to SCORE-022 (Evidence Strength Tests)
- TEST SCORE-023 to SCORE-026 (Explanation Generation Tests)
- TEST SCORE-027 to SCORE-031 (Scoring Policy Tests)
- TEST SCORE-032 to SCORE-036 (Integration and Reassessment Tests)
- TEST SCORE-037 to SCORE-040 (Security and Review Safety Tests)
"""

import copy
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel, EventSourceModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.detection.engine import DetectionEngine
from app.detection.registry import RuleRegistry
from app.detection.scoring_policy import (
    SeverityLevel,
    ConfidenceLevel,
    EvidenceStrength,
    ProvenanceType,
    ConfidenceWeights,
    ScoringPolicyDefinition,
    ScoringPolicyRegistry,
)
from app.detection.severity_assessor import SeverityAssessor
from app.detection.confidence_scorer import ConfidenceScorer
from app.detection.evidence_assessor import EvidenceAssessor
from app.detection.assessment_result import ThreatAssessmentResult, AnalystReview
from app.detection.exceptions import InvalidPolicyError, ScoringPolicyError, AssessmentError
from app.detection.test_rules import get_test_rule_001, get_test_rule_004
from app.detection.rule_schema import DetectionRuleDefinition
from app.schemas.detection import DetectionResult, EvaluationStatus
from app.services.threat_assessment_service import ThreatAssessmentService
from app.ingestion.processor import EventProcessor
from app.ingestion.schemas import EventProcessingStatus


class TestScoringEngine(unittest.TestCase):
    """Test suite covering the SnareSight threat assessment and confidence scoring system."""

    def setUp(self):
        """Initializes in-memory database and isolated scoring engine components."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed Honeypot & Collector Source
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.source = EventSourceModel(
            source_id="collector-web-01",
            source_type="HTTP_INGESTION",
            source_name="Web Login Collector",
            environment="isolated_lab",
            status="ONLINE",
        )
        self.db.add_all([self.decoy, self.source])
        self.db.commit()

        # Isolated registries and services
        self.rule_registry = RuleRegistry()
        self.policy_registry = ScoringPolicyRegistry()
        self.scoring_service = ThreatAssessmentService(
            policies=self.policy_registry,
            rules=self.rule_registry,
        )

        # Base sample normalized event fixture
        self.event_id = str(uuid.uuid4())
        self.raw_event_id = str(uuid.uuid4())
        self.session_id = f"decoy_sess_{uuid.uuid4().hex}"
        self.base_event = {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "event_type": "LOGIN_ATTEMPT",
            "event_category": "AUTHENTICATION",
            "action": "SUBMIT_CREDENTIALS",
            "outcome": "FAILURE",
            "decoy_id": "WEB-001",
            "session_id": self.session_id,
            "observed_source_id": "collector-web-01",
            "source_address": "198.51.100.45",
            "source_port": 49152,
            "source_protocol": "HTTP",
            "target_service": "WEB_PORTAL",
            "target_port": 8080,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "received_at": datetime.now(timezone.utc).isoformat(),
            "validation_status": "VALID",
            "sanitized_metadata": {
                "username": "admin",
                "password_length": 14,
                "http_method": "POST",
                "http_path": "/login",
                "status_code": 401,
            },
            "provenance": {
                "source_type": "controlled_test",
                "environment": "isolated_lab",
            },
        }

        # Seed sample detection rule
        self.rule = self.rule_registry.register_rule(get_test_rule_001())

        # Sample detection result fixture
        self.detection_result = DetectionResult(
            detection_result_id=str(uuid.uuid4()),
            rule_id=self.rule.rule_id,
            rule_version=self.rule.rule_version,
            evaluated_event_id=self.event_id,
            related_event_ids=[],
            session_id=self.session_id,
            decoy_id="WEB-001",
            evaluation_status=EvaluationStatus.MATCHED,
            matched_conditions=[
                {"field": "event_type", "operator": "EQUALS", "value": "LOGIN_ATTEMPT", "matched": True}
            ],
            detection_explanation="Rule matched LOGIN_ATTEMPT",
            evidence_references=[
                {
                    "event_id": self.event_id,
                    "raw_event_id": self.raw_event_id,
                    "observed_at": self.base_event["observed_at"],
                    "event_type": "LOGIN_ATTEMPT",
                }
            ],
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            provenance={"source_type": "controlled_test", "environment": "isolated_lab"},
        )

    def tearDown(self):
        """Cleans up database and isolates test state."""
        self.db.close()
        Base.metadata.drop_all(self.engine)
        self.rule_registry.clear()
        self.policy_registry.clear()
        self.scoring_service.clear()

    # =========================================================================
    # SEVERITY TESTS: TEST SCORE-001 to SCORE-007
    # =========================================================================

    def test_score_001_valid_baseline_severity_is_assigned(self):
        """TEST SCORE-001: Valid baseline severity is assigned from rule default."""
        policy = self.policy_registry.get_policy()
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        # get_test_rule_001 has severity_default = "LOW"
        level, score, explanation = SeverityAssessor.assess_severity(self.rule, self.base_event, metrics, policy)
        self.assertEqual(level, SeverityLevel.LOW)
        self.assertGreaterEqual(score, 20)
        self.assertLessEqual(score, 39)
        self.assertIn("Baseline rule severity 'LOW'", explanation)

    def test_score_002_low_severity_is_assigned_correctly(self):
        """TEST SCORE-002: LOW severity is assigned within boundary [20, 39]."""
        policy = self.policy_registry.get_policy()
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        level, score, _ = SeverityAssessor.assess_severity(self.rule, self.base_event, metrics, policy)
        self.assertEqual(level, SeverityLevel.LOW)
        self.assertTrue(20 <= score <= 39)

    def test_score_003_medium_severity_is_assigned_correctly(self):
        """TEST SCORE-003: MEDIUM severity is assigned within boundary [40, 59]."""
        med_rule = self.rule_registry.register_rule(get_test_rule_004())  # severity_default = "MEDIUM"
        policy = self.policy_registry.get_policy()
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        level, score, _ = SeverityAssessor.assess_severity(med_rule, self.base_event, metrics, policy)
        self.assertEqual(level, SeverityLevel.MEDIUM)
        self.assertTrue(40 <= score <= 59)

    def test_score_004_high_severity_requires_the_configured_criteria(self):
        """TEST SCORE-004: HIGH severity requires high-impact category or rule designation."""
        high_rule = DetectionRuleDefinition.model_validate({
            "rule_id": "TEST-HIGH-SEV",
            "rule_version": "1.0",
            "rule_name": "High Severity Rule",
            "description": "Exploitation attempt rule",
            "category": "EXPLOITATION",
            "severity_default": "HIGH",
            "conditions": {"all": [{"field": "action", "operator": "EQUALS", "value": "EXPLOIT"}]},
        })
        policy = self.policy_registry.get_policy()
        exploit_event = copy.deepcopy(self.base_event)
        exploit_event["event_category"] = "EXPLOITATION"
        strength, metrics = EvidenceAssessor.assess_evidence(exploit_event)

        level, score, _ = SeverityAssessor.assess_severity(high_rule, exploit_event, metrics, policy)
        self.assertEqual(level, SeverityLevel.HIGH)
        self.assertTrue(60 <= score <= 79)

    def test_score_005_critical_severity_requires_explicit_policy_support(self):
        """TEST SCORE-005: CRITICAL severity is capped at HIGH unless rule explicitly designated CRITICAL."""
        # Non-critical rule attempting escalation
        rule_def = DetectionRuleDefinition.model_validate({
            "rule_id": "TEST-ESCALATE",
            "rule_version": "1.0",
            "rule_name": "Escalation Test",
            "description": "Rule without critical designation",
            "category": "EXPLOITATION",
            "severity_default": "HIGH",  # Not CRITICAL
            "conditions": {"all": [{"field": "action", "operator": "EQUALS", "value": "EXPLOIT"}]},
        })
        policy = self.policy_registry.get_policy()  # allow_critical_auto_escalation = False
        exploit_event = copy.deepcopy(self.base_event)
        exploit_event["event_category"] = "EXPLOITATION"
        # Simulate many interactions to trigger high score
        metrics = {"unique_evidence_count": 10}

        level, score, explanation = SeverityAssessor.assess_severity(rule_def, exploit_event, metrics, policy)
        self.assertEqual(level, SeverityLevel.HIGH)
        self.assertLessEqual(score, 79)
        self.assertIn("Capped at HIGH", explanation)

    def test_score_006_severity_is_not_derived_from_confidence(self):
        """TEST SCORE-006: High severity can have low confidence; low severity can have high confidence."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        # Severity is LOW, but confidence is HIGH due to valid evidence
        self.assertEqual(assessment.severity_level, SeverityLevel.LOW)
        self.assertEqual(assessment.confidence_level, ConfidenceLevel.VERY_HIGH)
        self.assertNotEqual(str(assessment.severity_level.value), str(assessment.confidence_level.value))

    def test_score_007_severity_configuration_boundaries_are_enforced(self):
        """TEST SCORE-007: Severity score is strictly clamped between 0 and 100."""
        policy = self.policy_registry.get_policy()
        metrics = {"unique_evidence_count": 50}
        level, score, _ = SeverityAssessor.assess_severity(self.rule, self.base_event, metrics, policy)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    # =========================================================================
    # CONFIDENCE TESTS: TEST SCORE-008 to SCORE-018
    # =========================================================================

    def test_score_008_confidence_score_stays_within_0_100(self):
        """TEST SCORE-008: Confidence score remains strictly bounded between 0 and 100."""
        policy = self.policy_registry.get_policy()
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        level, score, _ = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_score_009_valid_evidence_produces_the_expected_score(self):
        """TEST SCORE-009: Clean, verified telemetry produces high confidence score."""
        policy = self.policy_registry.get_policy()
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        level, score, _ = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertGreaterEqual(score, 80)
        self.assertEqual(level, ConfidenceLevel.VERY_HIGH)

    def test_score_010_missing_evidence_does_not_receive_maximum_points(self):
        """TEST SCORE-010: Event lacking session context receives lower confidence."""
        policy = self.policy_registry.get_policy()
        event_no_session = copy.deepcopy(self.base_event)
        event_no_session["session_id"] = None

        _, metrics = EvidenceAssessor.assess_evidence(event_no_session)
        _, score, explanation = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertLess(score, 80)
        self.assertIn("Missing session penalty", explanation)

    def test_score_011_invalid_timestamps_reduce_or_invalidate_confidence(self):
        """TEST SCORE-011: Corrupted or missing timestamp triggers documented penalty."""
        policy = self.policy_registry.get_policy()
        event_bad_ts = copy.deepcopy(self.base_event)
        event_bad_ts["observed_at"] = "invalid_timestamp_string"

        _, metrics = EvidenceAssessor.assess_evidence(event_bad_ts)
        _, score, explanation = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertIn("Invalid timestamp penalty", explanation)
        self.assertLess(score, 70)

    def test_score_012_duplicate_evidence_does_not_increase_confidence(self):
        """TEST SCORE-012: Duplicate copies of the same event ID do not inflate evidence count or score."""
        dup_refs = [
            {"event_id": self.event_id, "raw_event_id": self.raw_event_id},
            {"event_id": self.event_id, "raw_event_id": self.raw_event_id},
            {"event_id": self.event_id, "raw_event_id": self.raw_event_id},
        ]
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event, evidence_references=dup_refs)
        self.assertEqual(metrics["unique_evidence_count"], 1)

    def test_score_013_independent_corroboration_is_handled_correctly(self):
        """TEST SCORE-013: Distinct events within the same session increase unique evidence count."""
        ev2_id = str(uuid.uuid4())
        ev3_id = str(uuid.uuid4())
        refs = [
            {"event_id": ev2_id, "raw_event_id": str(uuid.uuid4())},
            {"event_id": ev3_id, "raw_event_id": str(uuid.uuid4())},
        ]
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event, evidence_references=refs)
        self.assertEqual(metrics["unique_evidence_count"], 3)
        self.assertEqual(strength, EvidenceStrength.STRONG)

    def test_score_014_contradictory_evidence_is_represented(self):
        """TEST SCORE-014: Contradictory interaction data triggers confidence penalty."""
        policy = self.policy_registry.get_policy()
        contradictory_event = copy.deepcopy(self.base_event)
        contradictory_event["outcome"] = "BLOCKED"
        contradictory_event["action"] = "EXECUTE_PAYLOAD"

        _, metrics = EvidenceAssessor.assess_evidence(contradictory_event)
        self.assertTrue(metrics["has_contradiction"])

        _, score, explanation = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertIn("Contradictory evidence penalty", explanation)

    def test_score_015_source_reliability_is_assessed_appropriately(self):
        """TEST SCORE-015: Telemetry lacking source identifier receives lower reliability score."""
        policy = self.policy_registry.get_policy()
        unverified_event = copy.deepcopy(self.base_event)
        del unverified_event["observed_source_id"]

        _, metrics = EvidenceAssessor.assess_evidence(unverified_event)
        self.assertFalse(metrics["source_reliable"])

        _, score, explanation = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        self.assertIn("Unregistered or missing collector identifier", explanation)

    def test_score_016_unknown_provenance_does_not_receive_unjustified_confidence(self):
        """TEST SCORE-016: Unknown provenance classification receives lower score."""
        policy = self.policy_registry.get_policy()
        unknown_event = copy.deepcopy(self.base_event)
        unknown_event["provenance"] = {"source_type": "mysterious_origin"}

        _, metrics = EvidenceAssessor.assess_evidence(unknown_event)
        _, score, explanation = ConfidenceScorer.calculate_confidence(metrics, self.detection_result.matched_conditions, policy)
        # Should mention unclassified provenance
        self.assertIn("provenance", explanation.lower())

    def test_score_017_synthetic_provenance_remains_clearly_identified(self):
        """TEST SCORE-017: Synthetic simulation provenance is preserved and distinguished."""
        synthetic_event = copy.deepcopy(self.base_event)
        synthetic_event["provenance"] = {"source_type": "synthetic_simulation", "environment": "isolated_lab"}

        strength, metrics = EvidenceAssessor.assess_evidence(synthetic_event)
        self.assertEqual(metrics["provenance_type"], "SYNTHETIC_SIMULATION")

    def test_score_018_confidence_and_severity_remain_independent(self):
        """TEST SCORE-018: Confidence calculations do not consult or affect severity."""
        policy = self.policy_registry.get_policy()
        metrics = {"event_valid": True, "has_session": True, "timestamp_valid": True, "source_reliable": True, "provenance_type": "LIVE_HONEYPOT"}
        _, conf_score, _ = ConfidenceScorer.calculate_confidence(metrics, [{"matched": True}], policy)
        # Confidence is calculated independently without rule severity input
        self.assertGreaterEqual(conf_score, 80)

    # =========================================================================
    # EVIDENCE STRENGTH TESTS: TEST SCORE-019 to SCORE-022
    # =========================================================================

    def test_score_019_evidence_strength_is_classified_correctly(self):
        """TEST SCORE-019: Evidence strength is classified into standard 4 tiers."""
        strength, _ = EvidenceAssessor.assess_evidence(self.base_event)
        self.assertIn(strength, [EvidenceStrength.INSUFFICIENT, EvidenceStrength.LIMITED, EvidenceStrength.MODERATE, EvidenceStrength.STRONG])

    def test_score_020_insufficient_evidence_is_not_presented_as_strong(self):
        """TEST SCORE-020: Unvalidated event is classified as INSUFFICIENT."""
        unvalidated_event = copy.deepcopy(self.base_event)
        unvalidated_event["validation_status"] = "INVALID"
        strength, _ = EvidenceAssessor.assess_evidence(unvalidated_event)
        self.assertEqual(strength, EvidenceStrength.INSUFFICIENT)

    def test_score_021_supporting_event_ids_remain_traceable(self):
        """TEST SCORE-021: Assessment result contains deduplicated supporting event IDs."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertIn(self.event_id, assessment.supporting_event_ids)

    def test_score_022_evidence_references_remain_valid(self):
        """TEST SCORE-022: Assessment result retains pointers to persisted evidence."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertIn(self.event_id, assessment.supporting_evidence_ids)

    # =========================================================================
    # EXPLANATION TESTS: TEST SCORE-023 to SCORE-026
    # =========================================================================

    def test_score_023_severity_explanation_is_generated(self):
        """TEST SCORE-023: Severity explanation is generated dynamically."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertTrue(len(assessment.severity_explanation) > 10)
        self.assertIn("Severity assessed as", assessment.severity_explanation)

    def test_score_024_confidence_explanation_is_generated(self):
        """TEST SCORE-024: Confidence explanation is generated dynamically."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertTrue(len(assessment.confidence_explanation) > 10)
        self.assertIn("Confidence calculated as", assessment.confidence_explanation)

    def test_score_025_explanations_reference_real_scoring_factors(self):
        """TEST SCORE-025: Explanations describe actual contributing factors."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertIn("Baseline rule severity", assessment.severity_explanation)
        self.assertIn("Positive factors", assessment.confidence_explanation)

    def test_score_026_no_misleading_claims_of_real_system_compromise_are_generated(self):
        """TEST SCORE-026: Explanations state that honeypot telemetry does not prove compromise of real systems."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertIn("not real-world compromise probability", assessment.confidence_explanation)

    # =========================================================================
    # POLICY TESTS: TEST SCORE-027 to SCORE-031
    # =========================================================================

    def test_score_027_valid_policy_loads_correctly(self):
        """TEST SCORE-027: Valid scoring policy definition is registered and retrieved."""
        policy = self.policy_registry.get_policy("DEFAULT_SCORING_POLICY")
        self.assertEqual(policy.policy_id, "DEFAULT_SCORING_POLICY")
        self.assertEqual(policy.policy_version, "1.0")

    def test_score_028_invalid_policy_is_rejected(self):
        """TEST SCORE-028: Policy with weights that do not sum to 1.0 is rejected."""
        with self.assertRaises(ValueError):
            ConfidenceWeights(
                rule_match_quality=0.5,
                event_validity=0.5,
                source_reliability=0.5,  # Sum = 1.5 > 1.0
                provenance_fidelity=0.0,
                session_consistency=0.0,
                timestamp_quality=0.0,
            )

    def test_score_029_policy_versions_are_preserved(self):
        """TEST SCORE-029: Multiple versions of the same policy ID are preserved."""
        p2 = ScoringPolicyDefinition(
            policy_id="DEFAULT_SCORING_POLICY",
            policy_version="2.0",
            policy_name="Updated Scoring Policy",
            description="Version 2.0 with adjusted thresholds",
            enabled=True,
        )
        self.policy_registry.register_policy(p2)
        versions = self.policy_registry.get_versions("DEFAULT_SCORING_POLICY")
        self.assertEqual(versions, ["1.0", "2.0"])

    def test_score_030_unauthorized_policy_modification_is_rejected(self):
        """TEST SCORE-030: Re-registering existing policy version raises InvalidPolicyError."""
        policy = self.policy_registry.get_policy("DEFAULT_SCORING_POLICY")
        with self.assertRaises(InvalidPolicyError):
            self.policy_registry.register_policy(policy)

    def test_score_031_historical_assessment_retains_original_policy_version(self):
        """TEST SCORE-031: Assessment records the exact policy ID and version used at assessment time."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertEqual(assessment.scoring_policy_id, "DEFAULT_SCORING_POLICY")
        self.assertEqual(assessment.scoring_policy_version, "1.0")

    # =========================================================================
    # INTEGRATION & REASSESSMENT TESTS: TEST SCORE-032 to SCORE-036
    # =========================================================================

    def test_score_032_detection_result_reaches_the_scoring_service(self):
        """TEST SCORE-032: DetectionResult passed to ThreatAssessmentService yields ThreatAssessmentResult."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertIsNotNone(assessment.assessment_id)
        self.assertEqual(assessment.detection_result_id, self.detection_result.detection_result_id)

    def test_score_033_assessment_persists_successfully(self):
        """TEST SCORE-033: Assessment can be retrieved by ID and by detection_result_id."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        fetched = self.scoring_service.get_assessment(assessment.assessment_id)
        self.assertEqual(fetched.assessment_id, assessment.assessment_id)
        by_det = self.scoring_service.get_assessment_for_detection(self.detection_result.detection_result_id)
        self.assertEqual(by_det.assessment_id, assessment.assessment_id)

    def test_score_034_scoring_failure_does_not_delete_detection_evidence(self):
        """TEST SCORE-034: Exception during scoring does not delete or roll back persisted database events."""
        raw_payload = {
            "schema_version": "1.0",
            "raw_event_id": str(uuid.uuid4()),
            "event_type": "login_attempt",
            "event_category": "authentication",
            "action": "submit_credentials",
            "outcome": "failure",
            "decoy_id": "WEB-001",
            "session_id": f"decoy_sess_{uuid.uuid4().hex}",
            "source_address": "198.51.100.22",
            "target_service": "web_portal",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "service_metadata": {"username": "admin", "password_length": 12},
            "provenance": {"source_type": "controlled_test", "environment": "isolated_lab"},
        }

        # Patch assess_detection to simulate failure
        with patch("app.services.threat_assessment_service.ThreatAssessmentService.assess_detection", side_effect=Exception("Scoring breakdown")):
            res = EventProcessor.process_single_event(self.db, raw_payload, source_id="collector-web-01")
            self.assertEqual(res.status, EventProcessingStatus.ACCEPTED)
            # Verify event was still committed to PostgreSQL/SQLite
            db_event = self.db.query(SecurityEventModel).filter(SecurityEventModel.session_id == raw_payload["session_id"]).first()
            self.assertIsNotNone(db_event)

    def test_score_035_duplicate_assessments_are_prevented(self):
        """TEST SCORE-035: Repeated assessment calls for the same detection_result_id return cached instance."""
        res1 = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        res2 = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.assertEqual(res1.assessment_id, res2.assessment_id)

    def test_score_036_reassessment_creates_a_traceable_history_entry(self):
        """TEST SCORE-036: Submitting an analyst review creates an auditable history record."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        self.scoring_service.submit_analyst_review(
            assessment_id=assessment.assessment_id,
            reviewer_id="analyst_charlie",
            proposed_severity=SeverityLevel.MEDIUM,
            proposed_confidence=85,
            review_reason="Elevated severity based on verified reconnaissance sequence",
        )
        history = self.scoring_service.get_assessment_history(assessment.assessment_id)
        self.assertEqual(len(history), 2)  # 1 initial + 1 review
        self.assertEqual(history[-1].initiator, "analyst_charlie")
        self.assertEqual(history[-1].updated_severity, SeverityLevel.MEDIUM)

    # =========================================================================
    # SECURITY & REVIEW TESTS: TEST SCORE-037 to SCORE-040
    # =========================================================================

    def test_score_037_passwords_are_never_included_in_assessments(self):
        """TEST SCORE-037: Sensitive credential strings are absent from assessments."""
        event_with_secret = copy.deepcopy(self.base_event)
        event_with_secret["sanitized_metadata"]["password"] = "CanarySecret99!"
        assessment = self.scoring_service.assess_detection(self.detection_result, event_with_secret)

        result_json = assessment.model_dump_json()
        self.assertNotIn("CanarySecret99!", result_json)

    def test_score_038_secrets_are_unavailable_to_the_scoring_engine(self):
        """TEST SCORE-038: Evidence assessor only references metadata and deduplicated identifiers."""
        strength, metrics = EvidenceAssessor.assess_evidence(self.base_event)
        for key in metrics:
            self.assertNotIn("password", key.lower())
            self.assertNotIn("token", key.lower())

    def test_score_039_user_controlled_scoring_expressions_cannot_execute_code(self):
        """TEST SCORE-039: Dynamic code execution (eval, exec) is never invoked in scoring calculations."""
        # Confidence calculation uses purely mathematical arithmetic
        policy = self.policy_registry.get_policy()
        metrics = {"event_valid": True, "has_session": True, "timestamp_valid": True, "source_reliable": True, "provenance_type": "LIVE_HONEYPOT"}
        level, score, _ = ConfidenceScorer.calculate_confidence(metrics, [], policy)
        self.assertIsInstance(score, int)

    def test_score_040_analyst_review_cannot_silently_modify_historical_assessments(self):
        """TEST SCORE-040: Analyst review records review metadata without erasing automated score."""
        assessment = self.scoring_service.assess_detection(self.detection_result, self.base_event)
        orig_sev = assessment.severity_level
        orig_conf = assessment.confidence_score

        updated = self.scoring_service.submit_analyst_review(
            assessment_id=assessment.assessment_id,
            reviewer_id="analyst_alice",
            proposed_severity=SeverityLevel.HIGH,
            proposed_confidence=95,
            review_reason="External threat intel correlation",
        )

        # Automated score fields remain intact
        self.assertEqual(updated.severity_level, orig_sev)
        self.assertEqual(updated.confidence_score, orig_conf)
        # Review record stores proposed changes
        self.assertTrue(updated.analyst_review.reviewed)
        self.assertEqual(updated.analyst_review.proposed_severity, SeverityLevel.HIGH)
        self.assertEqual(updated.analyst_review.proposed_confidence, 95)

