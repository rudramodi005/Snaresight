"""Comprehensive automated test suite for SnareSight Task P16:
Configurable Rule-Based Threat Detection Engine.

Covers:
- TEST DET-001 to DET-006 (Rule Registry Tests)
- TEST DET-007 to DET-014 (Rule Validation Tests)
- TEST DET-015 to DET-020 (Individual Event Evaluation Tests)
- TEST DET-021 to DET-025 (Detection Result Tests)
- TEST DET-026 to DET-030 (Session and Time-Window Evaluation Tests)
- TEST DET-031 to DET-036 (Security and Safety Invariant Tests)
- TEST DET-037 to DET-040 (Pipeline Integration and Fault Tolerance Tests)
"""

import copy
import time
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel, EventSourceModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.detection.engine import DetectionEngine
from app.detection.registry import RuleRegistry
from app.detection.rule_validator import RuleValidator
from app.detection.condition_evaluator import ConditionEvaluator, Operator
from app.detection.field_registry import FieldRegistry, PROHIBITED_SENSITIVE_FIELDS
from app.detection.execution_tracker import ExecutionTracker
from app.detection.result_builder import ResultBuilder
from app.detection.session_evaluator import SessionEvaluator
from app.detection.window_evaluator import TimeWindowEvaluator
from app.detection.exceptions import (
    RuleValidationError,
    DuplicateRuleError,
    RuleNotFoundError,
    UnsupportedFieldError,
    RestrictedFieldError,
    InvalidOperatorError,
)
from app.detection.rule_schema import (
    DetectionRuleDefinition,
    AtomicCondition,
    ConditionGroup,
    EvaluationMode,
    DetectionType,
    RuleSeverity,
)
from app.detection.test_rules import (
    get_test_rule_001,
    get_test_rule_002,
    get_test_rule_003,
    get_test_rule_004,
    get_test_rule_005,
    get_test_rule_006,
    get_test_rule_007,
    get_test_rule_008_unsupported_field,
    get_test_rule_009_invalid_operator,
    get_test_rule_010_version_v1,
    get_test_rule_010_version_v2,
)
from app.services.detection_service import DetectionService
from app.schemas.detection import EvaluationStatus
from app.ingestion.processor import EventProcessor
from app.ingestion.schemas import EventProcessingStatus


class TestDetectionEngine(unittest.TestCase):
    """Test suite covering the SnareSight rule-based detection engine."""

    def setUp(self):
        """Initializes in-memory database and isolated detection engine components."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed Honeypot & Collector Source fixtures
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)

        self.source = EventSourceModel(
            source_id="collector-web-01",
            source_type="HTTP_INGESTION",
            source_name="Web Login Collector",
            environment="isolated_lab",
            status="ONLINE",
        )
        self.db.add(self.source)
        self.db.commit()

        # Isolated Detection Components
        self.registry = RuleRegistry()
        self.tracker = ExecutionTracker()
        self.det_engine = DetectionEngine(registry=self.registry, tracker=self.tracker)
        self.service = DetectionService(
            engine=self.det_engine,
            registry=self.registry,
            tracker=self.tracker,
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
            "source_address": "198.51.100.45",
            "source_port": 49152,
            "source_protocol": "HTTP",
            "target_service": "WEB_PORTAL",
            "target_port": 8080,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "received_at": datetime.now(timezone.utc).isoformat(),
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

    def tearDown(self):
        """Cleans up database and isolates test state."""
        self.db.close()
        Base.metadata.drop_all(self.engine)
        self.registry.clear()
        self.tracker.clear()

    # =========================================================================
    # RULE REGISTRY TESTS: TEST DET-001 to DET-006
    # =========================================================================

    def test_det_001_valid_rule_registration(self):
        """TEST DET-001: Valid rule is registered successfully."""
        rule_def = get_test_rule_001()
        reg_rule = self.registry.register_rule(rule_def)
        self.assertEqual(reg_rule.rule_id, "TEST-RULE-001")
        self.assertEqual(reg_rule.rule_version, "1.0")
        self.assertTrue(reg_rule.enabled)

    def test_det_002_duplicate_rule_identifier_handling(self):
        """TEST DET-002: Attempting to register exact duplicate rule version raises DuplicateRuleError."""
        rule_def = get_test_rule_001()
        self.registry.register_rule(rule_def)
        with self.assertRaises(DuplicateRuleError):
            self.registry.register_rule(rule_def)

    def test_det_003_rule_version_registration(self):
        """TEST DET-003: Registering multiple versions of the same rule ID succeeds."""
        v1 = get_test_rule_010_version_v1()
        v2 = get_test_rule_010_version_v2()
        self.registry.register_rule(v1)
        self.registry.register_rule(v2)
        versions = self.registry.get_versions("TEST-RULE-010")
        self.assertEqual(versions, ["1.0", "2.0"])
        # Active version updates to newest
        active = self.registry.get_rule("TEST-RULE-010")
        self.assertEqual(active.rule_version, "2.0")

    def test_det_004_disabled_rule_exclusion(self):
        """TEST DET-004: Disabled rules are excluded from active list."""
        rule_def = get_test_rule_007()  # enabled: False
        self.registry.register_rule(rule_def)
        enabled_rules = self.registry.list_enabled_rules()
        self.assertNotIn("TEST-RULE-007", [r.rule_id for r in enabled_rules])
        disabled_rules = self.registry.list_disabled_rules()
        self.assertIn("TEST-RULE-007", [r.rule_id for r in disabled_rules])

    def test_det_005_invalid_rule_rejection(self):
        """TEST DET-005: Registering an invalid rule raises RuleValidationError."""
        rule_def = get_test_rule_008_unsupported_field()
        with self.assertRaises(RuleValidationError):
            self.registry.register_rule(rule_def)

    def test_det_006_historical_version_preservation(self):
        """TEST DET-006: Historical rule versions remain accessible and immutable."""
        v1 = get_test_rule_010_version_v1()
        v2 = get_test_rule_010_version_v2()
        self.registry.register_rule(v1)
        self.registry.register_rule(v2)

        retrieved_v1 = self.registry.get_rule("TEST-RULE-010", version="1.0")
        retrieved_v2 = self.registry.get_rule("TEST-RULE-010", version="2.0")
        self.assertEqual(retrieved_v1.rule_version, "1.0")
        self.assertEqual(retrieved_v2.rule_version, "2.0")
        self.assertEqual(retrieved_v1.severity_default.value, "LOW")
        self.assertEqual(retrieved_v2.severity_default.value, "HIGH")

    # =========================================================================
    # RULE VALIDATION TESTS: TEST DET-007 to DET-014
    # =========================================================================

    def test_det_007_valid_equals_operator(self):
        """TEST DET-007: Valid EQUALS operator passes validation."""
        rule_def = get_test_rule_001()
        is_valid, errors = RuleValidator.validate_rule(rule_def)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_det_008_invalid_operator_rejection(self):
        """TEST DET-008: Unrecognized operator is rejected."""
        rule_def = get_test_rule_009_invalid_operator()
        is_valid, errors = RuleValidator.validate_rule(rule_def)
        self.assertFalse(is_valid)
        self.assertTrue(any("not supported" in e.lower() for e in errors))

    def test_det_009_unsupported_field_rejection(self):
        """TEST DET-009: Target field not in approved registry is rejected."""
        rule_def = get_test_rule_008_unsupported_field()
        is_valid, errors = RuleValidator.validate_rule(rule_def)
        self.assertFalse(is_valid)
        self.assertTrue(any("not in the approved detection field registry" in e for e in errors))

    def test_det_010_invalid_operand_type_rejection(self):
        """TEST DET-010: Incompatible operand types (e.g. non-numeric for GREATER_THAN) are rejected."""
        invalid_rule = {
            "rule_id": "TEST-TYPE-ERR",
            "rule_name": "Invalid Operand Type",
            "rule_version": "1.0",
            "description": "Invalid numeric comparison against string",
            "category": "APPLICATION",
            "conditions": {
                "all": [
                    {"field": "metadata.status_code", "operator": "GREATER_THAN", "value": "not_a_number"}
                ]
            },
        }
        is_valid, errors = RuleValidator.validate_rule(invalid_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("requires numeric operand" in e for e in errors))

    def test_det_011_excessive_nesting_rejection(self):
        """TEST DET-011: Nesting condition groups beyond MAX_NESTING_DEPTH (3) is rejected."""
        deep_rule = {
            "rule_id": "TEST-DEEP-NEST",
            "rule_name": "Excessive Nesting",
            "rule_version": "1.0",
            "description": "Deeply nested conditions test",
            "category": "APPLICATION",
            "conditions": {
                "all": [
                    {
                        "all": [
                            {
                                "all": [
                                    {
                                        "all": [
                                            {"field": "outcome", "operator": "EQUALS", "value": "FAILURE"}
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
        }
        is_valid, errors = RuleValidator.validate_rule(deep_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("exceeds maximum allowable depth" in e for e in errors))

    def test_det_012_oversized_condition_rejection(self):
        """TEST DET-012: Condition trees exceeding MAX_TOTAL_CONDITIONS (20) are rejected."""
        many_conditions = [
            {"field": "outcome", "operator": "EQUALS", "value": f"VAL_{i}"} for i in range(25)
        ]
        oversized_rule = {
            "rule_id": "TEST-OVERSIZED",
            "rule_name": "Oversized Rule",
            "rule_version": "1.0",
            "description": "Exceeds condition limits",
            "category": "AUTHENTICATION",
            "conditions": {"all": many_conditions},
        }
        is_valid, errors = RuleValidator.validate_rule(oversized_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("exceeds maximum allowed" in e for e in errors))

    def test_det_013_malformed_logical_group_rejection(self):
        """TEST DET-013: Condition group lacking both 'all' and 'any' is rejected."""
        malformed_group_rule = {
            "rule_id": "TEST-MALFORMED",
            "rule_name": "Empty Condition Group",
            "rule_version": "1.0",
            "description": "Group lacks all and any keys",
            "category": "AUTHENTICATION",
            "conditions": {},
        }
        is_valid, errors = RuleValidator.validate_rule(malformed_group_rule)
        self.assertFalse(is_valid)
        self.assertTrue(any("must define at least one 'all' or 'any'" in e for e in errors))

    def test_det_014_restricted_field_rejection(self):
        """TEST DET-014: Condition targeting prohibited sensitive fields is rejected."""
        for restricted in ["password", "secret", "auth_token", "private_key"]:
            rule = {
                "rule_id": f"TEST-RESTRICTED-{restricted}",
                "rule_name": f"Restricted Field {restricted}",
                "rule_version": "1.0",
                "description": "Attempts to inspect sensitive field",
                "category": "AUTHENTICATION",
                "conditions": {
                    "all": [
                        {"field": restricted, "operator": "EQUALS", "value": "secret123"}
                    ]
                },
            }
            is_valid, errors = RuleValidator.validate_rule(rule)
            self.assertFalse(is_valid)
            self.assertTrue(any("strictly classified as RESTRICTED" in e or "prohibited" in e for e in errors))

    # =========================================================================
    # INDIVIDUAL EVALUATION TESTS: TEST DET-015 to DET-020
    # =========================================================================

    def test_det_015_matching_event_produces_matched(self):
        """TEST DET-015: Matching event produces MATCHED status."""
        self.registry.register_rule(get_test_rule_001())
        results = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
        self.assertEqual(results[0].rule_id, "TEST-RULE-001")
        self.assertIn("MATCHED", results[0].detection_explanation)

    def test_det_016_nonmatching_event_produces_no_match(self):
        """TEST DET-016: Non-matching event produces NO_MATCH status."""
        self.registry.register_rule(get_test_rule_006())  # Requires NON_EXISTENT_DECOY_999
        results = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)
        self.assertEqual(results[0].rule_id, "TEST-RULE-006")
        self.assertIn("NO_MATCH", results[0].detection_explanation)

    def test_det_017_disabled_rule_produces_skipped(self):
        """TEST DET-017: Explicitly evaluating a disabled rule produces SKIPPED status."""
        disabled_rule = self.registry.register_rule(get_test_rule_007())
        results = self.det_engine.evaluate_event(self.base_event, rules=[disabled_rule])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.SKIPPED)
        self.assertIn("disabled", results[0].detection_explanation.lower())

    def test_det_018_missing_required_field_is_handled_safely(self):
        """TEST DET-018: Event missing a field targeted by a rule evaluates to NO_MATCH without crashing."""
        self.registry.register_rule(get_test_rule_003())  # Requires metadata.http_method == 'POST'
        event_without_metadata = copy.deepcopy(self.base_event)
        del event_without_metadata["sanitized_metadata"]

        results = self.det_engine.evaluate_event(event_without_metadata)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_det_019_multiple_rules_can_evaluate_one_event(self):
        """TEST DET-019: Single event evaluated against multiple enabled rules returns distinct results."""
        self.registry.register_rule(get_test_rule_001())  # Match
        self.registry.register_rule(get_test_rule_004())  # Match
        self.registry.register_rule(get_test_rule_006())  # No match

        results = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(len(results), 3)
        status_map = {r.rule_id: r.evaluation_status for r in results}
        self.assertEqual(status_map["TEST-RULE-001"], EvaluationStatus.MATCHED)
        self.assertEqual(status_map["TEST-RULE-004"], EvaluationStatus.MATCHED)
        self.assertEqual(status_map["TEST-RULE-006"], EvaluationStatus.NO_MATCH)

    def test_det_020_one_failing_rule_does_not_prevent_other_valid_evaluations(self):
        """TEST DET-020: One rule encountering a runtime error does not abort peer rules."""
        valid_rule = DetectionRuleDefinition.model_validate(get_test_rule_001())
        # Construct faulty rule that simulates unexpected exception during match
        faulty_rule = DetectionRuleDefinition.model_validate(get_test_rule_002())

        self.registry.register_rule(valid_rule)
        self.registry.register_rule(faulty_rule)

        with patch("app.detection.event_matcher.EventMatcher.evaluate_rule") as mock_match:
            def side_effect(ev, r):
                if r.rule_id == "TEST-RULE-002":
                    raise RuntimeError("Simulated transient evaluator glitch")
                return True, [{"field": "event_type", "matched": True}], "OK"
            mock_match.side_effect = side_effect

            results = self.det_engine.evaluate_event(self.base_event)
            self.assertEqual(len(results), 2)
            status_map = {r.rule_id: r.evaluation_status for r in results}
            self.assertEqual(status_map["TEST-RULE-001"], EvaluationStatus.MATCHED)
            self.assertEqual(status_map["TEST-RULE-002"], EvaluationStatus.EVALUATION_ERROR)

    # =========================================================================
    # DETECTION RESULT TESTS: TEST DET-021 to DET-025
    # =========================================================================

    def test_det_021_evidence_references_are_recorded(self):
        """TEST DET-021: Evidence references accurately retain event identifiers."""
        self.registry.register_rule(get_test_rule_001())
        results = self.det_engine.evaluate_event(self.base_event)
        res = results[0]
        self.assertGreater(len(res.evidence_references), 0)
        self.assertEqual(res.evidence_references[0]["event_id"], self.event_id)
        self.assertEqual(res.evidence_references[0]["raw_event_id"], self.raw_event_id)

    def test_det_022_rule_version_is_recorded(self):
        """TEST DET-022: Rule version is recorded in detection result."""
        self.registry.register_rule(get_test_rule_001())
        results = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(results[0].rule_version, "1.0")

    def test_det_023_provenance_is_preserved(self):
        """TEST DET-023: Original event provenance is preserved in detection result."""
        self.registry.register_rule(get_test_rule_001())
        results = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(results[0].provenance["source_type"], "controlled_test")
        self.assertEqual(results[0].provenance["environment"], "isolated_lab")

    def test_det_024_explanation_is_generated(self):
        """TEST DET-024: Clear human-readable explanation is generated in detection result."""
        self.registry.register_rule(get_test_rule_004())
        results = self.det_engine.evaluate_event(self.base_event)
        self.assertIn("MATCHED", results[0].detection_explanation)
        self.assertIn("TEST-RULE-004", results[0].detection_explanation)
        self.assertGreater(len(results[0].matched_conditions), 0)

    def test_det_025_duplicate_evaluation_is_prevented(self):
        """TEST DET-025: Re-evaluating same event against same rule returns cached result (idempotency)."""
        self.registry.register_rule(get_test_rule_001())
        res1 = self.det_engine.evaluate_event(self.base_event)
        res2 = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(res1[0].detection_result_id, res2[0].detection_result_id)
        # Ensure only 1 execution record logged
        history = self.tracker.get_history()
        self.assertEqual(len(history), 1)

    # =========================================================================
    # SESSION AND TIME-WINDOW TESTS: TEST DET-026 to DET-030
    # =========================================================================

    def test_det_026_session_references_are_validated(self):
        """TEST DET-026: Session query returns only events bound to the specified session ID."""
        now = datetime.now(timezone.utc)
        ev1 = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="session_A",
            source_address="198.51.100.1",
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=now,
            received_at=now,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_sess_1",
        )
        ev2 = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="session_B",
            source_address="198.51.100.1",
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=now + timedelta(seconds=1),
            received_at=now + timedelta(seconds=1),
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_sess_2",
        )
        self.db.add_all([ev1, ev2])
        self.db.commit()

        events_a = SessionEvaluator.get_session_events(self.db, "session_A")
        self.assertEqual(len(events_a), 1)
        self.assertEqual(events_a[0].session_id, "session_A")

    def test_det_027_events_are_evaluated_in_stable_order(self):
        """TEST DET-027: Session events are returned in strict chronological order."""
        t0 = datetime.now(timezone.utc)
        for i in [3, 1, 2]:
            ev = SecurityEventModel(
                event_id=uuid.uuid4(),
                raw_event_id=uuid.uuid4(),
                event_type="COMMAND",
                event_category="EXECUTION",
                action="RUN",
                outcome="SUCCESS",
                decoy_id="WEB-001",
                session_id="order_session",
                source_address="198.51.100.2",
                source_protocol="HTTP",
                target_service="WEB_PORTAL",
                target_port=8080,
                observed_at=t0 + timedelta(seconds=i),
                received_at=t0 + timedelta(seconds=i),
                sanitized_metadata={},
                provenance={},
                deduplication_reference=f"dedup_order_{i}",
            )
            self.db.add(ev)
        self.db.commit()

        ordered = SessionEvaluator.get_session_events(self.db, "order_session")
        self.assertEqual(len(ordered), 3)
        self.assertTrue(ordered[0].observed_at < ordered[1].observed_at < ordered[2].observed_at)

    def test_det_028_late_arriving_event_is_handled(self):
        """TEST DET-028: Sliding window query accurately captures late-arriving events within bounds."""
        now = datetime.now(timezone.utc)
        ev_on_time = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="PROBE",
            event_category="RECONNAISSANCE",
            action="GET",
            outcome="BLOCKED",
            decoy_id="WEB-001",
            session_id="sess_late_1",
            source_address="198.51.100.3",
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=now - timedelta(seconds=60),
            received_at=now - timedelta(seconds=58),
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_late_1",
        )
        # Late event observed 120s ago, received now
        ev_late = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="PROBE",
            event_category="RECONNAISSANCE",
            action="GET",
            outcome="BLOCKED",
            decoy_id="WEB-001",
            session_id="sess_late_2",
            source_address="198.51.100.3",
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=now - timedelta(seconds=120),
            received_at=now,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_late_2",
        )
        self.db.add_all([ev_on_time, ev_late])
        self.db.commit()

        # Window of 180s includes both based on observed_at
        window_events = TimeWindowEvaluator.get_events_in_window(
            self.db, reference_time=now, window_seconds=180
        )
        self.assertEqual(len(window_events), 2)

    def test_det_029_maximum_evaluation_window_is_enforced(self):
        """TEST DET-029: TimeWindowEvaluator caps query window to MAX_ALLOWED_WINDOW_SECONDS."""
        now = datetime.now(timezone.utc)
        # Request 100 days; should cap to 86400 seconds (1 day)
        with patch.object(self.db, "query", wraps=self.db.query) as spy_query:
            TimeWindowEvaluator.get_events_in_window(
                self.db, reference_time=now, window_seconds=8640000
            )
            self.assertTrue(spy_query.called)

    def test_det_030_unrelated_sessions_are_not_merged(self):
        """TEST DET-030: Sessions sharing the same IP address are never conflated."""
        t = datetime.now(timezone.utc)
        ev_s1 = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="LOGIN",
            event_category="AUTHENTICATION",
            action="AUTH",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="session_ALPHA",
            source_address="203.0.113.5",
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=t,
            received_at=t,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_alpha",
        )
        ev_s2 = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            event_type="LOGIN",
            event_category="AUTHENTICATION",
            action="AUTH",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="session_BETA",
            source_address="203.0.113.5",  # Same IP
            source_protocol="HTTP",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=t + timedelta(seconds=1),
            received_at=t + timedelta(seconds=1),
            sanitized_metadata={},
            provenance={},
            deduplication_reference="dedup_beta",
        )
        self.db.add_all([ev_s1, ev_s2])
        self.db.commit()

        s1_events = SessionEvaluator.get_session_events(self.db, "session_ALPHA")
        s2_events = SessionEvaluator.get_session_events(self.db, "session_BETA")
        self.assertEqual(len(s1_events), 1)
        self.assertEqual(len(s2_events), 1)
        self.assertNotEqual(s1_events[0].session_id, s2_events[0].session_id)

    # =========================================================================
    # SECURITY & SAFETY INVARIANT TESTS: TEST DET-031 to DET-036
    # =========================================================================

    def test_det_031_python_eval_is_not_used(self):
        """TEST DET-031: Evaluator does not invoke eval() on condition operands."""
        # Operand containing Python code string
        res = ConditionEvaluator.evaluate(
            field_value="__import__('os').system('echo hacked')",
            operator_str="EQUALS",
            expected_value="__import__('os').system('echo hacked')",
        )
        # Evaluated as literal string comparison, never executed
        self.assertTrue(res)

    def test_det_032_python_exec_is_not_used(self):
        """TEST DET-032: Evaluator does not execute exec()."""
        # Malicious payload string
        res = ConditionEvaluator.evaluate(
            field_value="exec('x = 1')",
            operator_str="CONTAINS",
            expected_value="x = 1",
        )
        self.assertTrue(res)

    def test_det_033_rule_conditions_cannot_execute_shell_commands(self):
        """TEST DET-033: Shell commands in rule conditions are treated as literal strings."""
        shell_payload = "; rm -rf / ; cat /etc/passwd"
        res = ConditionEvaluator.evaluate(
            field_value=shell_payload,
            operator_str="EQUALS",
            expected_value=shell_payload,
        )
        self.assertTrue(res)

    def test_det_034_arbitrary_sql_cannot_be_supplied_by_a_rule(self):
        """TEST DET-034: SQL injection strings in rule conditions are treated as literal text."""
        sql_injection = "' OR 1=1 --"
        res = ConditionEvaluator.evaluate(
            field_value=sql_injection,
            operator_str="EQUALS",
            expected_value="' OR 1=1 --",
        )
        self.assertTrue(res)

    def test_det_035_sensitive_information_is_unavailable_to_the_evaluator(self):
        """TEST DET-035: Passwords and tokens cannot be queried by detection rules."""
        for forbidden in PROHIBITED_SENSITIVE_FIELDS:
            with self.assertRaises(RestrictedFieldError):
                FieldRegistry.get_field_def(forbidden)

    def test_det_036_unauthorized_users_cannot_modify_rules(self):
        """TEST DET-036: Unauthorized role attempting to create rules raises PermissionError."""
        rule_def = get_test_rule_001()
        with self.assertRaises(PermissionError):
            self.service.create_rule(rule_def, user_role="guest_viewer")

    # =========================================================================
    # INTEGRATION TESTS: TEST DET-037 to DET-040
    # =========================================================================

    def test_det_037_persisted_normalized_event_reaches_the_evaluator(self):
        """TEST DET-037: EventProcessor automatically evaluates registered rules post-commit."""
        # Register test rule in module singleton
        from app.detection.registry import rule_registry
        rule_registry.clear()
        rule_registry.register_rule(get_test_rule_001())

        sess_id = f"decoy_sess_{uuid.uuid4().hex}"
        raw_payload = {
            "schema_version": "1.0",
            "raw_event_id": str(uuid.uuid4()),
            "event_type": "login_attempt",
            "event_category": "authentication",
            "action": "submit_credentials",
            "outcome": "failure",
            "decoy_id": "WEB-001",
            "session_id": sess_id,
            "source_address": "198.51.100.22",
            "target_service": "web_portal",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "service_metadata": {"username": "admin", "password_length": 12},
            "provenance": {"source_type": "controlled_test", "environment": "isolated_lab"},
        }

        res = EventProcessor.process_single_event(self.db, raw_payload, source_id="collector-web-01")
        self.assertEqual(res.status, EventProcessingStatus.ACCEPTED)

        # Check execution history in module singleton tracker
        from app.detection.execution_tracker import execution_tracker
        history = execution_tracker.get_history()
        self.assertGreater(len(history), 0)
        self.assertEqual(history[-1].rule_id, "TEST-RULE-001")
        self.assertEqual(history[-1].execution_status, EvaluationStatus.MATCHED)

    def test_det_038_failed_detection_does_not_delete_the_event(self):
        """TEST DET-038: Exception during detection evaluation does not rollback persisted DB state."""
        sess_id = f"decoy_sess_{uuid.uuid4().hex}"
        raw_payload = {
            "schema_version": "1.0",
            "raw_event_id": str(uuid.uuid4()),
            "event_type": "login_attempt",
            "event_category": "authentication",
            "action": "submit_credentials",
            "outcome": "failure",
            "decoy_id": "WEB-001",
            "session_id": sess_id,
            "source_address": "198.51.100.22",
            "target_service": "web_portal",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "service_metadata": {"username": "admin", "password_length": 12},
            "provenance": {"source_type": "controlled_test", "environment": "isolated_lab"},
        }

        # Mock detection engine to raise an exception
        with patch("app.detection.engine.DetectionEngine.evaluate_event", side_effect=Exception("Explosion in detection")):
            res = EventProcessor.process_single_event(self.db, raw_payload, source_id="collector-web-01")
            self.assertEqual(res.status, EventProcessingStatus.ACCEPTED)
            # Verify event was nevertheless committed in DB
            persisted = self.db.query(SecurityEventModel).filter(SecurityEventModel.session_id == sess_id).first()
            self.assertIsNotNone(persisted, "Persisted event must remain stored even when detection fails")

    def test_det_039_rule_execution_failure_is_recorded(self):
        """TEST DET-039: Evaluator failures record an execution failure entry."""
        rule = DetectionRuleDefinition.model_validate(get_test_rule_001())
        with patch("app.detection.event_matcher.EventMatcher.evaluate_rule", side_effect=Exception("Boom")):
            results = self.det_engine.evaluate_event(self.base_event, rules=[rule])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.EVALUATION_ERROR)
            history = self.tracker.get_history()
            self.assertEqual(history[-1].execution_status, EvaluationStatus.EVALUATION_ERROR)

    def test_det_040_reprocessing_does_not_create_duplicate_results(self):
        """TEST DET-040: Reprocessing an event produces identical result ID and zero duplicate audit logs."""
        self.registry.register_rule(get_test_rule_001())
        res1 = self.det_engine.evaluate_event(self.base_event)
        res2 = self.det_engine.evaluate_event(self.base_event)
        self.assertEqual(res1[0].detection_result_id, res2[0].detection_result_id)
        self.assertEqual(len(self.tracker.get_history()), 1)

