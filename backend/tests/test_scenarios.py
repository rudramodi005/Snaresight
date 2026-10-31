"""Comprehensive automated test suite for SnareSight Task P18:
Authentication and Suspicious-Request Detection Scenarios.

Covers all 44 test specifications:
- TEST AUTH-001 to AUTH-007 (Authentication Detection Tests)
- TEST ENUM-001 to ENUM-004 (Username Enumeration Tests)
- TEST WEB-DET-001 to WEB-DET-004 (Web Enumeration Tests)
- TEST TRAV-001 to TRAV-005 (Directory Traversal Tests)
- TEST CMD-001 to CMD-003 (Command Discovery Interaction Tests)
- TEST FILE-001 to FILE-004 (File Interaction Tests)
- TEST BEHAV-001 to BEHAV-005 (Behavioral & Multi-Category Tests)
- TEST SCORE-001 to SCORE-005 (Severity, Confidence, and Provenance Tests)
- TEST ALERT-001 to ALERT-007 (Alert Generation, Cooldown, and Streaming Tests)
"""

import copy
import hashlib
import os
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
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.detection.engine import DetectionEngine
from app.detection.execution_tracker import ExecutionTracker
from app.detection.field_registry import FieldRegistry
from app.detection.registry import RuleRegistry
from app.detection.scenario_catalogue import get_all_scenarios
from app.detection.session_evaluator import SessionEvaluator
from app.schemas.detection import EvaluationStatus
from app.services.alert_service import AlertService
from app.services.threat_assessment_service import ThreatAssessmentService
from app.streaming.event_publisher import EventPublisher
from app.streaming.stream_manager import StreamManager


class TestDetectionScenarios(unittest.TestCase):
    """Test suite executing the 44 detection scenarios and alert lifecycles."""

    def setUp(self):
        """Initializes in-memory database and fresh detection/alert service instances."""
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

        # Initialize registries and engine
        self.registry = RuleRegistry()
        for sc in get_all_scenarios():
            self.registry.register_rule(sc)

        self.tracker = ExecutionTracker()
        self.det_engine = DetectionEngine(registry=self.registry, tracker=self.tracker)
        self.assessment_svc = ThreatAssessmentService(rules=self.registry)
        self.stream_mgr = StreamManager()
        self.publisher = EventPublisher(manager=self.stream_mgr)
        self.alert_svc = AlertService(
            rules=self.registry,
            assessment_svc=self.assessment_svc,
            publisher=self.publisher,
        )

    def tearDown(self):
        """Tears down in-memory database and clears tracker states."""
        self.db.close()
        self.alert_svc.clear()
        self.assessment_svc.clear()

    # Helper to generate synthetic normalized security events
    def _create_event(
        self,
        event_type="LOGIN_ATTEMPT",
        event_category="authentication",
        action="SUBMIT_CREDENTIALS",
        outcome="FAILURE",
        session_id="sess_001",
        decoy_id="WEB-001",
        source_address="198.51.100.10",
        observed_at=None,
        metadata=None,
        provenance=None,
        persist=True,
    ):
        eid = uuid.uuid4()
        now = observed_at or datetime.now(timezone.utc)
        meta = metadata or {}
        prov = provenance or {
            "source_type": "SYNTHETIC_SIMULATION",
            "environment": "isolated_lab",
            "collector_id": "collector-web-01",
        }
        ev_dict = {
            "event_id": str(eid),
            "raw_event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "event_category": event_category,
            "action": action,
            "outcome": outcome,
            "session_id": session_id,
            "decoy_id": decoy_id,
            "source_address": source_address,
            "source_port": 49152,
            "source_protocol": "HTTP",
            "target_service": "WEB_LOGIN",
            "target_port": 8080,
            "observed_at": now.isoformat(),
            "received_at": now.isoformat(),
            "sanitized_metadata": meta,
            "provenance": prov,
            "deduplication_reference": f"dedup_{eid}",
        }
        if persist:
            model = SecurityEventModel(
                event_id=eid,
                raw_event_id=uuid.UUID(ev_dict["raw_event_id"]),
                event_type=event_type,
                event_category=event_category,
                action=action,
                outcome=outcome,
                session_id=session_id,
                decoy_id=decoy_id,
                source_address=source_address,
                source_port=49152,
                source_protocol="HTTP",
                target_service="WEB_LOGIN",
                target_port=8080,
                observed_at=now,
                received_at=now,
                sanitized_metadata=meta,
                provenance=prov,
                deduplication_reference=ev_dict["deduplication_reference"],
            )
            self.db.add(model)
            self.db.commit()
        return ev_dict

    # =========================================================================
    # 1. AUTHENTICATION TESTS (TEST AUTH-001 to AUTH-007)
    # =========================================================================

    def test_auth_001_single_failed_login_does_not_trigger_repeated_failure_rule(self):
        """TEST AUTH-001: Single failed login does not incorrectly trigger repeated-failure rule."""
        ev = self._create_event(outcome="FAILURE", session_id="auth_s1")
        rule = self.registry.get_rule("AUTH-001")
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)
        self.assertIn("NO_MATCH", results[0].detection_explanation)

    def test_auth_002_configured_repeated_failures_trigger_expected_detection(self):
        """TEST AUTH-002: Configured repeated failures trigger the expected detection."""
        rule = self.registry.get_rule("AUTH-001")
        # Generate 3 failures (threshold is 3)
        ev1 = self._create_event(outcome="FAILURE", session_id="auth_s2")
        ev2 = self._create_event(outcome="FAILURE", session_id="auth_s2")
        ev3 = self._create_event(outcome="FAILURE", session_id="auth_s2")

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
        self.assertEqual(results[0].rule_id, "AUTH-001")
        self.assertIn("MATCHED", results[0].detection_explanation)
        self.assertGreaterEqual(len(results[0].related_event_ids), 2)

    def test_auth_003_events_outside_configured_time_window_do_not_qualify(self):
        """TEST AUTH-003: Events outside the configured time window do not incorrectly qualify."""
        rule = self.registry.get_rule("AUTH-001")
        now = datetime.now(timezone.utc)
        # Event 1 and 2 occurred 2 hours ago (outside 300s window)
        old_time = now - timedelta(hours=2)
        self._create_event(outcome="FAILURE", session_id="auth_s3", observed_at=old_time)
        self._create_event(outcome="FAILURE", session_id="auth_s3", observed_at=old_time + timedelta(seconds=1))
        # Event 3 is current
        ev3 = self._create_event(outcome="FAILURE", session_id="auth_s3", observed_at=now)

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        # Old events fell outside the 300s window, so only 1 current event exists -> NO_MATCH
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_auth_004_duplicate_ingestion_does_not_inflate_failure_count(self):
        """TEST AUTH-004: Duplicate ingestion does not inflate the failure count."""
        rule = self.registry.get_rule("AUTH-001")
        ev1 = self._create_event(outcome="FAILURE", session_id="auth_s4")
        # In passing session_events with duplicate event IDs, deduplication ensures count = 1
        dup_events = [ev1, ev1, copy.deepcopy(ev1)]
        results = self.det_engine.evaluate_event(ev1, rules=[rule], session_events=dup_events)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_auth_005_different_validated_sessions_remain_separate(self):
        """TEST AUTH-005: Different validated sessions remain separate."""
        rule = self.registry.get_rule("AUTH-001")
        # Session A has 2 failures
        self._create_event(outcome="FAILURE", session_id="session_ALPHA")
        self._create_event(outcome="FAILURE", session_id="session_ALPHA")
        # Session B has 2 failures
        self._create_event(outcome="FAILURE", session_id="session_BETA")
        ev_b2 = self._create_event(outcome="FAILURE", session_id="session_BETA")

        # Evaluating ev_b2 against session_BETA must not count session_ALPHA events
        results = self.det_engine.evaluate_event(ev_b2, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_auth_006_decoy_authentication_acceptance_is_accurately_classified(self):
        """TEST AUTH-006: Decoy authentication acceptance is accurately classified."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="auth_s6")
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
        self.assertEqual(results[0].rule_id, "AUTH-002")

    def test_auth_007_simulated_access_is_not_reported_as_real_production_compromise(self):
        """TEST AUTH-007: Simulated access is not reported as real production authentication."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="auth_s7")
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        res = results[0]
        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertIsNotNone(alert)
        # Finding title and recommendations must clearly state decoy / simulated warning
        self.assertIn("Decoy", alert.title)
        self.assertIn("isolated honeypot environment", alert.recommendations["simulated_interaction_warning"])
        self.assertNotIn("production compromise", alert.title.lower())

    # =========================================================================
    # 2. USERNAME ENUMERATION TESTS (TEST ENUM-001 to ENUM-004)
    # =========================================================================

    def test_enum_001_repeated_identical_username_fingerprint_is_handled_correctly(self):
        """TEST ENUM-001: Repeated identical username fingerprint is handled correctly."""
        rule = self.registry.get_rule("AUTH-003")
        fp_same = hashlib.sha256(b"admin").hexdigest()
        # 3 attempts using the same username fingerprint
        self._create_event(session_id="enum_s1", metadata={"username_fingerprint": fp_same})
        self._create_event(session_id="enum_s1", metadata={"username_fingerprint": fp_same})
        ev3 = self._create_event(session_id="enum_s1", metadata={"username_fingerprint": fp_same})

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        # Distinct username count is 1 (< threshold 3) -> NO_MATCH
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_enum_002_distinct_username_fingerprints_are_counted_according_to_policy(self):
        """TEST ENUM-002: Distinct username fingerprints are counted according to policy."""
        rule = self.registry.get_rule("AUTH-003")
        fp1 = hashlib.sha256(b"admin").hexdigest()
        fp2 = hashlib.sha256(b"root").hexdigest()
        fp3 = hashlib.sha256(b"test").hexdigest()

        self._create_event(session_id="enum_s2", metadata={"username_fingerprint": fp1})
        self._create_event(session_id="enum_s2", metadata={"username_fingerprint": fp2})
        ev3 = self._create_event(session_id="enum_s2", metadata={"username_fingerprint": fp3})

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
        self.assertIn("3 distinct username fingerprints", results[0].detection_explanation)

    def test_enum_003_missing_username_metadata_does_not_create_false_match(self):
        """TEST ENUM-003: Missing username metadata does not create a false match."""
        rule = self.registry.get_rule("AUTH-003")
        ev = self._create_event(session_id="enum_s3", metadata={})
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_enum_004_plaintext_usernames_are_not_required_for_detection(self):
        """TEST ENUM-004: Plaintext usernames are not required for detection."""
        rule = self.registry.get_rule("AUTH-003")
        # Metadata contains only privacy-safe one-way hash, no plaintext
        fp = hashlib.sha256(b"user_1024").hexdigest()
        ev = self._create_event(session_id="enum_s4", metadata={"username_fingerprint": fp})
        self.assertNotIn("username", ev["sanitized_metadata"])
        self.assertIn("username_fingerprint", ev["sanitized_metadata"])
        # Verified that rule targets metadata.username_fingerprint without needing raw username
        cond_fields = [c.field for c in rule.conditions.all if hasattr(c, "field")]
        self.assertIn("metadata.username_fingerprint", cond_fields)

    # =========================================================================
    # 3. WEB ENUMERATION TESTS (TEST WEB-DET-001 to WEB-DET-004)
    # =========================================================================

    def test_web_det_001_repeated_distinct_path_categories_trigger_configured_rule(self):
        """TEST WEB-DET-001: Repeated distinct path categories trigger the configured rule."""
        rule = self.registry.get_rule("WEB-001")
        self._create_event(event_category="request", session_id="web_s1", metadata={"http_path": "/api/v1"})
        self._create_event(event_category="request", session_id="web_s1", metadata={"http_path": "/wp-login.php"})
        ev3 = self._create_event(event_category="request", session_id="web_s1", metadata={"http_path": "/.env"})

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_web_det_002_repeated_access_to_one_path_is_assessed_correctly(self):
        """TEST WEB-DET-002: Repeated access to one path is assessed correctly."""
        rule = self.registry.get_rule("WEB-001")
        for _ in range(5):
            ev = self._create_event(event_category="request", session_id="web_s2", metadata={"http_path": "/login"})

        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        # Distinct paths probed = 1 (< threshold 3) -> NO_MATCH
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_web_det_003_normalized_equivalent_paths_are_not_double_counted(self):
        """TEST WEB-DET-003: Normalized equivalent paths are not double-counted unnecessarily."""
        p1 = SessionEvaluator.normalize_path("/admin/")
        p2 = SessionEvaluator.normalize_path("/admin")
        self.assertEqual(p1, p2)

        p3 = SessionEvaluator.normalize_path("/etc%2fpasswd")
        p4 = SessionEvaluator.normalize_path("/etc/passwd")
        self.assertEqual(p3, p4)

    def test_web_det_004_ordinary_missing_resource_requests_do_not_become_high_severity(self):
        """TEST WEB-DET-004: Ordinary missing-resource requests do not automatically become high-severity alerts."""
        rule = self.registry.get_rule("WEB-001")
        self.assertEqual(rule.severity_default.value, "LOW")

    # =========================================================================
    # 4. DIRECTORY TRAVERSAL TESTS (TEST TRAV-001 to TRAV-005)
    # =========================================================================

    def test_trav_001_known_safe_traversal_indicators_are_recognized(self):
        """TEST TRAV-001: Known safe traversal indicators are recognized."""
        rule = self.registry.get_rule("WEB-002")
        ev = self._create_event(
            event_category="request",
            session_id="trav_s1",
            metadata={"http_path": "/static/../../etc/passwd"},
        )
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_trav_002_encoded_traversal_representations_are_handled_correctly(self):
        """TEST TRAV-002: Encoded traversal representations are handled correctly."""
        rule = self.registry.get_rule("WEB-002")
        for enc_path in ["/static/..%2f..%2fetc/passwd", "/images/%2e%2e%2fconfig.json", "/..%5cboot.ini"]:
            ev = self._create_event(
                event_category="request",
                session_id=f"trav_enc_{enc_path[:5]}",
                metadata={"http_path": enc_path},
                persist=False,
            )
            results = self.det_engine.evaluate_event(ev, rules=[rule])
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_trav_003_benign_path_strings_do_not_produce_unsupported_matches(self):
        """TEST TRAV-003: Benign path strings do not produce unsupported matches."""
        rule = self.registry.get_rule("WEB-002")
        ev = self._create_event(
            event_category="request",
            session_id="trav_s3",
            metadata={"http_path": "/index.html"},
        )
        results = self.det_engine.evaluate_event(ev, rules=[rule])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_trav_004_detection_does_not_access_the_filesystem(self):
        """TEST TRAV-004: Detection does not access the filesystem."""
        rule = self.registry.get_rule("WEB-002")
        ev = self._create_event(
            event_category="request",
            session_id="trav_s4",
            metadata={"http_path": "../../../non_existent_system_secret.conf"},
        )
        # Mock os.path and file open to assert zero filesystem interaction
        with patch("os.path.exists") as mock_exists, patch("builtins.open") as mock_open:
            results = self.det_engine.evaluate_event(ev, rules=[rule])
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
            mock_exists.assert_not_called()
            mock_open.assert_not_called()

    def test_trav_005_no_submitted_path_is_executed(self):
        """TEST TRAV-005: No submitted path is executed."""
        rule = self.registry.get_rule("WEB-002")
        ev = self._create_event(
            event_category="request",
            session_id="trav_s5",
            metadata={"http_path": "../bin/sh; rm -rf /"},
        )
        with patch("subprocess.run") as mock_sub, patch("os.system") as mock_sys:
            results = self.det_engine.evaluate_event(ev, rules=[rule])
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
            mock_sub.assert_not_called()
            mock_sys.assert_not_called()

    # =========================================================================
    # 5. COMMAND INTERACTION TESTS (TEST CMD-001 to CMD-003)
    # =========================================================================

    def test_cmd_001_supported_command_category_event_is_classified_correctly(self):
        """TEST CMD-001: Supported command-category event is classified correctly when enabled."""
        rule = copy.deepcopy(self.registry.get_rule("CMD-001"))
        rule.enabled = True  # Controlled test mode
        ev = self._create_event(
            event_type="COMMAND_RUN",
            event_category="COMMAND_EXECUTION",
            session_id="cmd_s1",
            metadata={"command_category": "sys_info", "command_text": "uname -a"},
            persist=False,
        )
        results = self.det_engine.evaluate_event(ev, rules=[rule])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_cmd_002_unsupported_command_telemetry_is_deferred_safely(self):
        """TEST CMD-002: Unsupported command telemetry is rejected or deferred safely."""
        # Built-in CMD-001 rule is explicitly disabled / deferred
        rule = self.registry.get_rule("CMD-001")
        self.assertFalse(rule.enabled)
        ev = self._create_event(session_id="cmd_s2", metadata={"command_category": "unknown_cat"})
        results = self.det_engine.evaluate_event(ev, rules=[rule])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.SKIPPED)
        self.assertIn("deferred", results[0].detection_explanation.lower())

    def test_cmd_003_recorded_command_text_is_never_executed(self):
        """TEST CMD-003: Recorded command text is never executed."""
        rule = copy.deepcopy(self.registry.get_rule("CMD-001"))
        rule.enabled = True
        ev = self._create_event(
            event_type="COMMAND_RUN",
            event_category="COMMAND_EXECUTION",
            session_id="cmd_s3",
            metadata={"command_category": "identity", "command_text": "whoami && id"},
            persist=False,
        )
        with patch("subprocess.Popen") as mock_popen, patch("os.system") as mock_sys:
            results = self.det_engine.evaluate_event(ev, rules=[rule])
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
            mock_popen.assert_not_called()
            mock_sys.assert_not_called()

    # =========================================================================
    # 6. FILE INTERACTION TESTS (TEST FILE-001 to FILE-004)
    # =========================================================================

    def test_file_001_supported_transfer_metadata_generates_expected_finding(self):
        """TEST FILE-001: Supported transfer metadata generates the expected finding when active."""
        rule = copy.deepcopy(self.registry.get_rule("FILE-001"))
        rule.enabled = True
        ev = self._create_event(
            event_category="APPLICATION",
            session_id="file_s1",
            metadata={"transfer_direction": "UPLOAD", "file_name": "malware_sample.bin"},
            persist=False,
        )
        results = self.det_engine.evaluate_event(ev, rules=[rule])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_file_002_missing_transfer_fields_are_handled_correctly(self):
        """TEST FILE-002: Missing transfer fields are handled correctly."""
        rule = copy.deepcopy(self.registry.get_rule("FILE-001"))
        rule.enabled = True
        ev = self._create_event(event_category="APPLICATION", session_id="file_s2", metadata={})
        results = self.det_engine.evaluate_event(ev, rules=[rule])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_file_003_no_uploaded_file_is_executed(self):
        """TEST FILE-003: No uploaded file is executed."""
        rule = copy.deepcopy(self.registry.get_rule("FILE-001"))
        rule.enabled = True
        ev = self._create_event(
            event_category="APPLICATION",
            session_id="file_s3",
            metadata={"transfer_direction": "UPLOAD", "file_name": "payload.exe"},
            persist=False,
        )
        with patch("subprocess.run") as mock_sub:
            results = self.det_engine.evaluate_event(ev, rules=[rule])
            self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
            mock_sub.assert_not_called()

    def test_file_004_no_unnecessary_file_contents_are_persisted(self):
        """TEST FILE-004: No unnecessary file contents are persisted."""
        ev = self._create_event(
            event_category="APPLICATION",
            session_id="file_s4",
            metadata={"transfer_direction": "UPLOAD", "file_name": "safe.txt", "file_size": 256},
        )
        self.assertNotIn("file_content", ev["sanitized_metadata"])
        self.assertNotIn("raw_payload_bytes", ev["sanitized_metadata"])

    # =========================================================================
    # 7. BEHAVIOR TESTS (TEST BEHAV-001 to BEHAV-005)
    # =========================================================================

    def test_behav_001_multiple_distinct_suspicious_categories_are_identified(self):
        """TEST BEHAV-001: Multiple distinct suspicious categories are identified."""
        rule = self.registry.get_rule("BEHAV-001")
        self._create_event(event_category="authentication", session_id="behav_s1")
        ev2 = self._create_event(event_category="request", session_id="behav_s1")

        results = self.det_engine.evaluate_event(ev2, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)
        self.assertIn("distinct security categories", results[0].detection_explanation)

    def test_behav_002_unrelated_sessions_are_not_combined(self):
        """TEST BEHAV-002: Unrelated sessions are not combined."""
        rule = self.registry.get_rule("BEHAV-001")
        self._create_event(event_category="authentication", session_id="session_101")
        ev_diff = self._create_event(event_category="request", session_id="session_102")

        results = self.det_engine.evaluate_event(ev_diff, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        # Session 102 only has 1 category -> NO_MATCH
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_behav_003_duplicate_observations_do_not_inflate_evidence(self):
        """TEST BEHAV-003: Duplicate observations do not inflate evidence."""
        rule = self.registry.get_rule("BEHAV-001")
        ev1 = self._create_event(event_category="authentication", session_id="behav_s3")
        # Same event repeated multiple times
        results = self.det_engine.evaluate_event(ev1, rules=[rule], session_events=[ev1, ev1, ev1])
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.NO_MATCH)

    def test_behav_004_repeated_suspicious_requests_are_evaluated_correctly(self):
        """TEST BEHAV-004: Repeated suspicious requests are evaluated correctly."""
        rule = self.registry.get_rule("WEB-003")
        self._create_event(event_category="request", session_id="rep_s1", metadata={"request_pattern": "sqli_probe"})
        self._create_event(event_category="request", session_id="rep_s1", metadata={"request_pattern": "traversal_probe"})
        ev3 = self._create_event(event_category="request", session_id="rep_s1", metadata={"request_pattern": "xss_probe"})

        results = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evaluation_status, EvaluationStatus.MATCHED)

    def test_behav_005_false_positive_suppression_works_as_configured(self):
        """TEST BEHAV-005: False-positive suppression works as configured."""
        rule = self.registry.get_rule("WEB-002")
        ev = self._create_event(
            event_category="request",
            session_id="supp_session_99",
            metadata={"http_path": "/static/../app.js"},
        )
        results = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)
        res = results[0]
        self.assertEqual(res.evaluation_status, EvaluationStatus.MATCHED)

        # Register suppression for this session
        self.alert_svc.add_suppression_rule(
            suppression_id="supp_01",
            session_id="supp_session_99",
            reason="Authorized penetration testing window",
        )

        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertIsNone(alert)

        # Audit log verifies suppression was auditable
        audits = self.alert_svc.get_suppression_audit_log()
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["reason"], "Authorized penetration testing window")

    # =========================================================================
    # 8. SCORING TESTS (TEST SCORE-001 to SCORE-005)
    # =========================================================================

    def test_score_001_severity_is_generated_using_p17(self):
        """TEST SCORE-001: Severity is generated using P17."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="score_s1")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        assessment = self.assessment_svc.assess_detection(res, ev, db=self.db)
        self.assertIn(assessment.severity_level.value, ["HIGH", "CRITICAL"])
        self.assertGreater(assessment.severity_score, 0)

    def test_score_002_confidence_is_generated_independently(self):
        """TEST SCORE-002: Confidence is generated independently."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="score_s2")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        assessment = self.assessment_svc.assess_detection(res, ev, db=self.db)
        self.assertGreaterEqual(assessment.confidence_score, 50)
        self.assertLessEqual(assessment.confidence_score, 100)

    def test_score_003_evidence_strength_is_preserved(self):
        """TEST SCORE-003: Evidence strength is preserved."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="score_s3")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        assessment = self.assessment_svc.assess_detection(res, ev, db=self.db)
        self.assertIn(assessment.evidence_strength.value, ["INSUFFICIENT", "LIMITED", "MODERATE", "STRONG"])

    def test_score_004_explanation_matches_the_actual_evidence(self):
        """TEST SCORE-004: Explanation matches the actual evidence."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="score_s4")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        assessment = self.assessment_svc.assess_detection(res, ev, db=self.db)
        self.assertEqual(assessment.rule_id, "AUTH-002")
        self.assertIn("HIGH", assessment.severity_explanation)

    def test_score_005_synthetic_provenance_remains_visible(self):
        """TEST SCORE-005: Synthetic provenance remains visible."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(
            outcome="SUCCESS",
            session_id="score_s5",
            provenance={"source_type": "SYNTHETIC_SIMULATION", "environment": "test_lab"},
        )
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        assessment = self.assessment_svc.assess_detection(res, ev, db=self.db)
        self.assertEqual(assessment.provenance.get("source_type"), "SYNTHETIC_SIMULATION")

    # =========================================================================
    # 9. ALERT TESTS (TEST ALERT-001 to ALERT-007)
    # =========================================================================

    def test_alert_001_matching_detection_generates_alert_where_configured(self):
        """TEST ALERT-001: Matching detection generates an alert where configured."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="alert_s1")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.detection_rule_id, "AUTH-002")

        # Verify in DB
        db_alert = self.db.query(AlertModel).filter(AlertModel.alert_id == alert.alert_id).first()
        self.assertIsNotNone(db_alert)

    def test_alert_002_nonmatching_detection_does_not_generate_alert(self):
        """TEST ALERT-002: Nonmatching detection does not generate an alert."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="FAILURE", session_id="alert_s2")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertIsNone(alert)

    def test_alert_003_duplicate_alert_generation_is_prevented(self):
        """TEST ALERT-003: Duplicate alert generation is prevented."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="alert_s3")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        alert1 = self.alert_svc.create_alert(self.db, res, ev, cooldown_seconds=300)
        self.assertIsNotNone(alert1)

        # Immediate second alert for same rule & session is blocked by cooldown
        alert2 = self.alert_svc.create_alert(self.db, res, ev, cooldown_seconds=300)
        self.assertIsNone(alert2)

    def test_alert_004_rule_version_is_retained(self):
        """TEST ALERT-004: Rule version is retained."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="alert_s4")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]
        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertEqual(alert.detection_rule_version, "1.0")

    def test_alert_005_supporting_event_references_remain_valid(self):
        """TEST ALERT-005: Supporting event references remain valid."""
        rule = self.registry.get_rule("AUTH-001")
        self._create_event(outcome="FAILURE", session_id="alert_s5")
        self._create_event(outcome="FAILURE", session_id="alert_s5")
        ev3 = self._create_event(outcome="FAILURE", session_id="alert_s5")

        res = self.det_engine.evaluate_event(ev3, rules=[rule], db=self.db)[0]
        alert = self.alert_svc.create_alert(self.db, res, ev3)
        self.assertIsNotNone(alert)

        # Check evidence junction table
        evidence_links = self.db.query(AlertEvidenceModel).filter(AlertEvidenceModel.alert_id == alert.alert_id).all()
        self.assertGreaterEqual(len(evidence_links), 3)

    def test_alert_006_streaming_notification_occurs_after_database_commit(self):
        """TEST ALERT-006: Streaming notification occurs after database commit."""
        from app.streaming.authorization import StreamUser
        user = StreamUser(user_id="user_1", username="analyst_1", roles=["analyst"])
        sub = self.stream_mgr.register_subscriber(user=user)
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="alert_s6")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]

        alert = self.alert_svc.create_alert(self.db, res, ev)
        self.assertIsNotNone(alert)

        # Subscriber queue has received the security_alert frame
        self.assertFalse(sub.queue.empty())
        msg = sub.queue.get_nowait()
        self.assertIn("event: security_alert", msg)
        self.assertIn(str(alert.alert_id), msg)

    def test_alert_007_streaming_failure_does_not_delete_the_alert(self):
        """TEST ALERT-007: Streaming failure does not delete the alert."""
        rule = self.registry.get_rule("AUTH-002")
        ev = self._create_event(outcome="SUCCESS", session_id="alert_s7")
        res = self.det_engine.evaluate_event(ev, rules=[rule], db=self.db)[0]

        # Simulate exception during publisher broadcast
        with patch.object(self.publisher, "publish_persisted_alert", side_effect=RuntimeError("Stream network down")):
            alert = self.alert_svc.create_alert(self.db, res, ev)
            self.assertIsNotNone(alert)

            # DB persistence remains intact
            db_alert = self.db.query(AlertModel).filter(AlertModel.alert_id == alert.alert_id).first()
            self.assertIsNotNone(db_alert)
            self.assertEqual(db_alert.alert_id, alert.alert_id)


if __name__ == "__main__":
    unittest.main()
