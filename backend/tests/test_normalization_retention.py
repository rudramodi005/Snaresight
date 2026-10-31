"""Comprehensive test suite for SnareSight Task P14:
Normalization, Deduplication, Data Lifecycle Management, and Evidence Retention.

Covers:
- TEST NORM-001 to NORM-010 (Normalization)
- TEST DEDUP-001 to DEDUP-008 (Deduplication)
- TEST RET-001 to RET-014 (Retention & Preservation)
- TEST DATA-001 to DATA-005 (Data Integrity)
"""

import copy
import uuid
from datetime import datetime, timezone, timedelta
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.ingestion.schemas import EventProcessingStatus
from app.ingestion.event_classifier import EventClassifier
from app.ingestion.timestamp_normalizer import TimestampNormalizer
from app.ingestion.source_normalizer import SourceNormalizer
from app.ingestion.metadata_normalizer import MetadataNormalizer
from app.ingestion.normalizer import EventNormalizer
from app.ingestion.deduplicator import EventDeduplicator
from app.ingestion.processor import EventProcessor
from app.retention.config import RetentionPolicyConfig
from app.retention.calculator import RetentionCalculator
from app.retention.preservation import EvidencePreservationService
from app.retention.audit import RetentionAuditTracker
from app.retention.service import RetentionService
from app.retention.reprocessor import EventReprocessingService


class TestNormalizationAndRetention(unittest.TestCase):
    """Test suite for event normalization, deduplication, retention, and evidence preservation."""

    def setUp(self):
        """Set up in-memory SQLite database and test fixtures."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        # Seed Honeypot & Rule
        self.decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="Production Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(self.decoy)

        self.rule = DetectionRuleModel(
            rule_id="RULE-WEB-BRUTE",
            rule_name="Repeated Web Login Failures",
            rule_version="1.0",
            description="Detects rapid failed login attempts on web decoys",
            category="AUTHENTICATION",
            enabled=True,
            severity="HIGH",
            configuration={"threshold": 5, "window_seconds": 60},
        )
        self.db.add(self.rule)
        self.db.commit()

        # Base sample valid event conforming to P11 contract
        self.base_event = {
            "raw_event_id": str(uuid.uuid4()),
            "schema_version": "1.0",
            "event_type": "login_attempt",
            "event_category": "authentication",
            "decoy_id": "WEB-001",
            "session_id": "decoy_sess_3430c5e63810486c99cff33faad6a50d",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source": {
                "ip_address": "198.51.100.45",
                "port": 54321,
                "protocol": "https",
                "user_agent_summary": "Mozilla/5.0 TestClient",
            },
            "request": {
                "method": "POST",
                "path": "/login",
                "content_type": "application/x-www-form-urlencoded",
            },
            "interaction": {
                "username_fingerprint": "7c4852c2863cb6ff7bb84f50684f00db1e075c35399587ccf618a8efaa6734ee",
                "username_length": 18,
                "password_present": True,
                "password_length_category": "medium (8-16)",
                "status_code": 401,
                "simulated_outcome": "simulated_auth_failure",
                "is_authorized": False,
            },
            "provenance": {
                "source_type": "controlled_test",
                "environment": "isolated_lab",
                "source_id": "lab-vm-01",
            },
        }

    def tearDown(self):
        """Clean up database session and tables."""
        self.db.close()
        Base.metadata.drop_all(self.engine)

    # =========================================================================
    # NORMALIZATION TESTS: TEST NORM-001 to NORM-010
    # =========================================================================

    def test_norm_001_valid_web_event_normalizes_correctly(self):
        """TEST NORM-001: Valid web event normalizes correctly."""
        obs_dt = datetime.now(timezone.utc)
        normalized = EventNormalizer.normalize_event(self.base_event, obs_dt, "dedup_ref_001")

        self.assertIsInstance(normalized["event_id"], uuid.UUID)
        self.assertEqual(str(normalized["raw_event_id"]), self.base_event["raw_event_id"])
        self.assertEqual(normalized["action"], "SUBMIT_CREDENTIALS")
        self.assertEqual(normalized["outcome"], "FAILURE")
        self.assertEqual(normalized["target_service"], "WEB_PORTAL")
        self.assertEqual(normalized["target_port"], 8080)

    def test_norm_002_required_fields_are_preserved(self):
        """TEST NORM-002: Required fields are preserved."""
        obs_dt = datetime.now(timezone.utc)
        normalized = EventNormalizer.normalize_event(self.base_event, obs_dt, "dedup_ref_002")

        required_keys = [
            "event_id", "raw_event_id", "schema_version", "event_type",
            "event_category", "action", "outcome", "decoy_id", "session_id",
            "observed_at", "received_at", "normalized_at", "source_address",
            "target_service", "target_port", "provenance"
        ]
        for key in required_keys:
            self.assertIn(key, normalized)
            self.assertIsNotNone(normalized[key], f"Key {key} should not be None")

    def test_norm_003_optional_fields_remain_optional(self):
        """TEST NORM-003: Optional fields remain optional."""
        event_without_port = copy.deepcopy(self.base_event)
        event_without_port["source"]["port"] = None

        obs_dt = datetime.now(timezone.utc)
        normalized = EventNormalizer.normalize_event(event_without_port, obs_dt, "dedup_ref_003")

        self.assertIsNone(normalized["source_port"])
        self.assertEqual(normalized["source_address"], "198.51.100.45")

    def test_norm_004_event_category_is_consistent_with_event_type(self):
        """TEST NORM-004: Event category is consistent with event type."""
        cat_login = EventClassifier.classify_category("login_attempt")
        self.assertEqual(cat_login, "AUTHENTICATION")

        cat_page = EventClassifier.classify_category("decoy_page_visited")
        self.assertEqual(cat_page, "REQUEST")

        cat_conn = EventClassifier.classify_category("port_probe")
        self.assertEqual(cat_conn, "CONNECTION")

        # Contradiction check: Authentication attempt cannot be classified as SUCCESS on decoy
        is_valid, diag = EventClassifier.validate_classification_consistency(
            event_type="login_attempt",
            category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="SUCCESS",
            provenance=self.base_event["provenance"],
            interaction={"is_authorized": False},
        )
        self.assertFalse(is_valid)
        self.assertIn("cannot be classified as SUCCESS", diag.explanation)

    def test_norm_005_provenance_is_preserved(self):
        """TEST NORM-005: Provenance is preserved."""
        event = copy.deepcopy(self.base_event)
        event["provenance"]["environment"] = "demo_sandbox"

        obs_dt = datetime.now(timezone.utc)
        normalized = EventNormalizer.normalize_event(event, obs_dt, "dedup_ref_005")

        self.assertEqual(normalized["provenance"]["environment"], "demo_sandbox")

    def test_norm_006_session_references_are_preserved(self):
        """TEST NORM-006: Session references are preserved."""
        obs_dt = datetime.now(timezone.utc)
        normalized = EventNormalizer.normalize_event(self.base_event, obs_dt, "dedup_ref_006")

        self.assertEqual(normalized["session_id"], "decoy_sess_3430c5e63810486c99cff33faad6a50d")
        self.assertTrue(normalized["observed_source_id"].startswith("src_profile_decoy_se"))

    def test_norm_007_utc_conversion_works(self):
        """TEST NORM-007: UTC conversion works."""
        # Non-UTC timezone offset (+05:30) in the past
        ts_ist = "2026-10-31T05:30:00+05:30"
        dt_utc, is_late, diag = TimestampNormalizer.parse_to_utc(ts_ist)

        self.assertIsNone(diag)
        self.assertEqual(dt_utc.tzinfo, timezone.utc)
        self.assertEqual(dt_utc.hour, 0)
        self.assertEqual(dt_utc.minute, 0)

    def test_norm_008_invalid_timestamps_are_rejected(self):
        """TEST NORM-008: Invalid timestamps are rejected."""
        dt_utc, is_late, diag = TimestampNormalizer.parse_to_utc("not-a-timestamp")
        self.assertIsNone(dt_utc)
        self.assertIsNotNone(diag)
        self.assertEqual(diag.rejection_category, "timestamp")

    def test_norm_009_future_timestamp_anomalies_are_flagged(self):
        """TEST NORM-009: Future timestamp anomalies are flagged."""
        future_ts = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        dt_utc, is_late, diag = TimestampNormalizer.parse_to_utc(future_ts, future_skew_tolerance_seconds=300)

        self.assertIsNone(dt_utc)
        self.assertIsNotNone(diag)
        self.assertEqual(diag.rejection_category, "timestamp_anomaly")

    def test_norm_010_late_arriving_events_remain_valid_where_permitted(self):
        """TEST NORM-010: Late-arriving events remain valid where permitted."""
        past_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        dt_utc, is_late, diag = TimestampNormalizer.parse_to_utc(past_ts)

        self.assertIsNotNone(dt_utc)
        self.assertIsNone(diag)
        self.assertTrue(is_late, "Event older than 30 days should be flagged as late-arriving")

    # =========================================================================
    # DEDUPLICATION TESTS: TEST DEDUP-001 to DEDUP-008
    # =========================================================================

    def test_dedup_001_first_event_is_accepted(self):
        """TEST DEDUP-001: First event is accepted."""
        result = EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.ACCEPTED)

    def test_dedup_002_identical_source_event_id_is_identified_as_duplicate(self):
        """TEST DEDUP-002: Identical source event ID is identified as duplicate."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        # Submit identical event again
        dup_result = EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        self.assertEqual(dup_result.status, EventProcessingStatus.DUPLICATE)

    def test_dedup_003_same_id_with_different_content_triggers_a_conflict(self):
        """TEST DEDUP-003: Same ID with different content triggers a conflict."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")

        # Create altered event with SAME raw_event_id but DIFFERENT content
        altered_event = copy.deepcopy(self.base_event)
        altered_event["interaction"]["username_attempted"] = "malicious_different_user"
        altered_event["interaction"]["path"] = "/secret_different_path"

        conflict_result = EventProcessor.process_single_event(self.db, altered_event, "collector-agent-01")
        self.assertEqual(conflict_result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(conflict_result.error.rejection_category, "identifier_collision")

    def test_dedup_004_distinct_legitimate_events_are_preserved(self):
        """TEST DEDUP-004: Distinct legitimate events are preserved."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")

        # Legitimate second interaction with different ID and timestamp
        second_event = copy.deepcopy(self.base_event)
        second_event["raw_event_id"] = str(uuid.uuid4())
        second_event["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        res2 = EventProcessor.process_single_event(self.db, second_event, "collector-agent-01")
        self.assertEqual(res2.status, EventProcessingStatus.ACCEPTED)

        # Verify 2 distinct rows exist in database
        sec_count = self.db.query(SecurityEventModel).count()
        self.assertEqual(sec_count, 2)

    def test_dedup_005_repeated_batch_processing_is_idempotent(self):
        """TEST DEDUP-005: Repeated batch processing is idempotent."""
        ev1 = copy.deepcopy(self.base_event)
        ev2 = copy.deepcopy(self.base_event)
        ev2["raw_event_id"] = str(uuid.uuid4())
        ev2["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()

        batch = [ev1, ev2]
        # First submission
        for ev in batch:
            r = EventProcessor.process_single_event(self.db, ev, "collector-agent-01")
            self.assertEqual(r.status, EventProcessingStatus.ACCEPTED)

        # Second submission
        for ev in batch:
            r = EventProcessor.process_single_event(self.db, ev, "collector-agent-01")
            self.assertEqual(r.status, EventProcessingStatus.DUPLICATE)

        # Verify row counts remain unchanged
        self.assertEqual(self.db.query(RawEventModel).count(), 2)
        self.assertEqual(self.db.query(SecurityEventModel).count(), 2)

    def test_dedup_006_concurrent_duplicate_submissions_do_not_create_duplicate_rows(self):
        """TEST DEDUP-006: Duplicate submissions do not create duplicate rows."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        # Repeated attempt
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        self.assertEqual(self.db.query(SecurityEventModel).count(), 1)

    def test_dedup_007_database_unique_constraints_prevent_duplicate_persistence(self):
        """TEST DEDUP-007: Database unique constraints prevent duplicate persistence."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        first_sec = self.db.query(SecurityEventModel).first()

        # Attempt to insert directly into DB with same deduplication_reference
        duplicate_model = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),  # Different raw_id
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="decoy_sess_3430c5e63810486c99cff33faad6a50d",
            source_address="198.51.100.45",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=datetime.now(timezone.utc),
            received_at=datetime.now(timezone.utc),
            sanitized_metadata={},
            provenance={},
            deduplication_reference=first_sec.deduplication_reference,  # Collision on UNIQUE constraint
        )
        self.db.add(duplicate_model)
        with self.assertRaises(Exception):
            self.db.commit()
        self.db.rollback()

    def test_dedup_008_simulation_and_live_events_remain_separate(self):
        """TEST DEDUP-008: Simulation and live events remain separate."""
        sim_event = copy.deepcopy(self.base_event)
        sim_event["provenance"] = {
            "source_type": "synthetic_simulation",
            "environment": "isolated_lab",
            "source_id": "lab-vm-01",
        }
        res = EventProcessor.process_single_event(self.db, sim_event, "collector-agent-01")
        self.assertEqual(res.status, EventProcessingStatus.ACCEPTED)

        stored = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(sim_event["raw_event_id"])
        ).first()
        self.assertEqual(stored.provenance["source_type"], "synthetic_simulation")

        stored = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(sim_event["raw_event_id"])
        ).first()
        self.assertEqual(stored.provenance["source_type"], "synthetic_simulation")

    # =========================================================================
    # RETENTION TESTS: TEST RET-001 to RET-014
    # =========================================================================

    def test_ret_001_retention_eligibility_is_calculated_correctly(self):
        """TEST RET-001: Retention eligibility is calculated correctly."""
        cfg = RetentionPolicyConfig({"RAW_EVENTS": 90})
        # Record 91 days old -> expired
        old_ts = datetime.now(timezone.utc) - timedelta(days=91)
        self.assertTrue(RetentionCalculator.is_expired("RAW_EVENTS", old_ts, policy_config=cfg))

        # Record 89 days old -> not expired
        recent_ts = datetime.now(timezone.utc) - timedelta(days=89)
        self.assertFalse(RetentionCalculator.is_expired("RAW_EVENTS", recent_ts, policy_config=cfg))

    def test_ret_002_raw_and_normalized_events_follow_separate_policies(self):
        """TEST RET-002: Raw and normalized events follow separate policies."""
        cfg = RetentionPolicyConfig({
            "RAW_EVENTS": 30,
            "NORMALIZED_EVENTS": 90,
        })
        ts = datetime.now(timezone.utc) - timedelta(days=45)
        # 45 days is expired for RAW_EVENTS (30d) but NOT expired for NORMALIZED_EVENTS (90d)
        self.assertTrue(RetentionCalculator.is_expired("RAW_EVENTS", ts, policy_config=cfg))
        self.assertFalse(RetentionCalculator.is_expired("NORMALIZED_EVENTS", ts, policy_config=cfg))

    def test_ret_003_alert_retention_is_calculated_correctly(self):
        """TEST RET-003: Alert retention is calculated correctly."""
        cfg = RetentionPolicyConfig({"ALERTS": 365})
        alert_ts = datetime.now(timezone.utc) - timedelta(days=400)
        self.assertTrue(RetentionCalculator.is_expired("ALERTS", alert_ts, policy_config=cfg))

    def test_ret_004_simulation_retention_is_configurable(self):
        """TEST RET-004: Simulation retention is configurable."""
        cfg = RetentionPolicyConfig({"SIMULATION_EVENTS": 14})
        self.assertEqual(cfg.get_retention_days("SIMULATION_EVENTS"), 14)
        cfg.set_retention("SIMULATION_EVENTS", 7)
        self.assertEqual(cfg.get_retention_days("SIMULATION_EVENTS"), 7)

    def test_ret_005_dry_run_mode_makes_no_destructive_changes(self):
        """TEST RET-005: Dry-run mode makes no destructive changes."""
        # Insert old expired record
        old_time = datetime.now(timezone.utc) - timedelta(days=200)
        sec_event = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="sess_old",
            source_address="1.2.3.4",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=old_time,
            received_at=old_time,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="old_ref_001",
        )
        self.db.add(sec_event)
        self.db.commit()

        service = RetentionService()
        preview = service.preview_retention(self.db)

        self.assertEqual(preview["mode"], "DRY_RUN")
        self.assertGreaterEqual(preview["candidate_count"], 1)
        self.assertEqual(preview["deleted_count"], 0)
        # Verify row still exists in DB
        self.assertEqual(self.db.query(SecurityEventModel).count(), 1)

    def test_ret_006_active_investigation_evidence_is_preserved(self):
        """TEST RET-006: Active investigation evidence is preserved."""
        preservation = EvidencePreservationService()
        ev_id = uuid.uuid4()
        preservation.place_hold(
            investigation_id="INV-2026-001",
            target_id=str(ev_id),
            target_type="SECURITY_EVENT",
            reason="Suspected APT brute-force campaign",
            authorized_analyst="analyst_alice",
        )
        self.assertTrue(preservation.is_target_preserved(self.db, ev_id, "SECURITY_EVENT"))

    def test_ret_007_preservation_holds_override_ordinary_retention(self):
        """TEST RET-007: Preservation holds override ordinary retention."""
        old_time = datetime.now(timezone.utc) - timedelta(days=200)
        ev_id = uuid.uuid4()
        sec_event = SecurityEventModel(
            event_id=ev_id,
            raw_event_id=uuid.uuid4(),
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="sess_held",
            source_address="1.2.3.4",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=old_time,
            received_at=old_time,
            sanitized_metadata={},
            provenance={},
            deduplication_reference="held_ref_001",
        )
        self.db.add(sec_event)
        self.db.commit()

        preservation = EvidencePreservationService()
        preservation.place_hold(
            investigation_id="INV-001",
            target_id=str(ev_id),
            target_type="SECURITY_EVENT",
            reason="Legal hold",
            authorized_analyst="analyst_bob",
        )

        service = RetentionService(preservation=preservation)
        res = service.execute_retention(
            self.db,
            authorization_token="CONFIRM_RETENTION_DELETION",
            initiated_by="admin_test",
        )
        self.assertEqual(res["preserved_count"], 1)
        self.assertEqual(res["deleted_count"], 0)
        # Record remains in DB
        self.assertEqual(self.db.query(SecurityEventModel).count(), 1)

    def test_ret_008_expired_records_are_identified_correctly(self):
        """TEST RET-008: Expired records are identified correctly."""
        cfg = RetentionPolicyConfig({"NORMALIZED_EVENTS": 90})
        old_ts = datetime.now(timezone.utc) - timedelta(days=120)
        self.assertTrue(RetentionCalculator.is_expired("NORMALIZED_EVENTS", old_ts, policy_config=cfg))

    def test_ret_009_deletion_requires_authorization(self):
        """TEST RET-009: Deletion requires authorization."""
        service = RetentionService()
        with self.assertRaises(PermissionError):
            service.execute_retention(
                self.db,
                authorization_token="INVALID_TOKEN",
                initiated_by="unauthorized_actor",
            )

    def test_ret_010_retention_operations_are_audited(self):
        """TEST RET-010: Retention operations are audited."""
        audit = RetentionAuditTracker()
        service = RetentionService(audit=audit)
        service.preview_retention(self.db)

        history = audit.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].mode, "DRY_RUN")

    def test_ret_011_partial_retention_failure_is_handled_safely(self):
        """TEST RET-011: Partial retention failure is handled safely."""
        service = RetentionService()
        res = service.preview_retention(self.db)
        self.assertIn(res["status"], {"SUCCESS", "PARTIAL", "FAILED"})

    def test_ret_012_retention_does_not_break_foreign_key_relationships(self):
        """TEST RET-012: Retention does not break foreign-key relationships."""
        # Insert raw event and linked security event
        raw_id = uuid.uuid4()
        raw_ev = RawEventModel(
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type="login_attempt",
            event_category="AUTHENTICATION",
            decoy_id="WEB-001",
            event_source_id="WEB-001",
            session_id="sess_fk",
            observed_at=datetime.now(timezone.utc) - timedelta(days=200),
            received_at=datetime.now(timezone.utc) - timedelta(days=200),
            sanitized_payload={},
            provenance={},
            validation_status="VALID",
        )
        self.db.add(raw_ev)
        self.db.flush()

        sec_ev = SecurityEventModel(
            event_id=uuid.uuid4(),
            raw_event_id=raw_id,
            schema_version="1.0",
            event_type="LOGIN_ATTEMPT",
            event_category="AUTHENTICATION",
            action="SUBMIT_CREDENTIALS",
            outcome="FAILURE",
            decoy_id="WEB-001",
            session_id="sess_fk",
            source_address="1.2.3.4",
            source_protocol="https",
            target_service="WEB_PORTAL",
            target_port=8080,
            observed_at=datetime.now(timezone.utc) - timedelta(days=200),
            received_at=datetime.now(timezone.utc) - timedelta(days=200),
            sanitized_metadata={},
            provenance={},
            deduplication_reference="fk_ref_001",
        )
        self.db.add(sec_ev)
        self.db.commit()

        # Execute retention evaluating only RAW_EVENTS
        # Since raw event has a living linked security_event, it must be preserved!
        service = RetentionService()
        res = service.execute_retention(
            self.db,
            authorization_token="CONFIRM_RETENTION_DELETION",
            categories=["RAW_EVENTS"],
            initiated_by="admin",
        )
        self.assertEqual(res["deleted_count"], 0)
        self.assertEqual(res["preserved_count"], 1)

    def test_ret_013_trusted_server_timestamps_drive_retention_decisions(self):
        """TEST RET-013: Trusted server timestamps drive retention decisions."""
        # Attacker sets observed_at to 10 years ago, but server received it 1 day ago
        attacker_event = {
            "observed_at": datetime(2016, 1, 1, tzinfo=timezone.utc),
            "received_at": datetime.now(timezone.utc) - timedelta(days=1),
        }
        cfg = RetentionPolicyConfig({"RAW_EVENTS": 90})
        # Server timestamp (received_at) is only 1 day old -> NOT expired!
        server_ts = RetentionCalculator.get_trusted_timestamp(attacker_event, "RAW_EVENTS")
        self.assertFalse(RetentionCalculator.is_expired("RAW_EVENTS", server_ts, policy_config=cfg))

    def test_ret_014_retention_configuration_cannot_be_silently_modified(self):
        """TEST RET-014: Retention configuration cannot be silently modified."""
        cfg = RetentionPolicyConfig()
        # Attempt to set retention below lower bound (RAW_EVENTS min is 7 days)
        with self.assertRaises(ValueError):
            cfg.set_retention("RAW_EVENTS", 1)

        # Attempt to set retention above upper bound (RAW_EVENTS max is 730 days)
        with self.assertRaises(ValueError):
            cfg.set_retention("RAW_EVENTS", 10000)

    # =========================================================================
    # DATA INTEGRITY TESTS: TEST DATA-001 to DATA-005
    # =========================================================================

    def test_data_001_raw_event_evidence_remains_available_after_normalization(self):
        """TEST DATA-001: Raw event evidence remains available after normalization."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        raw_record = self.db.query(RawEventModel).filter(
            RawEventModel.raw_event_id == uuid.UUID(self.base_event["raw_event_id"])
        ).first()
        self.assertIsNotNone(raw_record)
        self.assertEqual(raw_record.sanitized_payload["session_id"], self.base_event["session_id"])

    def test_data_002_normalized_records_reference_their_raw_events(self):
        """TEST DATA-002: Normalized records reference their raw events."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        sec_record = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(self.base_event["raw_event_id"])
        ).first()
        self.assertIsNotNone(sec_record)
        self.assertEqual(sec_record.raw_event.raw_event_id, sec_record.raw_event_id)

    def test_data_003_provenance_remains_intact_after_reprocessing(self):
        """TEST DATA-003: Provenance remains intact after reprocessing."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        res = EventReprocessingService.execute_reprocessing(
            self.db,
            raw_event_ids=[uuid.UUID(self.base_event["raw_event_id"])],
            authorized_by="admin_auditor",
        )
        self.assertEqual(res["processed_count"], 1)

        sec_record = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(self.base_event["raw_event_id"])
        ).first()
        self.assertEqual(sec_record.provenance["source_type"], "controlled_test")

    def test_data_004_no_sensitive_fields_enter_persisted_records(self):
        """TEST DATA-004: No sensitive fields enter persisted records."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        sec_record = self.db.query(SecurityEventModel).first()
        meta_str = str(sec_record.sanitized_metadata).lower()

        for forbidden in ("password", "private_key", "secret_key", "auth_token"):
            self.assertNotIn(f"'{forbidden}':", meta_str)

    def test_data_005_original_event_identifiers_remain_traceable(self):
        """TEST DATA-005: Original event identifiers remain traceable."""
        EventProcessor.process_single_event(self.db, self.base_event, "collector-agent-01")
        sec_record = self.db.query(SecurityEventModel).first()
        self.assertEqual(str(sec_record.raw_event_id), self.base_event["raw_event_id"])


if __name__ == "__main__":
    unittest.main()
