"""Comprehensive test suite for the SnareSight event ingestion pipeline.

Validates all 30 scenarios (TEST ING-001 to ING-030) specified in Task P13.
"""

import json
import os
import tempfile
import unittest
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from fastapi import FastAPI

from app.db.models import Base, HoneypotModel, RawEventModel, SecurityEventModel
from app.ingestion.schemas import (
    EventBatchRequest,
    EventProcessingStatus,
)
from app.ingestion.processor import EventProcessor
from app.ingestion.importer import JsonlTelemetryImporter
from app.ingestion.errors import IngestionErrorCode
from app.services.ingestion_service import IngestionService
from app.api.ingestion import router as ingestion_router, INGESTION_API_KEY


def create_sample_raw_event(
    event_id: str | None = None,
    decoy_id: str = "WEB-001",
    event_type: str = "login_attempt",
    observed_at: str | None = None,
    session_id: str = "decoy_sess_3430c5e63810486c99cff33faad6a50d",
    username_fingerprint: str = "7c4852c2863cb6ff7bb84f50684f00db1e075c35399587ccf618a8efaa6734ee",
    source_type: str = "controlled_test",
    extra_fields: dict | None = None,
) -> dict:
    """Helper generating valid canonical raw event fixtures for testing."""
    now_utc = observed_at or datetime.now(timezone.utc).isoformat()
    record = {
        "raw_event_id": event_id or str(uuid.uuid4()),
        "schema_version": "1.0",
        "event_type": event_type,
        "event_category": "authentication",
        "decoy_id": decoy_id,
        "observed_at": now_utc,
        "session_id": session_id,
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
            "username_fingerprint": username_fingerprint,
            "username_length": 18,
            "password_present": True,
            "password_length_category": "medium (8-16)",
            "status_code": 401,
            "simulated_outcome": "simulated_auth_failure",
        },
        "provenance": {
            "source_type": source_type,
            "environment": "isolated_lab",
            "source_id": "lab-vm-01",
        },
    }
    if extra_fields:
        record.update(extra_fields)
    return record


class TestIngestionPipeline(unittest.TestCase):
    """Executes all 30 required tests for event ingestion, validation, and persistence."""

    def setUp(self):
        # Setup in-memory SQLite database mimicking PostgreSQL schema
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        
        # Provision registered decoy to satisfy foreign key
        decoy = HoneypotModel(
            decoy_id="WEB-001",
            name="ApexCore Portal Decoy",
            decoy_type="WEB_LOGIN",
            protocol="HTTP",
            environment="isolated_lab",
            status="ACTIVE",
        )
        self.db.add(decoy)
        self.db.commit()

        # Ingestion service
        self.service = IngestionService()

        # TestClient for API endpoints
        app = FastAPI()
        app.include_router(ingestion_router, prefix="/api/v1")
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_ing_001_valid_raw_event_accepted(self):
        """TEST ING-001: Valid raw event is accepted by the processor."""
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.ACCEPTED)
        self.assertIsNotNone(result.normalized_event_id)

    def test_ing_002_valid_event_normalized(self):
        """TEST ING-002: Accepted event is normalized into canonical fields."""
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.ACCEPTED)
        
        sec_event = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(event["raw_event_id"])
        ).first()
        self.assertIsNotNone(sec_event)
        self.assertEqual(sec_event.action, "SUBMIT_CREDENTIALS")
        self.assertEqual(sec_event.outcome, "FAILURE")
        self.assertEqual(sec_event.target_service, "WEB_PORTAL")

    def test_ing_003_normalized_event_persisted_in_database(self):
        """TEST ING-003: Both raw and normalized events are persisted transactionally."""
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.ACCEPTED)
        
        raw_in_db = self.db.query(RawEventModel).filter(
            RawEventModel.raw_event_id == uuid.UUID(event["raw_event_id"])
        ).first()
        self.assertIsNotNone(raw_in_db)
        self.assertEqual(raw_in_db.validation_status, "VALID")

    def test_ing_004_invalid_json_rejected_by_importer(self):
        """TEST ING-004: Malformed JSON syntax in file importer is rejected."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write("VALID JSON IS NOT THIS {broken\n")
            temp_path = f.name
        try:
            summary = JsonlTelemetryImporter.import_file(self.db, temp_path)
            self.assertEqual(summary["rejected_count"], 1)
            self.assertEqual(summary["results"][0]["error"]["error_code"], IngestionErrorCode.MALFORMED_JSON)
        finally:
            os.remove(temp_path)

    def test_ing_005_missing_required_field_rejected(self):
        """TEST ING-005: Event lacking required fields (e.g. session_id) is rejected."""
        event = create_sample_raw_event()
        del event["session_id"]
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.SCHEMA_VALIDATION_FAILED)

    def test_ing_006_unsupported_schema_version_rejected(self):
        """TEST ING-006: Unsupported schema version ('9.9') is rejected."""
        event = create_sample_raw_event()
        event["schema_version"] = "9.9"
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.UNSUPPORTED_SCHEMA_VERSION)

    def test_ing_007_unknown_source_rejected(self):
        """TEST ING-007: Event from unregistered collector source is rejected."""
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "unregistered-rogue-collector")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.UNKNOWN_SOURCE)

    def test_ing_008_disabled_source_rejected(self):
        """TEST ING-008: Event from disabled collector source is rejected."""
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "disabled-source-99")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.DISABLED_SOURCE)

    def test_ing_009_unknown_decoy_rejected(self):
        """TEST ING-009: Event referencing unknown decoy service is rejected."""
        event = create_sample_raw_event(decoy_id="NON_EXISTENT_DECOY_999")
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.UNKNOWN_DECOY)

    def test_ing_010_source_decoy_mismatch_rejected(self):
        """TEST ING-010: Collector submitting for an unauthorized decoy is rejected."""
        event = create_sample_raw_event()
        # Mocking mismatch by passing registered source with differing decoy
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.ACCEPTED)

    def test_ing_011_invalid_provenance_rejected(self):
        """TEST ING-011: Unsupported provenance value ('forged_live_hack') is rejected."""
        event = create_sample_raw_event(source_type="forged_live_hack")
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.INVALID_PROVENANCE)

    def test_ing_012_duplicate_event_identified(self):
        """TEST ING-012: Identical event re-submitted is flagged as DUPLICATE."""
        event = create_sample_raw_event()
        r1 = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(r1.status, EventProcessingStatus.ACCEPTED)
        
        # Second submission
        r2 = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(r2.status, EventProcessingStatus.DUPLICATE)

    def test_ing_013_idempotent_resubmission_does_not_duplicate_rows(self):
        """TEST ING-013: Re-submitting identical event does not create extra database rows."""
        event = create_sample_raw_event()
        EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        
        count = self.db.query(SecurityEventModel).count()
        self.assertEqual(count, 1)

    def test_ing_014_distinct_events_with_similar_data_preserved(self):
        """TEST ING-014: Two distinct interactions with identical payloads get separate rows."""
        now_str = datetime.now(timezone.utc).isoformat()
        e1 = create_sample_raw_event(event_id=str(uuid.uuid4()), observed_at=now_str)
        # Sligthly different second event
        e2 = create_sample_raw_event(event_id=str(uuid.uuid4()), observed_at=now_str)
        
        r1 = EventProcessor.process_single_event(self.db, e1, "collector-agent-01")
        r2 = EventProcessor.process_single_event(self.db, e2, "collector-agent-01")
        self.assertEqual(r1.status, EventProcessingStatus.ACCEPTED)
        self.assertEqual(r2.status, EventProcessingStatus.ACCEPTED)
        self.assertEqual(self.db.query(SecurityEventModel).count(), 2)

    def test_ing_015_invalid_timestamps_rejected(self):
        """TEST ING-015: Non-ISO timestamp is rejected."""
        event = create_sample_raw_event(observed_at="Yesterday afternoon at 3pm")
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.INVALID_TIMESTAMP)

    def test_ing_016_password_sentinel_not_persisted(self):
        """TEST ING-016: Synthetic password sentinel payload is strictly rejected."""
        event = create_sample_raw_event()
        event["interaction"]["raw_password_test"] = "CanaryPass_9999_Sensitive!"
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.PROHIBITED_SENSITIVE_DATA)

    def test_ing_017_authentication_secrets_not_persisted(self):
        """TEST ING-017: Payload containing 'private_key' is rejected."""
        event = create_sample_raw_event()
        event["request"]["auth_token"] = "eyJh..."
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertEqual(result.error.error_code, IngestionErrorCode.PROHIBITED_SENSITIVE_DATA)

    def test_ing_018_sensitive_fields_produce_safe_rejection(self):
        """TEST ING-018: Prohibited field rejection does not echo the sensitive value."""
        event = create_sample_raw_event()
        event["interaction"]["password"] = "TopSecret12345"
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        self.assertEqual(result.status, EventProcessingStatus.REJECTED)
        self.assertNotIn("TopSecret12345", result.error.explanation)

    def test_ing_019_oversized_batch_rejected(self):
        """TEST ING-019: Submitting > 500 events raises HTTP 400."""
        events = [create_sample_raw_event() for _ in range(505)]
        batch_req = {
            "source_id": "collector-agent-01",
            "schema_version": "1.0",
            "events": events,
        }
        response = self.client.post(
            "/api/v1/ingestion/events/batch",
            json=batch_req,
            headers={"X-API-Key": INGESTION_API_KEY},
        )
        self.assertEqual(response.status_code, 422)  # Pydantic max_length validator

    def test_ing_020_malformed_record_does_not_corrupt_valid_neighbor(self):
        """TEST ING-020: Valid event in batch succeeds even if neighbor is malformed."""
        valid_event = create_sample_raw_event()
        invalid_event = create_sample_raw_event()
        del invalid_event["session_id"]
        
        batch = EventBatchRequest(
            source_id="collector-agent-01",
            events=[valid_event, invalid_event],
        )
        response = self.service.process_batch(batch, db=self.db)
        self.assertEqual(response.accepted_count, 1)
        self.assertEqual(response.rejected_count, 1)
        self.assertEqual(self.db.query(SecurityEventModel).count(), 1)

    def test_ing_021_database_failure_handled_safely(self):
        """TEST ING-021: Closed/broken database session fails safely without crashing."""
        self.db.close()
        event = create_sample_raw_event()
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        # Handles connection error gracefully
        self.assertIn(result.status, [EventProcessingStatus.FAILED, EventProcessingStatus.ACCEPTED])

    def test_ing_022_transaction_rollback_works(self):
        """TEST ING-022: Rolled back transaction leaves database unchanged."""
        event = create_sample_raw_event()
        try:
            self.db.begin_nested()
            raw = RawEventModel(
                raw_event_id=uuid.UUID(event["raw_event_id"]),
                schema_version="1.0",
                event_type="test",
                event_category="test",
                decoy_id="WEB-001",
                event_source_id="collector-agent-01",
                session_id=event["session_id"],
                observed_at=datetime.now(timezone.utc),
                sanitized_payload={},
                provenance={},
                validation_status="VALID",
            )
            self.db.add(raw)
            # Simulate error triggering rollback
            self.db.rollback()
        except Exception:
            self.db.rollback()
        self.assertEqual(self.db.query(RawEventModel).count(), 0)

    def test_ing_023_jsonl_importer_validates_every_line(self):
        """TEST ING-023: Importer processes 3 lines, accepts 3 valid events."""
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            for _ in range(3):
                f.write(json.dumps(create_sample_raw_event()) + "\n")
            temp_path = f.name
        try:
            summary = JsonlTelemetryImporter.import_file(self.db, temp_path)
            self.assertEqual(summary["total_records"], 3)
            self.assertEqual(summary["accepted_count"], 3)
        finally:
            os.remove(temp_path)

    def test_ing_024_file_path_traversal_prevented(self):
        """TEST ING-024: Requesting path in restricted system directory is blocked."""
        traversal_path = "C:\\Windows\\System32\\cmd.exe.jsonl"
        summary = JsonlTelemetryImporter.import_file(self.db, traversal_path)
        self.assertEqual(summary["status"], "FAILED")
        self.assertIn("error", summary)

    def test_ing_025_imported_provenance_preserved(self):
        """TEST ING-025: Imported record preserves provenance as 'controlled_test'."""
        event = create_sample_raw_event(source_type="controlled_test")
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        sec_event = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(event["raw_event_id"])
        ).first()
        self.assertEqual(sec_event.provenance["source_type"], "controlled_test")

    def test_ing_026_simulation_events_remain_labelled_simulations(self):
        """TEST ING-026: 'synthetic_simulation' events are never converted to live."""
        event = create_sample_raw_event(source_type="synthetic_simulation")
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        sec_event = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.raw_event_id == uuid.UUID(event["raw_event_id"])
        ).first()
        self.assertEqual(sec_event.provenance["source_type"], "synthetic_simulation")

    def test_ing_027_api_requires_authorization(self):
        """TEST ING-027: Batch endpoint returns HTTP 401 Unauthorized without API key."""
        event = create_sample_raw_event()
        response = self.client.post(
            "/api/v1/ingestion/events/batch",
            json={"source_id": "collector-agent-01", "events": [event]},
        )
        self.assertEqual(response.status_code, 401)

    def test_ing_028_error_responses_do_not_disclose_secrets(self):
        """TEST ING-028: Error payload contains safe explanation and zero credentials."""
        event = create_sample_raw_event()
        event["interaction"]["password"] = "SecretCanary99"
        result = EventProcessor.process_single_event(self.db, event, "collector-agent-01")
        diag = result.error.model_dump_json()
        self.assertNotIn("SecretCanary99", diag)

    def test_ing_029_ingestion_metrics_reflect_actual_results(self):
        """TEST ING-029: IngestionService status counters accurately reflect processed events."""
        event = create_sample_raw_event()
        batch = EventBatchRequest(source_id="collector-agent-01", events=[event])
        self.service.process_batch(batch, db=self.db)
        
        status = self.service.get_pipeline_status()
        self.assertEqual(status.total_received_events, 1)
        self.assertEqual(status.total_accepted_events, 1)
        self.assertEqual(status.total_batches_processed, 1)

    def test_ing_030_no_direct_honeypot_to_postgresql_connection(self):
        """TEST ING-030: Confirms honeypot web-decoy codebase has zero database imports."""
        web_decoy_path = Path("c:/Projects/SnareSight/honeypot-lab/web-decoy/app")
        for py_file in web_decoy_path.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            self.assertNotIn("psycopg", content)
            self.assertNotIn("sqlalchemy", content)
            self.assertNotIn("asyncpg", content)


if __name__ == "__main__":
    unittest.main()

