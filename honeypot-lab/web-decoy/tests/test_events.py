"""Tests for honeypot event collection, JSONL logging, and password exclusion."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.services.event_logger import DecoyEventLogger
from app.schemas.events import DecoyEvent, EventType, EventSource, EventRequest, EventInteraction, EventProvenance


class TestEventLogging(unittest.TestCase):
    """Verifies structured JSONL serialization and sensitive data exclusion."""

    def setUp(self):
        self.client = TestClient(app)

    def test_04_password_never_persisted_in_jsonl(self):
        """TEST 04: Highly sensitive canary password is NEVER written to the log file."""
        canary_password = "SUPER_SECRET_CANARY_STRING_DO_NOT_LOG_998877"
        self.client.post("/login", data={
            "username": "investigation_target",
            "password": canary_password
        })

        # Inspect the log file directly
        log_path = Path("data/events.jsonl")
        if log_path.exists():
            content = log_path.read_text(encoding="utf-8")
            self.assertNotIn(canary_password, content, "SECURITY VIOLATION: Canary password was logged!")

    def test_05_password_not_in_error_or_response_output(self):
        """TEST 05: Password is never echoed in HTML response, error messages, or headers."""
        canary_password = "ANOTHER_CANARY_PASSWORD_112233"
        response = self.client.post("/login", data={
            "username": "victim_user",
            "password": canary_password
        })
        self.assertNotIn(canary_password, response.text)
        self.assertNotIn(canary_password, str(response.headers))

    def test_08_events_contain_all_schema_fields(self):
        """TEST 08: Generated events strictly conform to the canonical DecoyEvent schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_log = Path(tmpdir) / "test_events.jsonl"
            logger = DecoyEventLogger(log_path=temp_log)

            event = DecoyEvent(
                event_type=EventType.LOGIN_ATTEMPT,
                decoy_id="TEST-DECOY-01",
                session_id="decoy_sess_12345",
                source=EventSource(ip_address="127.0.0.1", user_agent_summary="TestRunner/1.0"),
                request=EventRequest(method="POST", path="/login"),
                interaction=EventInteraction(
                    username_fingerprint="abc1234567890def",
                    username_length=11,
                    password_present=True,
                    password_length_category="medium (8-16)",
                    status_code=401,
                    simulated_outcome="auth_rejected"
                ),
                provenance=EventProvenance(source_type="controlled_simulation", environment="isolated_lab")
            )
            success = logger.log_event(event)
            self.assertTrue(success)

            # Read back line and validate JSON fields
            with open(temp_log, "r", encoding="utf-8") as f:
                line = f.readline()
                data = json.loads(line)

            expected_fields = [
                "schema_version", "event_id", "event_type", "observed_at",
                "decoy_id", "session_id", "source", "request", "interaction", "provenance"
            ]
            for field in expected_fields:
                self.assertIn(field, data)

    def test_09_timestamps_use_utc(self):
        """TEST 09: All timestamps are strictly UTC-formatted ISO-8601 strings."""
        event = DecoyEvent(
            event_type=EventType.DECOY_PAGE_VISITED,
            decoy_id="TEST-01",
            session_id="sess_01",
            source=EventSource(ip_address="127.0.0.1", user_agent_summary="Agent"),
            request=EventRequest(method="GET", path="/"),
            interaction=EventInteraction(status_code=200, simulated_outcome="view"),
            provenance=EventProvenance()
        )
        self.assertTrue(
            event.observed_at.endswith("+00:00") or event.observed_at.endswith("Z"),
            f"Timestamp {event.observed_at} is not strict UTC!"
        )

    def test_16_event_log_write_failure_handled_gracefully(self):
        """TEST 16: File write errors do not crash the application."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_log = Path(tmpdir) / "test_events.jsonl"
            logger = DecoyEventLogger(log_path=temp_log)
            event = DecoyEvent(
                event_type=EventType.DECOY_PAGE_VISITED,
                decoy_id="TEST-01",
                session_id="sess_01",
                source=EventSource(ip_address="127.0.0.1", user_agent_summary="Agent"),
                request=EventRequest(method="GET", path="/"),
                interaction=EventInteraction(status_code=200, simulated_outcome="view"),
                provenance=EventProvenance()
            )
            with patch("builtins.open", side_effect=PermissionError("Mock disk write failure")):
                result = logger.log_event(event)
                self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
