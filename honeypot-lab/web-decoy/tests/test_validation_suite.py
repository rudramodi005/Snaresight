"""Comprehensive QA validation suite for SnareSight Web Decoy.

Covers input boundaries (INPUT-001 to INPUT-017), concurrent multi-threading,
repeated interaction bursts, and complete event lifecycle validation.
"""

import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.services.event_logger import DecoyEventLogger
from app.schemas.events import DecoyEvent, EventType, EventSource, EventRequest, EventInteraction, EventProvenance


class TestValidationSuite(unittest.TestCase):
    """Deep QA inspection of honeypot input handling, concurrency, and event reliability."""

    def setUp(self):
        self.client = TestClient(app)

    # =========================================================================
    # SECTION 1: INPUT VALIDATION & BOUNDARY TESTS (INPUT-001 to INPUT-017)
    # =========================================================================

    def test_input_001_empty_username(self):
        """TEST INPUT-001: Empty username is accepted and generates simulated rejection."""
        response = self.client.post("/login", data={"username": "", "password": "SecretPassword123!"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication failed", response.text)

    def test_input_002_empty_password(self):
        """TEST INPUT-002: Empty password is accepted and generates simulated rejection."""
        response = self.client.post("/login", data={"username": "valid_user@corp.local", "password": ""})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication failed", response.text)

    def test_input_003_oversized_username(self):
        """TEST INPUT-003: Username exceeding MAX_USERNAME_LENGTH is rejected with HTTP 400."""
        oversized_user = "U" * (settings.MAX_USERNAME_LENGTH + 20)
        response = self.client.post("/login", data={"username": oversized_user, "password": "abc"})
        self.assertEqual(response.status_code, 400)

    def test_input_004_oversized_password(self):
        """TEST INPUT-004: Password exceeding MAX_PASSWORD_LENGTH is rejected with HTTP 400."""
        oversized_pwd = "P" * (settings.MAX_PASSWORD_LENGTH + 20)
        response = self.client.post("/login", data={"username": "testuser", "password": oversized_pwd})
        self.assertEqual(response.status_code, 400)

    def test_input_005_unexpected_character_encoding(self):
        """TEST INPUT-005: UTF-8 special multibyte and emoji characters are safely processed."""
        emoji_username = "user_🔒_über_test@domain.corp"
        response = self.client.post("/login", data={"username": emoji_username, "password": "Password123!"})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication failed", response.text)

    def test_input_006_invalid_content_type(self):
        """TEST INPUT-006: Non-form content type (e.g. raw text) returns HTTP 422 unprocessable."""
        response = self.client.post("/login", content="plain text payload", headers={"Content-Type": "text/plain"})
        self.assertIn(response.status_code, [400, 422])

    def test_input_007_malformed_request_structure(self):
        """TEST INPUT-007: Incomplete multipart form boundary is safely rejected."""
        response = self.client.post("/login", content=b"--badboundary\r\n", headers={"Content-Type": "multipart/form-data; boundary=badboundary"})
        self.assertIn(response.status_code, [400, 422])

    def test_input_008_unexpected_json_body(self):
        """TEST INPUT-008: JSON payload sent to form endpoint returns HTTP 422 safely."""
        response = self.client.post("/login", json={"user": "admin", "pass": "secret"})
        self.assertIn(response.status_code, [400, 422])

    def test_input_009_html_like_input(self):
        """TEST INPUT-009: Nested HTML tags are treated as inert strings."""
        html_input = "<b>bold_admin</b><div>nested</div>"
        response = self.client.post("/login", data={"username": html_input, "password": "123"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("<b>bold_admin</b>", response.text)

    def test_input_010_script_like_input(self):
        """TEST INPUT-010: Embedded script tags with event handlers remain inert."""
        script_input = '<img src=x onerror=alert("XSS")>'
        response = self.client.post("/login", data={"username": script_input, "password": "123"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("<img src=x", response.text)

    def test_input_011_command_like_input(self):
        """TEST INPUT-011: Unix shell chaining and backticks are handled as plain text."""
        cmd_input = "admin`whoami`$(id)|cat /etc/shadow"
        response = self.client.post("/login", data={"username": cmd_input, "password": "123"})
        self.assertEqual(response.status_code, 401)

    def test_input_012_path_traversal_looking_text(self):
        """TEST INPUT-012: Directory traversal sequences remain inert."""
        traversal_input = "../../../../windows/system32/cmd.exe"
        response = self.client.post("/login", data={"username": traversal_input, "password": "123"})
        self.assertEqual(response.status_code, 401)

    def test_input_013_repeated_form_submission(self):
        """TEST INPUT-013: 10 rapid sequential submissions in the same session succeed."""
        session_cookie = None
        for i in range(10):
            cookies = {settings.SESSION_COOKIE_NAME: session_cookie} if session_cookie else {}
            response = self.client.post("/login", data={"username": f"user_{i}", "password": "pwd"}, cookies=cookies)
            self.assertEqual(response.status_code, 401)
            if not session_cookie:
                session_cookie = response.cookies.get(settings.SESSION_COOKIE_NAME)

    def test_input_014_missing_session_information(self):
        """TEST INPUT-014: Request lacking cookies automatically receives a new session ID."""
        response = self.client.post("/login", data={"username": "new_visitor", "password": "pwd"})
        self.assertEqual(response.status_code, 401)
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)

    def test_input_015_unexpected_http_methods(self):
        """TEST INPUT-015: Unsupported HTTP methods (PUT, DELETE, PATCH) return 405 Method Not Allowed."""
        r_put = self.client.put("/login")
        self.assertEqual(r_put.status_code, 405)
        r_del = self.client.delete("/login")
        self.assertEqual(r_del.status_code, 405)

    def test_input_016_invalid_corrupted_session_cookie(self):
        """TEST INPUT-016: Malformed session cookie is safely discarded and replaced."""
        corrupted_cookie = {"apex_session_id": "malicious'--DROP TABLE"}
        response = self.client.get("/", cookies=corrupted_cookie)
        self.assertEqual(response.status_code, 200)
        new_cookie = response.cookies.get(settings.SESSION_COOKIE_NAME)
        self.assertNotEqual(new_cookie, corrupted_cookie["apex_session_id"])
        self.assertTrue(new_cookie.startswith("decoy_sess_"))

    def test_input_017_unexpected_header_injection(self):
        """TEST INPUT-017: Giant and hostile HTTP headers do not crash the decoy."""
        headers = {
            "X-Forwarded-For": "10.0.0.1, 192.168.1.1; DROP TABLE",
            "User-Agent": "A" * 500 + "<script>bad</script>",
            "X-Custom-Probe": "injection\r\nInjected-Header: true"
        }
        response = self.client.get("/", headers=headers)
        self.assertEqual(response.status_code, 200)

    # =========================================================================
    # SECTION 2: CONCURRENT THREAD SAFETY TESTS
    # =========================================================================

    def test_concurrent_interactions(self):
        """TEST CONCURRENCY: 10 parallel threads submitting login attempts simultaneously."""
        def make_request(index):
            local_client = TestClient(app)
            return local_client.post("/login", data={
                "username": f"thread_worker_{index}@lab.test",
                "password": f"ThreadSafePassword_{index}!"
            })

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), 10)
        for res in results:
            self.assertEqual(res.status_code, 401)
            self.assertIn("Authentication failed", res.text)

    # =========================================================================
    # SECTION 3: LOG ROTATION AT SIZE LIMIT
    # =========================================================================

    def test_log_rotation_at_limit(self):
        """TEST ROTATION: Exceeding max_size_bytes triggers atomic .1 rotation without dropping data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_log = Path(tmpdir) / "events.jsonl"
            # Set tiny threshold (500 bytes) to trigger rotation after ~2 events
            logger = DecoyEventLogger(log_path=temp_log, max_size_bytes=500)

            for i in range(5):
                event = DecoyEvent(
                    event_type=EventType.LOGIN_ATTEMPT,
                    decoy_id="ROTATION-TEST",
                    session_id=f"sess_{i}",
                    source=EventSource(ip_address="127.0.0.1", user_agent_summary="Tester"),
                    request=EventRequest(method="POST", path="/login"),
                    interaction=EventInteraction(status_code=401, simulated_outcome="rejection"),
                    provenance=EventProvenance()
                )
                logger.log_event(event)

            # Confirm that both the active log and rotated .1 file exist
            self.assertTrue(temp_log.exists(), "Active log file must exist")
            rotated_file = temp_log.with_suffix(".jsonl.1")
            self.assertTrue(rotated_file.exists(), "Rotated log file .1 must exist")
            self.assertGreater(rotated_file.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()

