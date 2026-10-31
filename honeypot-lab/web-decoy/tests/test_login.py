"""Tests for web decoy login interface and simulated authentication behaviors."""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings


class TestLoginInterface(unittest.TestCase):
    """Verifies login page rendering, form processing, and simulated responses."""

    def setUp(self):
        self.client = TestClient(app)

    def test_01_login_page_renders_successfully(self):
        """TEST 01: Login page loads with HTTP 200 and expected portal branding."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ApexCore Global Access", response.text)
        self.assertIn('name="username"', response.text)
        self.assertIn('name="password"', response.text)
        # Verify session cookie was set
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)

    def test_02_empty_form_submission_handled(self):
        """TEST 02: Empty form submission returns simulated rejection."""
        response = self.client.post("/login", data={"username": "", "password": ""})
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication failed", response.text)

    def test_03_valid_form_data_produces_simulated_rejection(self):
        """TEST 03: Typical login attempt returns realistic simulated authentication rejection."""
        response = self.client.post("/login", data={
            "username": "corp_admin@apexcore.local",
            "password": "CorporateSummerPassword2026!"
        })
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authentication failed", response.text)
        self.assertIn("AC-4019", response.text)

    def test_10_invalid_route_probing_returns_404(self):
        """TEST 10: Suspicious URL probing returns generic 404 without leaking server details."""
        response = self.client.get("/wp-login.php")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Resource not found", response.text)

    def test_11_oversized_payload_rejected(self):
        """TEST 11: Oversized credential fields exceeding max length are safely rejected."""
        giant_username = "A" * (settings.MAX_USERNAME_LENGTH + 50)
        response = self.client.post("/login", data={"username": giant_username, "password": "123"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

