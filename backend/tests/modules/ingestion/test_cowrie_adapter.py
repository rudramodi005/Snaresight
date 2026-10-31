"""Unit tests for Cowrie SSH decoy telemetry adapter."""

import unittest
from app.ingestion.adapters.cowrie import CowrieDecoyAdapter


class TestCowrieDecoyAdapter(unittest.TestCase):
    """Verifies that Cowrie SSH/Telnet logs are properly adapted to canonical Raw Events."""

    def setUp(self) -> None:
        self.adapter = CowrieDecoyAdapter()

    def test_source_prefix(self) -> None:
        self.assertEqual(self.adapter.source_prefix, "COWRIE")

    def test_parse_login_attempt(self) -> None:
        raw_log = {
            "eventid": "cowrie.login.failed",
            "session": "sess_ssh_982341",
            "timestamp": "2026-11-01T01:00:00.000Z",
            "src_ip": "198.51.100.42",
            "src_port": 54321,
            "dst_port": 2222,
            "username": "admin",
            "password": "SuperSecretPassword123",
        }

        parsed = self.adapter.parse_event(raw_log)
        self.assertEqual(parsed["decoy_id"], "COWRIE-SSH-01")
        self.assertEqual(parsed["session_id"], "sess_ssh_982341")
        self.assertEqual(parsed["event_type"], "cowrie.login.failed")
        self.assertEqual(parsed["source"]["ip_address"], "198.51.100.42")
        self.assertEqual(parsed["source"]["protocol"], "ssh")
        self.assertEqual(parsed["interaction"]["username_attempted"], "admin")
        self.assertTrue(parsed["interaction"]["password_present"])
        # Ensure raw password string is NOT preserved in top-level interaction dict
        self.assertNotIn("password", parsed["interaction"])

    def test_parse_command_execution(self) -> None:
        raw_log = {
            "eventid": "cowrie.command.input",
            "session": "sess_ssh_982341",
            "timestamp": "2026-11-01T01:01:00.000Z",
            "src_ip": "198.51.100.42",
            "input": "uname -a && cat /etc/passwd",
        }

        parsed = self.adapter.parse_event(raw_log)
        self.assertEqual(parsed["event_type"], "cowrie.command.input")
        self.assertEqual(parsed["interaction"]["command"], "uname -a && cat /etc/passwd")


if __name__ == "__main__":
    unittest.main()
