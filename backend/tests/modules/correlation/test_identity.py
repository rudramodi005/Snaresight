"""Unit tests for SessionIdentityResolver (Task P21)."""

import unittest
from app.correlation.identity import SessionIdentityResolver, SessionIdentity
from app.correlation.schemas import CorrelationMethod


class TestSessionIdentityResolver(unittest.TestCase):
    """Verifies Levels 1 through 4 session identity resolution precedence and invariants."""

    def test_level_1_explicit_session_id(self):
        """Level 1: Explicit session identifier resolves to compound key."""
        event = {
            "event_id": "evt-101",
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.22",
            "source_port": 54321,
            "target_service": "SSH",
            "source_protocol": "TCP",
            "session_id": "sess_ssh_abc123",
            "metadata": {"connection_id": "conn-999"},
        }
        identity = SessionIdentityResolver.resolve_identity(event)
        self.assertEqual(identity.correlation_method, CorrelationMethod.EXPLICIT_SESSION_ID)
        self.assertEqual(identity.correlation_key, "SSH-001:SSH_DAEMON:sess_ssh_abc123")
        self.assertEqual(identity.explicit_session_id, "sess_ssh_abc123")
        self.assertTrue(identity.is_trustworthy)
        self.assertEqual(identity.decoy_id, "SSH-001")
        self.assertEqual(identity.source_address, "198.51.100.22")

    def test_level_1_ignores_generic_session_tokens(self):
        """Level 1 falls through if session token is a known generic dummy token."""
        for generic in ["none", "null", "undefined", "0", "-1", "UNKNOWN", ""]:
            event = {
                "event_id": "evt-102",
                "decoy_id": "SSH-001",
                "source_address": "198.51.100.22",
                "target_service": "SSH",
                "session_id": generic,
                "metadata": {"connection_id": "conn-abc"},
            }
            identity = SessionIdentityResolver.resolve_identity(event)
            # Should skip Level 1 and fall back to Level 2 (connection_id)
            self.assertEqual(
                identity.correlation_method,
                CorrelationMethod.EXPLICIT_CONNECTION_ID,
                f"Failed for generic session token: {generic}",
            )
            self.assertEqual(identity.correlation_key, "SSH-001:conn:conn-abc")

    def test_level_2_connection_id(self):
        """Level 2: Connection ID resolves to scoped connection key."""
        event = {
            "event_id": "evt-201",
            "decoy_id": "WEB-001",
            "source_address": "203.0.113.44",
            "source_port": 49200,
            "target_service": "HTTP",
            "session_id": None,
            "metadata": {"connection_id": "tcp-conn-5555"},
        }
        identity = SessionIdentityResolver.resolve_identity(event)
        self.assertEqual(identity.correlation_method, CorrelationMethod.EXPLICIT_CONNECTION_ID)
        self.assertEqual(identity.correlation_key, "WEB-001:conn:tcp-conn-5555")
        self.assertEqual(identity.connection_id, "tcp-conn-5555")
        self.assertTrue(identity.is_trustworthy)

    def test_level_3_contextual_fallback(self):
        """Level 3: Controlled Fallback Key uses compound tuple (IP + Decoy + Target Service)."""
        event = {
            "event_id": "evt-301",
            "decoy_id": "SSH-002",
            "source_address": "198.51.100.77",
            "source_port": 34567,
            "target_service": "SSH",
            "session_id": None,
            "metadata": {},
        }
        identity = SessionIdentityResolver.resolve_identity(event)
        self.assertEqual(identity.correlation_method, CorrelationMethod.CONTEXTUAL_FALLBACK)
        self.assertEqual(identity.correlation_key, "fallback:198.51.100.77:SSH-002:SSH")
        self.assertFalse(identity.is_trustworthy)

    def test_ip_alone_is_never_sufficient(self):
        """Security Invariant: Events from same IP to DIFFERENT decoys yield DIFFERENT keys."""
        event_a = {
            "event_id": "evt-302a",
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.77",
            "target_service": "SSH",
        }
        event_b = {
            "event_id": "evt-302b",
            "decoy_id": "WEB-001",
            "source_address": "198.51.100.77",
            "target_service": "HTTP",
        }
        id_a = SessionIdentityResolver.resolve_identity(event_a)
        id_b = SessionIdentityResolver.resolve_identity(event_b)
        self.assertNotEqual(id_a.correlation_key, id_b.correlation_key)
        self.assertIn("SSH-001", id_a.correlation_key)
        self.assertIn("WEB-001", id_b.correlation_key)

    def test_level_4_standalone_isolation(self):
        """Level 4: When source IP is unknown or 0.0.0.0 and no session IDs, isolate as standalone."""
        event = {
            "event_id": "evt-401",
            "decoy_id": "WEB-001",
            "source_address": "0.0.0.0",
            "target_service": "HTTP",
            "session_id": None,
            "metadata": {},
        }
        identity = SessionIdentityResolver.resolve_identity(event)
        self.assertEqual(identity.correlation_method, CorrelationMethod.STANDALONE)
        self.assertEqual(identity.correlation_key, "standalone:evt-401")
        self.assertFalse(identity.is_trustworthy)

    def test_credentials_never_used_in_correlation(self):
        """Security Invariant: Credentials or password fields must never be stored in identity."""
        event = {
            "event_id": "evt-501",
            "decoy_id": "SSH-001",
            "source_address": "198.51.100.99",
            "target_service": "SSH",
            "metadata": {"password": "SuperSecretPassword123!", "username": "admin"},
        }
        identity = SessionIdentityResolver.resolve_identity(event)
        self.assertNotIn("SuperSecretPassword123!", identity.correlation_key)
        self.assertNotIn("password", identity.correlation_key.lower())
        self.assertNotIn("SuperSecretPassword123!", identity.resolution_diagnostic)


if __name__ == "__main__":
    unittest.main()

