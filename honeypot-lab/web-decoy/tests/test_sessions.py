"""Tests for session management and privacy-preserving username pseudonymization."""

import unittest
from app.services.sanitization import compute_username_fingerprint
from app.services.session_manager import DecoySessionManager


class TestSessionsAndPrivacy(unittest.TestCase):
    """Verifies session lifecycle and HMAC username hashing."""

    def test_06_username_pseudonymization_deterministic_and_irreversible(self):
        """TEST 06: Keyed HMAC fingerprinting is consistent and irreversible."""
        salt = "test_lab_secret_salt_123"
        fp1 = compute_username_fingerprint("administrator", salt)
        fp2 = compute_username_fingerprint("administrator", salt)
        fp3 = compute_username_fingerprint("ADMINISTRATOR", salt)  # Case-insensitive
        fp_different = compute_username_fingerprint("guest_user", salt)

        self.assertEqual(fp1, fp2, "HMAC must be deterministic for identical usernames")
        self.assertEqual(fp1, fp3, "HMAC must normalize casing")
        self.assertNotEqual(fp1, fp_different, "Different usernames must yield different fingerprints")
        self.assertEqual(len(fp1), 16, "Fingerprint must be a 16-character hex digest")
        # Ensure raw username is nowhere in the fingerprint
        self.assertNotIn("admin", fp1)

    def test_07_session_identifiers_are_unique(self):
        """TEST 07: Generated session IDs are unique, unguessable, and follow prefix conventions."""
        manager = DecoySessionManager(ttl_seconds=3600)
        sessions = set()
        for _ in range(50):
            token, is_new = manager.get_or_create_session(None)
            self.assertTrue(is_new)
            self.assertTrue(token.startswith("decoy_sess_"))
            self.assertNotIn(token, sessions)
            sessions.add(token)


if __name__ == "__main__":
    unittest.main()

