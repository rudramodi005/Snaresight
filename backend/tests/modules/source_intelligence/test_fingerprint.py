"""Unit tests for IP canonicalization, fingerprinting, and source profile labelling."""

import unittest
from app.modules.source_intelligence.fingerprint import (
    canonicalize_ip,
    generate_source_fingerprint,
    generate_profile_id,
    format_source_display_label,
)


class TestSourceFingerprint(unittest.TestCase):
    """Verifies safe canonicalization and deterministic fingerprinting."""

    def test_ipv4_canonicalization(self):
        canonical, family, is_private = canonicalize_ip("192.168.1.100")
        self.assertEqual(canonical, "192.168.1.100")
        self.assertEqual(family, "IPv4")
        self.assertTrue(is_private)

        canonical_pub, family_pub, is_priv_pub = canonicalize_ip("8.8.8.8")
        self.assertEqual(canonical_pub, "8.8.8.8")
        self.assertEqual(family_pub, "IPv4")
        self.assertFalse(is_priv_pub)

    def test_ipv6_canonicalization(self):
        canonical, family, is_private = canonicalize_ip("2607:f8b0:4005:0805:0000:0000:0000:200e")
        self.assertEqual(canonical, "2607:f8b0:4005:805::200e")
        self.assertEqual(family, "IPv6")
        self.assertFalse(is_private)

    def test_loopback_and_whitespace(self):
        canonical, family, is_private = canonicalize_ip("  127.0.0.1  ")
        self.assertEqual(canonical, "127.0.0.1")
        self.assertTrue(is_private)

    def test_deterministic_fingerprint(self):
        fp1 = generate_source_fingerprint("198.51.100.1")
        fp2 = generate_source_fingerprint("198.51.100.1")
        fp3 = generate_source_fingerprint("198.51.100.2")

        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)
        self.assertEqual(len(fp1), 64)

    def test_profile_id_format(self):
        pid = generate_profile_id("198.51.100.55")
        self.assertTrue(pid.startswith("PROF-"))
        self.assertEqual(len(pid), 21)

    def test_display_label_policy_enforcement(self):
        label = format_source_display_label("203.0.113.10")
        self.assertEqual(label, "Observed Source Profile: 203.0.113.10")
        self.assertNotIn("Attacker", label)
        self.assertNotIn("Hacker", label)
        self.assertNotIn("Confirmed", label)
