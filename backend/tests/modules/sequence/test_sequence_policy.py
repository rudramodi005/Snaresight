"""Unit tests for CrossSessionCorrelationPolicy and Behavioral Patterns (Task P22)."""

import unittest
from datetime import datetime, timezone, timedelta
from app.modules.correlation.sequence_policy import CrossSessionCorrelationPolicy
from app.modules.correlation.sequence_schemas import SequencePatternType


class TestSequencePolicy(unittest.TestCase):
    """Verifies temporal windows, pattern matchers, and false-positive boundaries."""

    def setUp(self):
        self.policy = CrossSessionCorrelationPolicy(
            policy_version="1.0",
            max_correlation_window_seconds=86400,
            max_sequence_span_seconds=604800,
            min_sessions=2,
        )
        self.t0 = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)

    def test_temporal_window_admissible(self):
        """Sessions occurring 4 hours apart are within the 24-hour correlation window."""
        t1 = self.t0 + timedelta(hours=4)
        is_valid, msg = self.policy.is_within_temporal_window(self.t0, t1)
        self.assertTrue(is_valid)
        self.assertIn("Within allowable", msg)

    def test_temporal_window_exceeded(self):
        """Sessions separated by 25 hours fail the correlation window check."""
        t_late = self.t0 + timedelta(hours=25)
        is_valid, msg = self.policy.is_within_temporal_window(self.t0, t_late)
        self.assertFalse(is_valid)
        self.assertIn("exceeds max correlation window", msg)

    def test_total_sequence_span_exceeded(self):
        """Total sequence span exceeding 7 days is rejected."""
        t_span = self.t0 + timedelta(days=8)
        is_valid, msg = self.policy.is_within_temporal_window(
            self.t0, self.t0 + timedelta(hours=1), sequence_start_time=self.t0 - timedelta(days=8)
        )
        self.assertFalse(is_valid)
        self.assertIn("exceeds max sequence span", msg)

    def test_pattern_multi_technique_progression(self):
        """Pattern 4: Progression across T1110 (Credential Access) and T1083 (Discovery)."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "decoy_id": "WEB-001"},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=1), "decoy_id": "WEB-001"},
        ]
        detections = [
            {"detection_rule_id": "AUTH-001", "severity": "MEDIUM"},
            {"detection_rule_id": "WEB-001", "severity": "HIGH"},
        ]
        mappings = [
            {"technique_id": "T1110"},
            {"technique_id": "T1083"},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections, mappings)
        self.assertIsNotNone(match)
        pattern, title, rationale = match
        self.assertEqual(pattern, SequencePatternType.MULTI_TECHNIQUE_PROGRESSION)
        self.assertIn("Multi-Stage ATT&CK Technique Progression", title)

    def test_pattern_enumeration_then_exploit(self):
        """Pattern 3: Enumeration rule (WEB-001) followed by exploit rule (WEB-002)."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "decoy_id": "WEB-001"},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=2), "decoy_id": "WEB-001"},
        ]
        detections = [
            {"detection_rule_id": "WEB-001", "severity": "HIGH"},
            {"detection_rule_id": "WEB-002", "severity": "CRITICAL"},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections, mappings=[])
        self.assertIsNotNone(match)
        pattern, title, _ = match
        self.assertEqual(pattern, SequencePatternType.ENUMERATION_THEN_EXPLOIT)

    def test_pattern_auth_then_enumeration(self):
        """Pattern 2: Auth rule (AUTH-001) followed by enumeration (AUTH-003)."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "decoy_id": "SSH-001"},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=1), "decoy_id": "SSH-001"},
        ]
        detections = [
            {"detection_rule_id": "AUTH-001", "severity": "MEDIUM"},
            {"detection_rule_id": "AUTH-003", "severity": "MEDIUM"},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections, mappings=[])
        self.assertIsNotNone(match)
        pattern, _, _ = match
        self.assertEqual(pattern, SequencePatternType.AUTH_THEN_ENUMERATION)

    def test_pattern_repeated_authentication(self):
        """Pattern 1: Multiple sessions exhibiting repeated authentication attempts."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "metadata_summary": {"initial_category": "authentication"}},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=1), "metadata_summary": {"initial_category": "authentication"}},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections=[], mappings=[])
        self.assertIsNotNone(match)
        pattern, _, _ = match
        self.assertEqual(pattern, SequencePatternType.REPEATED_AUTHENTICATION)

    def test_pattern_cross_protocol(self):
        """Pattern 6: Activity across distinct honeypot protocols with corroborated detections."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "honeypot_type": "SSH_DAEMON", "decoy_id": "SSH-001"},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=1), "honeypot_type": "WEB_LOGIN", "decoy_id": "WEB-001"},
        ]
        detections = [
            {"detection_rule_id": "RULE-A", "severity": "HIGH"},
            {"detection_rule_id": "RULE-B", "severity": "HIGH"},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections, mappings=[])
        self.assertIsNotNone(match)
        pattern, _, _ = match
        self.assertEqual(pattern, SequencePatternType.CROSS_PROTOCOL_INTERACTION)

    def test_false_positive_guardrail_insufficient_sessions(self):
        """Single session never forms a multi-session sequence."""
        sessions = [{"session_id": "s1", "first_observed_at": self.t0}]
        match = self.policy.match_behavioral_pattern(sessions, detections=[], mappings=[])
        self.assertIsNone(match)

    def test_false_positive_guardrail_unrelated_traffic(self):
        """Unrelated requests without detections or patterns return None."""
        sessions = [
            {"session_id": "s1", "first_observed_at": self.t0, "decoy_id": "WEB-001", "metadata_summary": {"initial_category": "generic"}},
            {"session_id": "s2", "first_observed_at": self.t0 + timedelta(hours=1), "decoy_id": "WEB-002", "metadata_summary": {"initial_category": "generic"}},
        ]
        match = self.policy.match_behavioral_pattern(sessions, detections=[], mappings=[])
        self.assertIsNone(match)


if __name__ == "__main__":
    unittest.main()

