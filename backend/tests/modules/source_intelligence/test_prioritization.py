"""Unit tests for explainable profile prioritization."""

import unittest
from app.modules.source_intelligence.prioritization import evaluate_profile_priority


class TestProfilePrioritization(unittest.TestCase):
    """Verifies deterministic, transparent profile prioritization logic."""

    def test_insufficient_data(self):
        prio, rationale = evaluate_profile_priority(
            total_events=1, total_sessions=1, total_alerts=0, distinct_honeypots=1, features={}
        )
        self.assertEqual(prio, "INSUFFICIENT_DATA")
        self.assertIn("sparse", rationale)

        prio0, _ = evaluate_profile_priority(
            total_events=5, total_sessions=0, total_alerts=0, distinct_honeypots=0, features={}
        )
        self.assertEqual(prio0, "INSUFFICIENT_DATA")

    def test_critical_due_to_critical_alert(self):
        prio, rationale = evaluate_profile_priority(
            total_events=10,
            total_sessions=2,
            total_alerts=1,
            distinct_honeypots=1,
            features={"severity_breakdown": {"CRITICAL": 1}},
        )
        self.assertEqual(prio, "CRITICAL")
        self.assertIn("CRITICAL alert", rationale)

    def test_critical_due_to_multi_decoy_high_alerts(self):
        prio, rationale = evaluate_profile_priority(
            total_events=25,
            total_sessions=4,
            total_alerts=2,
            distinct_honeypots=3,
            features={"severity_breakdown": {"HIGH": 2}},
        )
        self.assertEqual(prio, "CRITICAL")
        self.assertIn("Multi-decoy targeting", rationale)

    def test_high_due_to_credential_spray(self):
        prio, rationale = evaluate_profile_priority(
            total_events=30,
            total_sessions=2,
            total_alerts=0,
            distinct_honeypots=1,
            features={"auth_failure_count": 15, "distinct_usernames_count": 6},
        )
        self.assertEqual(prio, "HIGH")
        self.assertIn("Credential spraying", rationale)

    def test_high_due_to_traversal_probes(self):
        prio, rationale = evaluate_profile_priority(
            total_events=15,
            total_sessions=1,
            total_alerts=0,
            distinct_honeypots=1,
            features={"path_traversal_probes": 4},
        )
        self.assertEqual(prio, "HIGH")
        self.assertIn("path traversal", rationale)

    def test_medium_due_to_alerts_or_volume(self):
        prio, rationale = evaluate_profile_priority(
            total_events=25,
            total_sessions=3,
            total_alerts=1,
            distinct_honeypots=1,
            features={"severity_breakdown": {"LOW": 1}},
        )
        self.assertEqual(prio, "MEDIUM")

    def test_low_priority_benign(self):
        prio, rationale = evaluate_profile_priority(
            total_events=3,
            total_sessions=1,
            total_alerts=0,
            distinct_honeypots=1,
            features={},
        )
        self.assertEqual(prio, "LOW")
        self.assertIn("Low-volume interaction", rationale)

