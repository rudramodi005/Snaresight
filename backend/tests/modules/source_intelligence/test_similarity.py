"""Unit tests for behavioral profile similarity analysis."""

import unittest
from types import SimpleNamespace
from app.modules.source_intelligence.similarity import compare_source_profiles


class TestProfileSimilarity(unittest.TestCase):
    """Verifies multi-dimensional behavioral similarity comparisons."""

    def test_identical_profiles(self):
        p1 = SimpleNamespace(
            profile_id="PROF-001",
            display_label="Observed Source Profile: 198.51.100.1",
            source_ip="198.51.100.1",
            behavioral_summary={"honeypots": ["SSH-001", "WEB-001"]},
            protocol_distribution={"SSH": 10, "HTTP": 5},
            profile_priority="HIGH",
            profile_status="ACTIVE",
        )
        f1 = {
            "technique_distribution": {"T1110": 8, "T1059": 2},
            "interaction_tempo": 4.5,
            "auth_failure_count": 10,
        }

        p2 = SimpleNamespace(
            profile_id="PROF-002",
            display_label="Observed Source Profile: 198.51.100.2",
            source_ip="198.51.100.2",
            behavioral_summary={"honeypots": ["SSH-001", "WEB-001"]},
            protocol_distribution={"SSH": 10, "HTTP": 5},
            profile_priority="HIGH",
            profile_status="ACTIVE",
        )
        f2 = {
            "technique_distribution": {"T1110": 8, "T1059": 2},
            "interaction_tempo": 4.5,
            "auth_failure_count": 10,
        }

        res = compare_source_profiles(p1, f1, p2, f2)
        self.assertAlmostEqual(res.similarity_score, 100.0, places=1)
        self.assertEqual(len(res.contributing_factors), 4)
        self.assertEqual(len(res.common_techniques), 2)
        self.assertEqual(len(res.common_honeypots), 2)

    def test_orthogonal_profiles(self):
        p1 = SimpleNamespace(
            profile_id="PROF-001",
            display_label="Observed Source Profile: 198.51.100.1",
            source_ip="198.51.100.1",
            behavioral_summary={"honeypots": ["SSH-001"]},
            protocol_distribution={"SSH": 20},
            profile_priority="HIGH",
            profile_status="ACTIVE",
        )
        f1 = {
            "technique_distribution": {"T1110": 15},
            "interaction_tempo": 12.0,
            "auth_failure_count": 20,
        }

        p2 = SimpleNamespace(
            profile_id="PROF-003",
            display_label="Observed Source Profile: 198.51.100.3",
            source_ip="198.51.100.3",
            behavioral_summary={"honeypots": ["SMB-001"]},
            protocol_distribution={"SMB": 3},
            profile_priority="LOW",
            profile_status="DORMANT",
        )
        f2 = {
            "technique_distribution": {"T1021.002": 1},
            "interaction_tempo": 0.2,
            "auth_failure_count": 0,
        }

        res = compare_source_profiles(p1, f1, p2, f2)
        self.assertLess(res.similarity_score, 20.0)
        self.assertEqual(len(res.common_techniques), 0)
        self.assertEqual(len(res.common_honeypots), 0)

