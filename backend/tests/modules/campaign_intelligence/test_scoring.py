"""Unit tests for RelationshipScorer (Task P24)."""

import unittest
from app.modules.campaign_intelligence.scoring import RelationshipScorer


class TestRelationshipScorer(unittest.TestCase):
    """Verifies transparent relationship scoring, signal weighting, and contradiction handling."""

    def test_strong_relationship_with_shared_sequence(self):
        res = RelationshipScorer.evaluate_relationship(
            shared_sequences=2,
            source_similarity=85.0,
            shared_decoys=2,
            shared_techniques=2,
            temporal_gap_hours=12.0,
        )
        self.assertGreaterEqual(res["score"], 80)
        self.assertEqual(res["interpretation"], "STRONG_INVESTIGATION_RELATIONSHIP")
        self.assertTrue(res["is_above_threshold"])
        self.assertEqual(len(res["contributing_signals"]), 4)
        self.assertEqual(len(res["contradicting_signals"]), 0)

    def test_moderate_relationship(self):
        res = RelationshipScorer.evaluate_relationship(
            shared_sequences=1,
            source_similarity=50.0,
            shared_decoys=1,
            shared_techniques=1,
            temporal_gap_hours=24.0,
        )
        self.assertGreaterEqual(res["score"], 50)
        self.assertIn("RELATIONSHIP", res["interpretation"])

    def test_contradicting_tempo_disparity_penalty(self):
        # High base score, but severe velocity gap (100x tempo difference)
        res = RelationshipScorer.evaluate_relationship(
            shared_sequences=1,
            source_similarity=80.0,
            shared_decoys=1,
            shared_techniques=1,
            temporal_gap_hours=6.0,
            tempo_ratio=15.0,  # Penalty applies
        )
        self.assertEqual(len(res["contradicting_signals"]), 1)
        self.assertEqual(res["contradicting_signals"][0]["signal"], "CONTRADICTORY_TEMPO_DISPARITY")
        self.assertEqual(res["contradicting_signals"][0]["penalty"], -20.0)

    def test_disparate_protocol_penalty(self):
        res = RelationshipScorer.evaluate_relationship(
            shared_sequences=0,
            source_similarity=0.0,
            shared_decoys=0,
            shared_techniques=0,
            temporal_gap_hours=5.0,
            differing_protocols=True,
        )
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["interpretation"], "INSUFFICIENT_EVIDENCE_FOR_GROUPING")
        self.assertFalse(res["is_above_threshold"])

    def test_missing_signals_tracked(self):
        res = RelationshipScorer.evaluate_relationship(
            shared_sequences=0,
            source_similarity=75.0,
            shared_decoys=1,
            shared_techniques=0,
        )
        self.assertIn("SHARED_BEHAVIORAL_SEQUENCE", res["missing_signals"])
        self.assertIn("SHARED_MITRE_TECHNIQUES", res["missing_signals"])

