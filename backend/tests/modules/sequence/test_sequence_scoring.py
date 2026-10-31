"""Unit tests for SequenceScorer (Task P22)."""

import unittest
from app.modules.correlation.sequence_scoring import SequenceScorer
from app.modules.correlation.sequence_schemas import SequencePatternType


class TestSequenceScoring(unittest.TestCase):
    """Verifies separate confidence and relevance scoring, factor explanations, and bounds."""

    def test_baseline_scoring(self):
        """Baseline sequence yields valid bounded scores."""
        sessions = [{"session_id": "s1"}, {"session_id": "s2"}]
        conf, rel, agg_sev, expl = SequenceScorer.compute_scores(
            sessions=sessions,
            detections=[],
            mappings=[],
            pattern=SequencePatternType.REPEATED_AUTHENTICATION,
            has_shared_source_context=False,
        )
        self.assertGreaterEqual(conf, 10)
        self.assertLessEqual(conf, 100)
        self.assertGreaterEqual(rel, 10)
        self.assertLessEqual(rel, 100)
        self.assertEqual(agg_sev, "INFO")
        self.assertIn("confidence_factors", expl)
        self.assertIn("relevance_factors", expl)

    def test_shared_source_context_boosts_confidence(self):
        """Corroborated source context increases correlation confidence."""
        sessions = [{"session_id": "s1"}, {"session_id": "s2"}]
        conf_no_ctx, _, _, _ = SequenceScorer.compute_scores(
            sessions=sessions,
            detections=[],
            mappings=[],
            pattern=SequencePatternType.REPEATED_AUTHENTICATION,
            has_shared_source_context=False,
        )
        conf_with_ctx, _, _, expl = SequenceScorer.compute_scores(
            sessions=sessions,
            detections=[],
            mappings=[],
            pattern=SequencePatternType.REPEATED_AUTHENTICATION,
            has_shared_source_context=True,
        )
        self.assertGreater(conf_with_ctx, conf_no_ctx)
        self.assertTrue(any("Shared source address" in f for f in expl["confidence_factors"]))

    def test_critical_detection_elevates_relevance_and_severity(self):
        """Presence of CRITICAL detection sets aggregate severity to CRITICAL and adds +40 relevance."""
        sessions = [{"session_id": "s1"}, {"session_id": "s2"}]
        detections = [{"detection_rule_id": "WEB-002", "severity": "CRITICAL"}]
        conf, rel, agg_sev, expl = SequenceScorer.compute_scores(
            sessions=sessions,
            detections=detections,
            mappings=[],
            pattern=SequencePatternType.ENUMERATION_THEN_EXPLOIT,
        )
        self.assertEqual(agg_sev, "CRITICAL")
        self.assertGreaterEqual(rel, 70)
        self.assertTrue(any("CRITICAL" in f for f in expl["relevance_factors"]))

    def test_att_and_ck_mappings_add_confidence(self):
        """Evidence-backed ATT&CK technique mappings add +10 confidence factor."""
        sessions = [{"session_id": "s1"}, {"session_id": "s2"}]
        mappings = [{"technique_id": "T1110"}]
        conf, _, _, expl = SequenceScorer.compute_scores(
            sessions=sessions,
            detections=[],
            mappings=mappings,
            pattern=SequencePatternType.MULTI_TECHNIQUE_PROGRESSION,
        )
        self.assertTrue(any("ATT&CK mappings" in f for f in expl["confidence_factors"]))

    def test_disclaimer_always_present(self):
        """Score explanation always contains attribution disclaimer."""
        _, _, _, expl = SequenceScorer.compute_scores(
            sessions=[{"session_id": "s1"}, {"session_id": "s2"}],
            detections=[],
            mappings=[],
            pattern=SequencePatternType.REPEATED_AUTHENTICATION,
        )
        self.assertIn("disclaimer", expl)
        self.assertIn("human identity attribution", expl["disclaimer"])


if __name__ == "__main__":
    unittest.main()

