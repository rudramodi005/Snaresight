"""Unit tests for MITRE ATT&CK Mapping Confidence Engine (Task P20)."""

import unittest
from app.modules.mitre.mapping.confidence import MappingConfidenceEngine
from app.modules.mitre.mapping.schemas import (
    MappingCategory,
    MappingConfidenceLevel,
    MappingDefinitionSchema,
)


class TestMappingConfidence(unittest.TestCase):
    """Verifies that mapping confidence is explainable and independent of detection confidence."""

    def setUp(self):
        self.directly_supported_def = MappingDefinitionSchema(
            mapping_definition_id="MAP-TEST-001",
            rule_id="AUTH-001",
            technique_id="T1110",
            subtechnique_id="T1110.001",
            mapping_category=MappingCategory.DIRECTLY_SUPPORTED,
            default_confidence=85,
            required_evidence_fields=["event_category", "outcome"],
            mapping_rationale="Test rationale.",
            version="1.0",
        )

        self.analyst_review_def = MappingDefinitionSchema(
            mapping_definition_id="MAP-TEST-002",
            rule_id="AUTH-002",
            technique_id="T1078",
            subtechnique_id=None,
            mapping_category=MappingCategory.REQUIRES_ANALYST_REVIEW,
            default_confidence=45,
            required_evidence_fields=["event_category", "outcome"],
            mapping_rationale="Decoy simulation caveat.",
            version="1.0",
        )

        self.not_mapped_def = MappingDefinitionSchema(
            mapping_definition_id="MAP-TEST-003",
            rule_id="CMD-001",
            technique_id="T1082",
            subtechnique_id=None,
            mapping_category=MappingCategory.NOT_MAPPED,
            default_confidence=0,
            required_evidence_fields=[],
            mapping_rationale="Unmapped.",
            version="1.0",
        )

    def test_directly_supported_confidence_scoring(self):
        """CONF-01: Directly supported mapping with corroborating events receives HIGH confidence."""
        event = {"event_category": "authentication", "outcome": "FAILURE"}
        related = ["evt-1", "evt-2", "evt-3"]

        res = MappingConfidenceEngine.calculate_confidence(
            definition=self.directly_supported_def,
            event=event,
            related_event_ids=related,
            is_subtechnique=True,
            is_simulated_decoy=True,
        )

        self.assertTrue(res.score >= 80)
        self.assertEqual(res.level, MappingConfidenceLevel.HIGH)
        self.assertIn("Base confidence initialized", res.explanation)
        self.assertIn("Final calculated mapping confidence", res.explanation)

    def test_decoy_simulation_reduction_applied(self):
        """CONF-02: Decoy simulated authentication (AUTH-002) applies caveat reduction and achieves MODERATE or LOW level."""
        event = {"event_category": "authentication", "outcome": "SUCCESS"}
        res = MappingConfidenceEngine.calculate_confidence(
            definition=self.analyst_review_def,
            event=event,
            related_event_ids=None,
            is_subtechnique=False,
            is_simulated_decoy=True,
        )

        # Base 40 + 10 (telemetry) + 0 (volume) - 15 (decoy simulation) = 35 (LOW)
        self.assertEqual(res.score, 35)
        self.assertEqual(res.level, MappingConfidenceLevel.LOW)
        self.assertIn("Decoy simulation caveat", res.explanation)

    def test_not_mapped_returns_zero(self):
        """CONF-03: Not mapped definition produces zero confidence score."""
        res = MappingConfidenceEngine.calculate_confidence(
            definition=self.not_mapped_def,
            event={},
        )
        self.assertEqual(res.score, 0)
        self.assertEqual(res.level, MappingConfidenceLevel.LOW)
        self.assertIn("NOT_MAPPED", res.explanation)


if __name__ == "__main__":
    unittest.main()

