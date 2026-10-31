"""Unit tests for curated MITRE ATT&CK Mapping Definition Registry (Task P20)."""

import unittest
from app.modules.mitre.mapping.registry import MappingDefinitionRegistry, mapping_registry
from app.modules.mitre.mapping.schemas import MappingCategory, MappingDefinitionSchema


class TestMappingRegistry(unittest.TestCase):
    """Verifies curated registry loading, validation, and querying."""

    def setUp(self):
        self.registry = MappingDefinitionRegistry()

    def test_default_scenarios_are_registered(self):
        """REG-01: Default registry contains mappings for scenarios AUTH-001 through AUTH-003, WEB-001, WEB-002."""
        auth_001 = self.registry.get_definitions_for_rule("AUTH-001")
        self.assertTrue(len(auth_001) >= 1)
        self.assertEqual(auth_001[0].technique_id, "T1110")
        self.assertEqual(auth_001[0].subtechnique_id, "T1110.001")
        self.assertEqual(auth_001[0].mapping_category, MappingCategory.DIRECTLY_SUPPORTED)

        auth_002 = self.registry.get_definitions_for_rule("AUTH-002")
        self.assertTrue(len(auth_002) >= 1)
        self.assertEqual(auth_002[0].technique_id, "T1078")
        self.assertEqual(auth_002[0].mapping_category, MappingCategory.REQUIRES_ANALYST_REVIEW)

        web_001 = self.registry.get_definitions_for_rule("WEB-001")
        self.assertTrue(len(web_001) >= 1)
        self.assertEqual(web_001[0].technique_id, "T1083")

        web_002 = self.registry.get_definitions_for_rule("WEB-002")
        self.assertTrue(len(web_002) >= 1)
        self.assertEqual(web_002[0].technique_id, "T1190")

    def test_unsupported_scenarios_remain_unmapped(self):
        """REG-02: Deferred and unspecific scenarios (CMD-001, FILE-001, WEB-003, BEHAV-001, BEHAV-002) are NOT_MAPPED."""
        # Active definitions for deferred rules must be empty
        self.assertEqual(len(self.registry.get_definitions_for_rule("CMD-001")), 0)
        self.assertEqual(len(self.registry.get_definitions_for_rule("FILE-001")), 0)
        self.assertEqual(len(self.registry.get_definitions_for_rule("WEB-003")), 0)
        self.assertEqual(len(self.registry.get_definitions_for_rule("BEHAV-001")), 0)
        self.assertEqual(len(self.registry.get_definitions_for_rule("BEHAV-002")), 0)

        # But in full catalogue they exist with NOT_MAPPED category and is_active=False
        all_defs = {d.mapping_definition_id: d for d in self.registry.list_all_definitions(active_only=False)}
        self.assertEqual(all_defs["MAP-CMD-001-NONE"].mapping_category, MappingCategory.NOT_MAPPED)
        self.assertFalse(all_defs["MAP-CMD-001-NONE"].is_active)
        self.assertEqual(all_defs["MAP-FILE-001-NONE"].mapping_category, MappingCategory.NOT_MAPPED)
        self.assertEqual(all_defs["MAP-WEB-003-NONE"].mapping_category, MappingCategory.NOT_MAPPED)

    def test_unknown_rule_returns_empty_definitions(self):
        """REG-03: Querying an unknown rule ID returns an empty list without error."""
        defs = self.registry.get_definitions_for_rule("NON-EXISTENT-RULE")
        self.assertEqual(defs, [])

    def test_register_custom_valid_definition(self):
        """REG-04: Registering a custom valid definition succeeds and is queryable."""
        custom_def = MappingDefinitionSchema(
            mapping_definition_id="MAP-CUSTOM-TEST",
            rule_id="CUSTOM-001",
            rule_version_range=">=1.0",
            technique_id="T1190",
            mapping_category=MappingCategory.PARTIALLY_SUPPORTED,
            default_confidence=60,
            required_evidence_fields=["event_category"],
            mapping_rationale="Custom test mapping rationale.",
            version="1.0",
        )
        self.registry.register_definition(custom_def)
        retrieved = self.registry.get_definition("MAP-CUSTOM-TEST")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.rule_id, "CUSTOM-001")


if __name__ == "__main__":
    unittest.main()

