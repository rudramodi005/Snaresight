"""Unit tests for STIX 2.1 relationship extraction and parent-child linkage."""

import unittest
from app.modules.mitre.parser import StixParser


class TestStixRelationships(unittest.TestCase):
    """Verifies STIX 2.1 relationship handling, tactic associations, and sub-technique links."""

    def setUp(self):
        self.tactic = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--7141382c-16e0-4355-ab43-edd7f0160274",
            "name": "Credential Access",
            "x_mitre_shortname": "credential-access",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
        }
        self.parent_tech = {
            "type": "attack-pattern",
            "id": "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b",
            "name": "Brute Force",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "x_mitre_is_subtechnique": False,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        }
        self.sub_tech = {
            "type": "attack-pattern",
            "id": "attack-pattern--f67232e7-0a4a-43cf-8c6e-be2552825838",
            "name": "Password Guessing",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "x_mitre_is_subtechnique": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.001"}],
        }
        self.rel = {
            "type": "relationship",
            "id": "relationship--0ec1481e-1563-4467-b71e-05a22bbab0b3",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--f67232e7-0a4a-43cf-8c6e-be2552825838",
            "target_ref": "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b",
        }

    def test_parent_subtechnique_linkage(self):
        """REL-01: Sub-technique accurately links to parent STIX ID and parent technique ID."""
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000010",
            "objects": [self.tactic, self.parent_tech, self.sub_tech, self.rel],
        }
        parsed = StixParser.parse_bundle(bundle)
        self.assertEqual(len(parsed.subtechniques), 1)
        sub = parsed.subtechniques[0]
        self.assertEqual(sub.parent_technique_id, "T1110")
        self.assertEqual(sub.parent_stix_id, self.parent_tech["id"])

    def test_tactic_association_mapping(self):
        """REL-02: Kill chain phases accurately associate techniques with tactic names."""
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000011",
            "objects": [self.tactic, self.parent_tech],
        }
        parsed = StixParser.parse_bundle(bundle)
        tech = parsed.techniques[0]
        self.assertEqual(tech.tactic_name, "Credential Access")
        self.assertIn("credential-access", tech.tactics)

    def test_missing_relationship_target_handled_gracefully(self):
        """REL-03: Sub-technique with missing relationship target falls back to ID derivation."""
        # Bundle with sub-technique but missing the relationship object
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000012",
            "objects": [self.tactic, self.sub_tech],
        }
        parsed = StixParser.parse_bundle(bundle)
        self.assertEqual(len(parsed.subtechniques), 1)
        sub = parsed.subtechniques[0]
        # Parent ID derived from T1110.001 -> T1110
        self.assertEqual(sub.parent_technique_id, "T1110")
        self.assertIsNone(sub.parent_stix_id)


if __name__ == "__main__":
    unittest.main()

