"""Unit tests for safe STIX 2.1 parsing and validation in the MITRE ATT&CK module."""

import json
import unittest
from app.modules.mitre.exceptions import MitreParsingError
from app.modules.mitre.parser import StixParser
from app.modules.mitre.validators import StixValidator


class TestStixParser(unittest.TestCase):
    """Test suite covering STIX 2.1 JSON bundle parsing and schema validation."""

    def setUp(self):
        """Initializes sample STIX 2.1 objects."""
        self.valid_tactic = {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--7141382c-16e0-4355-ab43-edd7f0160274",
            "name": "Credential Access",
            "x_mitre_shortname": "credential-access",
            "description": "Adversary is attempting to access credentials.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0006", "url": "https://attack.mitre.org/tactics/TA0006"}
            ],
        }

        self.valid_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "x_mitre_platforms": ["Linux", "Windows"],
            "x_mitre_is_subtechnique": False,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110", "url": "https://attack.mitre.org/techniques/T1110"}
            ],
        }

        self.valid_subtechnique = {
            "type": "attack-pattern",
            "id": "attack-pattern--f67232e7-0a4a-43cf-8c6e-be2552825838",
            "name": "Password Guessing",
            "description": "Adversaries may guess passwords.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "x_mitre_platforms": ["Linux", "Windows"],
            "x_mitre_is_subtechnique": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110.001", "url": "https://attack.mitre.org/techniques/T1110/001"}
            ],
        }

        self.valid_relationship = {
            "type": "relationship",
            "id": "relationship--0ec1481e-1563-4467-b71e-05a22bbab0b3",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--f67232e7-0a4a-43cf-8c6e-be2552825838",
            "target_ref": "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b",
        }

    def test_parse_valid_stix_bundle(self):
        """PARSER-01: Valid STIX 2.1 bundle parses tactics, techniques, and sub-techniques."""
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "objects": [
                self.valid_tactic,
                self.valid_technique,
                self.valid_subtechnique,
                self.valid_relationship,
            ],
        }
        parsed = StixParser.parse_bundle(bundle, dataset_version="14.1")
        self.assertEqual(parsed.total_objects, 4)
        self.assertEqual(len(parsed.tactics), 1)
        self.assertEqual(len(parsed.techniques), 1)
        self.assertEqual(len(parsed.subtechniques), 1)
        self.assertEqual(len(parsed.relationships), 1)

        # Check tactic
        self.assertEqual(parsed.tactics[0].tactic_id, "TA0006")
        self.assertEqual(parsed.tactics[0].short_name, "credential-access")

        # Check technique
        self.assertEqual(parsed.techniques[0].technique_id, "T1110")
        self.assertFalse(parsed.techniques[0].is_subtechnique)

        # Check sub-technique parent linkage
        self.assertEqual(parsed.subtechniques[0].subtechnique_id, "T1110.001")
        self.assertEqual(parsed.subtechniques[0].parent_technique_id, "T1110")
        self.assertEqual(parsed.subtechniques[0].parent_stix_id, "attack-pattern--b1732e74-279c-485c-8b83-dbb7ef382b6b")

    def test_parse_malformed_json_raises_parsing_error(self):
        """PARSER-02: Malformed JSON raises MitreParsingError."""
        bad_json = "{'type': 'bundle', unquoted_key: }"
        with self.assertRaises(MitreParsingError):
            StixParser.parse_bundle(bad_json)

    def test_parse_invalid_bundle_structure_raises_error(self):
        """PARSER-03: Invalid top-level bundle structure is rejected."""
        # Missing type
        with self.assertRaises(MitreParsingError):
            StixParser.parse_bundle({"id": "bundle--123", "objects": []})

        # Not a bundle
        with self.assertRaises(MitreParsingError):
            StixParser.parse_bundle({"type": "identity", "id": "identity--123", "objects": []})

    def test_unsupported_object_types_handled_safely(self):
        """PARSER-04: Unsupported STIX types are safely accounted for without breaking import."""
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000002",
            "objects": [
                self.valid_tactic,
                {"type": "identity", "id": "identity--00000000-0000-0000-0000-000000000001", "name": "MITRE"},
                {"type": "marking-definition", "id": "marking-definition--00000000-0000-0000-0000-000000000002"},
            ],
        }
        parsed = StixParser.parse_bundle(bundle)
        self.assertEqual(len(parsed.tactics), 1)
        self.assertEqual(parsed.unsupported_count, 2)
        self.assertEqual(parsed.total_accepted, 1)

    def test_missing_optional_fields_are_handled_cleanly(self):
        """PARSER-05: Missing optional fields (description, platforms, etc.) receive sensible defaults."""
        minimal_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--00000000-0000-0000-0000-000000000003",
            "name": "Minimal Tech",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
        }
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000003",
            "objects": [minimal_technique],
        }
        parsed = StixParser.parse_bundle(bundle)
        self.assertEqual(len(parsed.techniques), 1)
        tech = parsed.techniques[0]
        self.assertEqual(tech.technique_id, "T1234")
        self.assertEqual(tech.description, "")
        self.assertEqual(tech.platforms, [])

    def test_xss_script_tags_are_sanitized(self):
        """PARSER-06: Script injection payloads in descriptions are neutralized."""
        malicious_technique = {
            "type": "attack-pattern",
            "id": "attack-pattern--00000000-0000-0000-0000-000000000004",
            "name": "XSS Test",
            "description": "Safe text <script>alert('pwned')</script> more safe text <img src=x onerror=alert(1)>",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1999"}],
        }
        bundle = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000004",
            "objects": [malicious_technique],
        }
        parsed = StixParser.parse_bundle(bundle)
        desc = parsed.techniques[0].description
        self.assertNotIn("<script>", desc)
        self.assertNotIn("alert('pwned')", desc)
        self.assertNotIn("onerror=", desc)

    def test_bundle_size_ceiling_is_enforced(self):
        """PARSER-07: Payload exceeding maximum size is rejected."""
        huge_string = " " * (StixValidator.MAX_BUNDLE_BYTES + 10)
        with self.assertRaises(MitreParsingError):
            StixParser.parse_bundle(huge_string)


if __name__ == "__main__":
    unittest.main()

