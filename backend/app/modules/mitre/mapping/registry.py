"""Curated Registry of Versioned ATT&CK Mapping Definitions (Task P20).

Enforces conservative, evidence-based mappings connecting SnareSight detection rules
to official MITRE ATT&CK techniques based strictly on observed honeypot telemetry.
"""

from typing import Dict, List, Optional
from app.modules.mitre.mapping.schemas import MappingCategory, MappingDefinitionSchema


class MappingDefinitionRegistry:
    """In-memory catalogue and validator for curated detection-to-ATT&CK mapping definitions."""

    def __init__(self):
        self._definitions: Dict[str, MappingDefinitionSchema] = {}
        self._rule_index: Dict[str, List[str]] = {}
        self._load_curated_definitions()

    def register_definition(self, definition: MappingDefinitionSchema) -> None:
        """Registers a verified mapping definition."""
        self._definitions[definition.mapping_definition_id] = definition
        if definition.rule_id not in self._rule_index:
            self._rule_index[definition.rule_id] = []
        if definition.mapping_definition_id not in self._rule_index[definition.rule_id]:
            self._rule_index[definition.rule_id].append(definition.mapping_definition_id)

    def get_definition(self, mapping_definition_id: str) -> Optional[MappingDefinitionSchema]:
        """Retrieves definition by unique ID."""
        return self._definitions.get(mapping_definition_id)

    def get_definitions_for_rule(self, rule_id: str) -> List[MappingDefinitionSchema]:
        """Retrieves active mapping definitions associated with a detection rule."""
        def_ids = self._rule_index.get(rule_id, [])
        return [self._definitions[did] for did in def_ids if self._definitions[did].is_active]

    def list_all_definitions(self, active_only: bool = True) -> List[MappingDefinitionSchema]:
        """Returns all registered mapping definitions."""
        if active_only:
            return [d for d in self._definitions.values() if d.is_active]
        return list(self._definitions.values())

    def _load_curated_definitions(self) -> None:
        """Loads curated mapping definitions for all 10 SnareSight detection scenarios."""

        # ---------------------------------------------------------------------
        # SCENARIO 01: AUTH-001 -> T1110 (Brute Force) & T1110.001 (Password Guessing)
        # ---------------------------------------------------------------------
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-AUTH-001-T1110",
                rule_id="AUTH-001",
                rule_version_range=">=1.0",
                technique_id="T1110",
                subtechnique_id="T1110.001",
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.DIRECTLY_SUPPORTED,
                default_confidence=85,
                required_evidence_fields=["event_category", "outcome"],
                optional_evidence_fields=["session_id", "source_ip", "metadata.username_fingerprint"],
                exclusion_conditions={"outcome": "SUCCESS"},
                mapping_rationale=(
                    "Repeated authentication failures observed on the web decoy login endpoint within a session "
                    "are consistent with automated credential guessing against public-facing authentication interfaces. "
                    "CRITICAL CAVEAT: Observed failures demonstrate guessing attempts, NOT successful credential acquisition."
                ),
                version="1.0",
                documentation_reference="https://attack.mitre.org/techniques/T1110/001/",
                is_active=True,
            )
        )

        # ---------------------------------------------------------------------
        # SCENARIO 02: AUTH-002 -> T1078 (Valid Accounts) [REQUIRES_ANALYST_REVIEW]
        # ---------------------------------------------------------------------
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-AUTH-002-T1078",
                rule_id="AUTH-002",
                rule_version_range=">=1.0",
                technique_id="T1078",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.REQUIRES_ANALYST_REVIEW,
                default_confidence=45,
                required_evidence_fields=["event_category", "outcome"],
                optional_evidence_fields=["session_id", "source_ip"],
                exclusion_conditions={"outcome": "FAILURE"},
                mapping_rationale=(
                    "Simulated successful authentication occurred against a decoy honeypot trap account. "
                    "CRITICAL DECEPTION WARNING: The honeypot simulates valid account acceptance for deception purposes. "
                    "This evidence does NOT establish compromise of authentic production directory accounts, domain credentials, "
                    "or production systems. Mandatory analyst review is required before classifying as genuine Valid Account abuse."
                ),
                version="1.0",
                documentation_reference="https://attack.mitre.org/techniques/T1078/",
                is_active=True,
            )
        )

        # ---------------------------------------------------------------------
        # SCENARIO 03: AUTH-003 -> T1087 (Account Discovery) [PARTIALLY_SUPPORTED]
        # ---------------------------------------------------------------------
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-AUTH-003-T1087",
                rule_id="AUTH-003",
                rule_version_range=">=1.0",
                technique_id="T1087",
                subtechnique_id="T1087.001",
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.PARTIALLY_SUPPORTED,
                default_confidence=65,
                required_evidence_fields=["event_category", "metadata.username_fingerprint"],
                optional_evidence_fields=["session_id"],
                exclusion_conditions={},
                mapping_rationale=(
                    "Probing distinct privacy-safe username fingerprints across multiple attempts within a session "
                    "is consistent with adversary account enumeration or discovery. Does not prove the attacker discovered "
                    "authentic internal domain or local system accounts."
                ),
                version="1.0",
                documentation_reference="https://attack.mitre.org/techniques/T1087/001/",
                is_active=True,
            )
        )

        # ---------------------------------------------------------------------
        # SCENARIO 04: WEB-001 -> T1083 (File and Directory Discovery) [PARTIALLY_SUPPORTED]
        # ---------------------------------------------------------------------
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-WEB-001-T1083",
                rule_id="WEB-001",
                rule_version_range=">=1.0",
                technique_id="T1083",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.PARTIALLY_SUPPORTED,
                default_confidence=65,
                required_evidence_fields=["event_category", "metadata.http_path"],
                optional_evidence_fields=["session_id", "source_ip"],
                exclusion_conditions={},
                mapping_rationale=(
                    "Systematic requests targeting distinct web directory paths on the decoy server "
                    "are consistent with automated file and directory discovery probing. "
                    "Does not establish that directory listings or sensitive files were disclosed or accessed."
                ),
                version="1.0",
                documentation_reference="https://attack.mitre.org/techniques/T1083/",
                is_active=True,
            )
        )

        # ---------------------------------------------------------------------
        # SCENARIO 05: WEB-002 -> T1190 (Exploit Public-Facing Application) [PARTIALLY_SUPPORTED]
        # ---------------------------------------------------------------------
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-WEB-002-T1190",
                rule_id="WEB-002",
                rule_version_range=">=1.0",
                technique_id="T1190",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.PARTIALLY_SUPPORTED,
                default_confidence=70,
                required_evidence_fields=["metadata.http_path"],
                optional_evidence_fields=["session_id", "source_ip"],
                exclusion_conditions={},
                mapping_rationale=(
                    "HTTP request path contains directory traversal sequences (../, ..%2f, %2e%2e/). "
                    "Consistent with exploitation attempts against web application input handlers. "
                    "CRITICAL EXECUTION SAFETY: Requested paths are matched passively and never executed or resolved "
                    "against the host filesystem. Does not indicate successful file retrieval or arbitrary execution."
                ),
                version="1.0",
                documentation_reference="https://attack.mitre.org/techniques/T1190/",
                is_active=True,
            )
        )

        # ---------------------------------------------------------------------
        # SCENARIOS 06-10: EXPLICITLY UNMAPPED SCENARIOS (NOT_MAPPED)
        # ---------------------------------------------------------------------
        # CMD-001: Command Discovery (Deferred)
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-CMD-001-NONE",
                rule_id="CMD-001",
                rule_version_range=">=1.0",
                technique_id="T1082",  # System Information Discovery
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.NOT_MAPPED,
                default_confidence=0,
                required_evidence_fields=[],
                mapping_rationale=(
                    "Rule CMD-001 is explicitly deferred and in DRAFT status. The current HTTP web decoy provides "
                    "no interactive shell or command prompt telemetry. Inferred or fictional command execution is "
                    "strictly prohibited from being mapped."
                ),
                version="1.0",
                is_active=False,
            )
        )

        # FILE-001: File Transfer (Deferred)
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-FILE-001-NONE",
                rule_id="FILE-001",
                rule_version_range=">=1.0",
                technique_id="T1105",  # Ingress Tool Transfer
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.NOT_MAPPED,
                default_confidence=0,
                required_evidence_fields=[],
                mapping_rationale=(
                    "Rule FILE-001 is explicitly deferred and in DRAFT status. The web decoy does not support file "
                    "upload, download, or payload transfer. File transfer techniques cannot be mapped without actual telemetry."
                ),
                version="1.0",
                is_active=False,
            )
        )

        # WEB-003: Repeated Suspicious Request Patterns
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-WEB-003-NONE",
                rule_id="WEB-003",
                rule_version_range=">=1.0",
                technique_id="T1190",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.NOT_MAPPED,
                default_confidence=0,
                required_evidence_fields=[],
                mapping_rationale=(
                    "Repeated suspicious request patterns provide insufficient behavioral specificity to justify an "
                    "ATT&CK technique. Statistical repetition without concrete signature remains unmapped to avoid speculation."
                ),
                version="1.0",
                is_active=False,
            )
        )

        # BEHAV-001: Multi-Category Suspicious Interaction
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-BEHAV-001-NONE",
                rule_id="BEHAV-001",
                rule_version_range=">=1.0",
                technique_id="T1190",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.NOT_MAPPED,
                default_confidence=0,
                required_evidence_fields=[],
                mapping_rationale=(
                    "Multi-category suspicious interaction aggregates distinct behaviors across a session. Full attack-chain "
                    "synthesis and multi-tactic progression belong to Phase 5 correlation, not atomic technique assignment."
                ),
                version="1.0",
                is_active=False,
            )
        )

        # BEHAV-002: Unusual HTTP Method Interaction
        self.register_definition(
            MappingDefinitionSchema(
                mapping_definition_id="MAP-BEHAV-002-NONE",
                rule_id="BEHAV-002",
                rule_version_range=">=1.0",
                technique_id="T1190",
                subtechnique_id=None,
                dataset_domain="enterprise-attack",
                mapping_category=MappingCategory.NOT_MAPPED,
                default_confidence=0,
                required_evidence_fields=[],
                mapping_rationale=(
                    "Requests utilizing unusual HTTP methods (TRACE, DEBUG, PROPFIND) represent statistical anomalies. "
                    "Baseline method anomalies lack defensible evidence of a specific ATT&CK technique and remain unmapped."
                ),
                version="1.0",
                is_active=False,
            )
        )


# Global singleton instance
mapping_registry = MappingDefinitionRegistry()

