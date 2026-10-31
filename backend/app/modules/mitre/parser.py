"""Secure STIX 2.1 bundle parser for MITRE ATT&CK datasets."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from app.modules.mitre.exceptions import MitreParsingError
from app.modules.mitre.schemas import (
    ExternalReference,
    RelationshipSchema,
    SubtechniqueSchema,
    TacticSchema,
    TechniqueSchema,
)
from app.modules.mitre.validators import StixValidator


@dataclass
class ParsedStixBundle:
    """Structured container of validated ATT&CK objects extracted from a STIX 2.1 bundle."""
    dataset_domain: str
    dataset_version: str
    total_objects: int
    tactics: List[TacticSchema] = field(default_factory=list)
    techniques: List[TechniqueSchema] = field(default_factory=list)
    subtechniques: List[SubtechniqueSchema] = field(default_factory=list)
    relationships: List[RelationshipSchema] = field(default_factory=list)
    unsupported_count: int = 0
    validation_warnings: List[str] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)

    @property
    def total_accepted(self) -> int:
        return len(self.tactics) + len(self.techniques) + len(self.subtechniques) + len(self.relationships)


class StixParser:
    """Interprets and validates STIX 2.1 JSON bundles according to official ATT&CK specifications."""

    @classmethod
    def parse_bundle(
        cls,
        raw_content: str | bytes | dict,
        dataset_version: str = "14.1",
        dataset_domain: str = "enterprise-attack",
    ) -> ParsedStixBundle:
        """Parses a STIX 2.1 JSON bundle safely without dynamic code evaluation.
        
        INVARIANT: Does not execute or evaluate imported text.
        """
        # 1. Parse JSON
        if isinstance(raw_content, (str, bytes)):
            if len(raw_content) > StixValidator.MAX_BUNDLE_BYTES:
                raise MitreParsingError(
                    f"STIX bundle size ({len(raw_content)} bytes) exceeds maximum ceiling of {StixValidator.MAX_BUNDLE_BYTES} bytes"
                )
            try:
                data = json.loads(raw_content)
            except Exception as exc:
                raise MitreParsingError(f"Malformed JSON in STIX bundle: {str(exc)}")
        elif isinstance(raw_content, dict):
            data = raw_content
        else:
            raise MitreParsingError("STIX bundle input must be str, bytes, or dict")

        # 2. Validate bundle structure
        is_valid_bundle, bundle_errors = StixValidator.validate_bundle_structure(data)
        if not is_valid_bundle:
            raise MitreParsingError(f"Invalid STIX bundle structure: {'; '.join(bundle_errors)}")

        objects = data.get("objects", [])
        result = ParsedStixBundle(
            dataset_domain=dataset_domain,
            dataset_version=dataset_version,
            total_objects=len(objects),
        )

        # Temporary maps to resolve parent-child subtechniques and tactic relationships
        stix_id_to_external_id: Dict[str, str] = {}
        stix_id_to_tactic_name: Dict[str, str] = {}
        subtechnique_parent_map: Dict[str, str] = {}  # child_stix_id -> parent_stix_id

        # First Pass: Collect tactics and identify STIX ID mappings
        for obj in objects:
            if not isinstance(obj, dict):
                result.validation_errors.append("Encountered non-dict STIX object in bundle")
                continue

            obj_type = obj.get("type")
            stix_id = obj.get("id")

            if obj_type == "x-mitre-tactic":
                is_valid, errs = StixValidator.validate_tactic_object(obj)
                if not is_valid:
                    result.validation_warnings.append(f"Skipping tactic {stix_id}: {'; '.join(errs)}")
                    continue

                tactic_id = StixValidator.extract_external_id(obj)
                short_name = str(obj.get("x_mitre_shortname", "")).strip().lower()
                name = str(obj.get("name", "")).strip()

                stix_id_to_external_id[stix_id] = tactic_id
                stix_id_to_tactic_name[short_name] = name

                tactic_schema = TacticSchema(
                    stix_id=stix_id,
                    tactic_id=tactic_id,
                    tactic_name=name,
                    short_name=short_name,
                    description=StixValidator.sanitize_text(obj.get("description")),
                    dataset_version=dataset_version,
                    is_deprecated=bool(obj.get("x_mitre_deprecated", False)),
                    is_revoked=bool(obj.get("revoked", False)),
                    external_references=cls._parse_external_references(obj.get("external_references")),
                )
                result.tactics.append(tactic_schema)

            elif obj_type == "relationship":
                rel_type = obj.get("relationship_type")
                if rel_type == "subtechnique-of":
                    src = obj.get("source_ref")
                    tgt = obj.get("target_ref")
                    if src and tgt:
                        subtechnique_parent_map[src] = tgt

        # Second Pass: Parse attack-patterns (Techniques & Sub-techniques) and Relationships
        for obj in objects:
            if not isinstance(obj, dict):
                continue

            obj_type = obj.get("type")
            stix_id = obj.get("id")

            if obj_type == "attack-pattern":
                is_valid, errs = StixValidator.validate_attack_pattern_object(obj)
                if not is_valid:
                    result.validation_warnings.append(f"Skipping attack-pattern {stix_id}: {'; '.join(errs)}")
                    continue

                ext_id = StixValidator.extract_external_id(obj)
                stix_id_to_external_id[stix_id] = ext_id
                name = str(obj.get("name", "")).strip()
                description = StixValidator.sanitize_text(obj.get("description"))
                is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
                is_deprecated = bool(obj.get("x_mitre_deprecated", False))
                is_revoked = bool(obj.get("revoked", False))
                platforms = [str(p) for p in (obj.get("x_mitre_platforms") or [])]
                data_sources = [str(ds) for ds in (obj.get("x_mitre_data_sources") or [])]
                ext_refs = cls._parse_external_references(obj.get("external_references"))

                # Extract kill chain tactics
                tactics_list: List[str] = []
                primary_tactic_id = "TA0001"
                primary_tactic_name = "Initial Access"
                kill_chain = obj.get("kill_chain_phases") or []
                if isinstance(kill_chain, list):
                    for phase in kill_chain:
                        if isinstance(phase, dict):
                            pname = str(phase.get("phase_name", "")).strip().lower()
                            if pname:
                                tactics_list.append(pname)
                                if pname in stix_id_to_tactic_name:
                                    primary_tactic_name = stix_id_to_tactic_name[pname]

                if is_subtechnique:
                    # Child sub-technique
                    parent_ext_id = ext_id.split(".")[0] if "." in ext_id else ""
                    parent_stix_id = subtechnique_parent_map.get(stix_id)
                    sub_schema = SubtechniqueSchema(
                        stix_id=stix_id,
                        subtechnique_id=ext_id,
                        subtechnique_name=name,
                        parent_technique_id=parent_ext_id,
                        parent_stix_id=parent_stix_id,
                        description=description,
                        dataset_version=dataset_version,
                        platforms=platforms,
                        is_deprecated=is_deprecated,
                        is_revoked=is_revoked,
                        external_references=ext_refs,
                    )
                    result.subtechniques.append(sub_schema)
                else:
                    # Parent technique
                    tech_schema = TechniqueSchema(
                        stix_id=stix_id,
                        technique_id=ext_id,
                        technique_name=name,
                        tactic_id=primary_tactic_id,
                        tactic_name=primary_tactic_name,
                        framework_version=f"v{dataset_version}",
                        description=description,
                        is_subtechnique=False,
                        tactics=tactics_list,
                        platforms=platforms,
                        data_sources=data_sources,
                        is_deprecated=is_deprecated,
                        is_revoked=is_revoked,
                        external_references=ext_refs,
                        subtechniques=[],
                    )
                    result.techniques.append(tech_schema)

            elif obj_type == "relationship":
                is_valid, errs = StixValidator.validate_relationship_object(obj)
                if not is_valid:
                    result.validation_warnings.append(f"Skipping relationship {stix_id}: {'; '.join(errs)}")
                    continue

                rel_schema = RelationshipSchema(
                    stix_id=stix_id,
                    relationship_type=str(obj.get("relationship_type")),
                    source_ref=str(obj.get("source_ref")),
                    target_ref=str(obj.get("target_ref")),
                    dataset_version=dataset_version,
                    description=StixValidator.sanitize_text(obj.get("description")),
                    is_deprecated=bool(obj.get("x_mitre_deprecated", False)),
                    is_revoked=bool(obj.get("revoked", False)),
                )
                result.relationships.append(rel_schema)

            elif obj_type == "x-mitre-tactic":
                # Already parsed in pass 1
                pass
            else:
                # Unsupported STIX types (identity, course-of-action, marking-definition, etc.) safely counted
                result.unsupported_count += 1

        return result

    @classmethod
    def _parse_external_references(cls, refs: Any) -> List[ExternalReference]:
        """Safely parses external references list."""
        parsed: List[ExternalReference] = []
        if not isinstance(refs, list):
            return parsed
        for r in refs:
            if isinstance(r, dict) and r.get("source_name"):
                parsed.append(
                    ExternalReference(
                        source_name=str(r.get("source_name")),
                        external_id=str(r.get("external_id")) if r.get("external_id") else None,
                        url=str(r.get("url")) if r.get("url") else None,
                        description=StixValidator.sanitize_text(r.get("description")) if r.get("description") else None,
                    )
                )
        return parsed

