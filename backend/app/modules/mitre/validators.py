"""Validation engine for STIX 2.1 MITRE ATT&CK bundles and framework entities."""

import re
from typing import Any, Dict, List, Set, Tuple
from app.modules.mitre.exceptions import MitreValidationError


class StixValidator:
    """Validates STIX 2.1 bundle structure, object fields, and security constraints."""

    MAX_BUNDLE_BYTES = 50 * 1024 * 1024  # 50 MB safety ceiling
    MAX_OBJECTS_COUNT = 50000

    UUID_REGEX = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    STIX_ID_REGEX = r"^[a-z0-9_-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ATTACK_TACTIC_ID_REGEX = r"^TA\d{4}$"
    ATTACK_TECHNIQUE_ID_REGEX = r"^T\d{4}(\.\d{3})?$"

    @classmethod
    def validate_bundle_structure(cls, data: Any) -> Tuple[bool, List[str]]:
        """Checks top-level STIX bundle conformity."""
        errors: List[str] = []

        if not isinstance(data, dict):
            return False, ["Bundle payload must be a JSON object"]

        bundle_type = data.get("type")
        if bundle_type != "bundle":
            errors.append(f"Invalid STIX bundle type '{bundle_type}'. Expected 'bundle'")

        bundle_id = data.get("id")
        if not bundle_id or not isinstance(bundle_id, str):
            errors.append("STIX bundle must have a valid string 'id'")
        elif not bundle_id.startswith("bundle--"):
            errors.append(f"STIX bundle id '{bundle_id}' must begin with 'bundle--'")

        objects = data.get("objects")
        if objects is None or not isinstance(objects, list):
            errors.append("STIX bundle must contain an 'objects' list")
        elif len(objects) > cls.MAX_OBJECTS_COUNT:
            errors.append(f"Bundle object count ({len(objects)}) exceeds safety maximum ({cls.MAX_OBJECTS_COUNT})")

        return len(errors) == 0, errors

    @classmethod
    def validate_stix_object_id(cls, stix_id: Any, expected_prefix: str | None = None) -> bool:
        """Validates STIX 2.1 identifier format."""
        if not stix_id or not isinstance(stix_id, str):
            return False
        if not re.match(cls.STIX_ID_REGEX, stix_id):
            return False
        if expected_prefix and not stix_id.startswith(f"{expected_prefix}--"):
            return False
        return True

    @classmethod
    def validate_tactic_object(cls, obj: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validates an x-mitre-tactic object."""
        errors: List[str] = []

        if not cls.validate_stix_object_id(obj.get("id"), expected_prefix="x-mitre-tactic"):
            errors.append(f"Invalid tactic STIX id: {obj.get('id')}")

        if not obj.get("name") or not isinstance(obj.get("name"), str):
            errors.append("Tactic requires a non-empty string 'name'")

        if not obj.get("x_mitre_shortname") or not isinstance(obj.get("x_mitre_shortname"), str):
            errors.append("Tactic requires a non-empty string 'x_mitre_shortname'")

        # Validate external ATT&CK ID presence
        ext_id = cls.extract_external_id(obj)
        if not ext_id:
            errors.append(f"Tactic {obj.get('id')} lacks an official ATT&CK external_id (e.g. TA0001)")
        elif not re.match(cls.ATTACK_TACTIC_ID_REGEX, ext_id):
            errors.append(f"Tactic external_id '{ext_id}' does not match expected format TAxxxx")

        return len(errors) == 0, errors

    @classmethod
    def validate_attack_pattern_object(cls, obj: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validates an attack-pattern (technique or sub-technique) object."""
        errors: List[str] = []

        if not cls.validate_stix_object_id(obj.get("id"), expected_prefix="attack-pattern"):
            errors.append(f"Invalid attack-pattern STIX id: {obj.get('id')}")

        if not obj.get("name") or not isinstance(obj.get("name"), str):
            errors.append("Attack pattern requires a non-empty string 'name'")

        ext_id = cls.extract_external_id(obj)
        if not ext_id:
            errors.append(f"Attack pattern {obj.get('id')} lacks an official ATT&CK external_id")
        elif not re.match(cls.ATTACK_TECHNIQUE_ID_REGEX, ext_id):
            errors.append(f"Technique external_id '{ext_id}' does not match format Txxxx or Txxxx.xxx")

        is_sub = obj.get("x_mitre_is_subtechnique", False)
        if is_sub and ext_id and "." not in ext_id:
            errors.append(f"Sub-technique external_id '{ext_id}' must contain a dot separator (e.g. T1110.001)")

        return len(errors) == 0, errors

    @classmethod
    def validate_relationship_object(cls, obj: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validates a relationship object."""
        errors: List[str] = []

        if not cls.validate_stix_object_id(obj.get("id"), expected_prefix="relationship"):
            errors.append(f"Invalid relationship STIX id: {obj.get('id')}")

        rel_type = obj.get("relationship_type")
        if not rel_type or not isinstance(rel_type, str):
            errors.append("Relationship requires a valid string 'relationship_type'")

        src = obj.get("source_ref")
        tgt = obj.get("target_ref")
        if not src or not isinstance(src, str):
            errors.append("Relationship requires a non-empty 'source_ref'")
        if not tgt or not isinstance(tgt, str):
            errors.append("Relationship requires a non-empty 'target_ref'")

        return len(errors) == 0, errors

    @classmethod
    def extract_external_id(cls, obj: Dict[str, Any]) -> str | None:
        """Extracts the official MITRE ATT&CK external_id (e.g. T1110, TA0006) from external_references."""
        refs = obj.get("external_references") or []
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    src_name = str(ref.get("source_name", "")).lower()
                    if "mitre" in src_name or src_name in ("mitre-attack", "mitre-enterprise-attack"):
                        ext_id = ref.get("external_id")
                        if ext_id and isinstance(ext_id, str):
                            return ext_id.strip()
            # Fallback to any reference with external_id
            for ref in refs:
                if isinstance(ref, dict) and ref.get("external_id"):
                    return str(ref.get("external_id")).strip()
        return None

    @classmethod
    def sanitize_text(cls, text: Any) -> str:
        """Sanitizes text strings to neutralize potential HTML/script injection.
        
        INVARIANT: ATT&CK descriptions are passive documentation. Executable scripts
        or malicious tags are neutralized.
        """
        if text is None:
            return ""
        val = str(text)
        # Strip script tags and dangerous HTML event handlers
        cleaned = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", val, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"on\w+\s*=", "data-blocked-handler=", cleaned, flags=re.IGNORECASE)
        return cleaned.strip()

