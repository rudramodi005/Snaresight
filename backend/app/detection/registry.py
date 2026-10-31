"""Centralized rule registry for SnareSight threat detection rules.

Maintains versioned detection rules, preserves historical versions immutably,
provides fast lookups, and manages enable/disable operational states.
"""

from typing import Dict, List, Optional
from app.detection.exceptions import DuplicateRuleError, RuleNotFoundError, RuleValidationError
from app.detection.rule_schema import DetectionRuleDefinition
from app.detection.rule_validator import RuleValidator


class RuleRegistry:
    """Thread-safe, version-aware registry of validated detection rules."""

    def __init__(self):
        # Structure: {rule_id: {version: DetectionRuleDefinition}}
        self._rules: Dict[str, Dict[str, DetectionRuleDefinition]] = {}
        # Tracks current / active version per rule_id: {rule_id: active_version_str}
        self._active_versions: Dict[str, str] = {}

    def register_rule(
        self,
        rule: DetectionRuleDefinition | dict,
        validate: bool = True,
    ) -> DetectionRuleDefinition:
        """Validates and registers a rule version. Preserves historical versions immutably."""
        if isinstance(rule, dict):
            rule_obj = DetectionRuleDefinition.model_validate(rule)
        else:
            rule_obj = rule

        if validate:
            is_valid, errors = RuleValidator.validate_rule(rule_obj)
            if not is_valid:
                raise RuleValidationError(
                    f"Rule '{rule_obj.rule_id}' failed validation: {'; '.join(errors)}",
                    rule_id=rule_obj.rule_id,
                )

        rule_id = rule_obj.rule_id
        version = rule_obj.rule_version

        if rule_id not in self._rules:
            self._rules[rule_id] = {}

        if version in self._rules[rule_id]:
            raise DuplicateRuleError(
                f"Rule '{rule_id}' version '{version}' is already registered and immutable."
            )

        # Register immutable version
        self._rules[rule_id][version] = rule_obj
        # Active version updates to newest registered version
        self._active_versions[rule_id] = version
        return rule_obj

    def is_rule_registered(self, rule_id: str, version: Optional[str] = None) -> bool:
        """Checks if a rule ID (and optional specific version) is already registered."""
        if rule_id not in self._rules:
            return False
        if version is not None:
            return version in self._rules[rule_id]
        return True

    def get_rule(self, rule_id: str, version: Optional[str] = None) -> DetectionRuleDefinition:
        """Retrieves a specific rule version or the current active version."""
        if rule_id not in self._rules:
            raise RuleNotFoundError(f"Detection rule '{rule_id}' not found in registry")

        versions = self._rules[rule_id]
        target_version = version or self._active_versions.get(rule_id)
        if not target_version or target_version not in versions:
            raise RuleNotFoundError(
                f"Version '{target_version}' of rule '{rule_id}' not found. Available: {list(versions.keys())}"
            )

        return versions[target_version]

    def get_versions(self, rule_id: str) -> List[str]:
        """Lists all registered version strings for a rule ID."""
        if rule_id not in self._rules:
            raise RuleNotFoundError(f"Rule '{rule_id}' not found")
        return sorted(list(self._rules[rule_id].keys()))

    def list_rules(self, enabled_only: bool = False) -> List[DetectionRuleDefinition]:
        """Returns the current active version of all registered rules."""
        result: List[DetectionRuleDefinition] = []
        for rule_id, current_ver in self._active_versions.items():
            rule = self._rules[rule_id][current_ver]
            if enabled_only and not rule.enabled:
                continue
            result.append(rule)
        return result

    def list_enabled_rules(self) -> List[DetectionRuleDefinition]:
        """Returns all currently enabled active detection rules."""
        return self.list_rules(enabled_only=True)

    def list_disabled_rules(self) -> List[DetectionRuleDefinition]:
        """Returns all currently disabled active detection rules."""
        return [r for r in self.list_rules(enabled_only=False) if not r.enabled]

    def set_rule_enabled(self, rule_id: str, enabled: bool, version: Optional[str] = None) -> DetectionRuleDefinition:
        """Enables or disables a specific rule version or active version."""
        rule = self.get_rule(rule_id, version=version)
        # We allow toggling operational 'enabled' state while keeping condition logic intact
        rule.enabled = enabled
        return rule

    def clear(self) -> None:
        """Clears all registered rules (used in test isolation)."""
        self._rules.clear()
        self._active_versions.clear()


# Module-level default singleton registry
rule_registry = RuleRegistry()

