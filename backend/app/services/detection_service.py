"""Detection rule configuration and execution management service for SnareSight.

Provides administrative interfaces for creating, validating, updating, versioning,
and auditing detection rules and evaluation execution history.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.detection.engine import DetectionEngine, detection_engine
from app.detection.exceptions import DetectionError, RuleNotFoundError, RuleValidationError
from app.detection.execution_tracker import ExecutionTracker, execution_tracker
from app.detection.registry import RuleRegistry, rule_registry
from app.detection.rule_schema import DetectionRuleDefinition
from app.detection.rule_validator import RuleValidator
from app.schemas.detection import DetectionExecutionRecord, DetectionResult


class DetectionService:
    """Service facade for managing detection rules and executing threat evaluations."""

    def __init__(
        self,
        engine: Optional[DetectionEngine] = None,
        registry: Optional[RuleRegistry] = None,
        tracker: Optional[ExecutionTracker] = None,
    ):
        self.engine = engine or detection_engine
        self.registry = registry or rule_registry
        self.tracker = tracker or execution_tracker

    def create_rule(
        self,
        rule_data: Dict[str, Any] | DetectionRuleDefinition,
        user_role: str = "analyst",
    ) -> DetectionRuleDefinition:
        """Creates and registers a validated rule. Enforces role authorization."""
        if user_role not in ("admin", "security_engineer", "analyst"):
            raise PermissionError(f"User role '{user_role}' is not authorized to create detection rules")

        rule_obj = rule_data if isinstance(rule_data, DetectionRuleDefinition) else DetectionRuleDefinition.model_validate(rule_data)
        
        # Enforce validation
        is_valid, errors = RuleValidator.validate_rule(rule_obj)
        if not is_valid:
            raise RuleValidationError(f"Rule validation failed: {'; '.join(errors)}", rule_id=rule_obj.rule_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        if not rule_obj.created_at:
            rule_obj.created_at = now_iso
        rule_obj.updated_at = now_iso

        return self.registry.register_rule(rule_obj, validate=False)

    def validate_rule_definition(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Dry-run validation of candidate rule configuration."""
        is_valid, errors = RuleValidator.validate_rule(rule_data)
        return {
            "valid": is_valid,
            "errors": errors,
            "rule_id": rule_data.get("rule_id"),
        }

    def enable_rule(self, rule_id: str, version: Optional[str] = None, user_role: str = "admin") -> DetectionRuleDefinition:
        """Enables a registered rule version."""
        if user_role not in ("admin", "security_engineer"):
            raise PermissionError(f"User role '{user_role}' lacks permission to toggle rule activation")
        return self.registry.set_rule_enabled(rule_id, enabled=True, version=version)

    def disable_rule(self, rule_id: str, version: Optional[str] = None, user_role: str = "admin") -> DetectionRuleDefinition:
        """Disables a registered rule version."""
        if user_role not in ("admin", "security_engineer"):
            raise PermissionError(f"User role '{user_role}' lacks permission to toggle rule activation")
        return self.registry.set_rule_enabled(rule_id, enabled=False, version=version)

    def get_rule(self, rule_id: str, version: Optional[str] = None) -> DetectionRuleDefinition:
        """Retrieves rule definition from registry."""
        return self.registry.get_rule(rule_id, version=version)

    def list_rules(self, enabled_only: bool = False) -> List[DetectionRuleDefinition]:
        """Lists active versions of all registered rules."""
        return self.registry.list_rules(enabled_only=enabled_only)

    def get_rule_version_history(self, rule_id: str) -> List[str]:
        """Lists all registered version numbers for a rule ID."""
        return self.registry.get_versions(rule_id)

    def evaluate_normalized_event(
        self,
        event: Dict[str, Any],
        db: Optional[Session] = None,
    ) -> List[DetectionResult]:
        """Passes event through the detection engine."""
        return self.engine.evaluate_event(event=event, db=db)

    def get_execution_history(self, limit: int = 100) -> List[DetectionExecutionRecord]:
        """Retrieves recent execution audit entries."""
        return self.tracker.get_history(limit=limit)


# Default module-level singleton
detection_service = DetectionService()

