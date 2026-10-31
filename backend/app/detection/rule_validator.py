"""Strict declarative rule validation engine for SnareSight.

Enforces structural integrity, field allowlists, operator validation, nesting depth
bounds, and condition count ceilings prior to rule registration.
"""

from typing import Any, Dict, List, Set, Tuple
from app.detection.exceptions import (
    RuleValidationError,
    InvalidOperatorError,
    UnsupportedFieldError,
    RestrictedFieldError,
)
from app.detection.field_registry import FieldRegistry, PROHIBITED_SENSITIVE_FIELDS
from app.detection.condition_evaluator import Operator
from app.detection.rule_schema import DetectionRuleDefinition, AtomicCondition, ConditionGroup


class RuleValidator:
    """Validates detection rules against SnareSight security and structure standards."""

    MAX_NESTING_DEPTH = 3
    MAX_TOTAL_CONDITIONS = 20
    MAX_STRING_OPERAND_LENGTH = 1000
    MAX_COLLECTION_OPERAND_LENGTH = 50

    SUPPORTED_CATEGORIES: Set[str] = {
        "AUTHENTICATION",
        "RECONNAISSANCE",
        "EXPLOITATION",
        "PERSISTENCE",
        "DECEPTION",
        "COMMAND_EXECUTION",
        "CREDENTIAL_ACCESS",
        "NETWORK",
        "APPLICATION",
    }

    @classmethod
    def validate_rule(cls, rule: DetectionRuleDefinition | Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Performs full syntactic, semantic, and security validation on a rule definition.
        
        Returns:
            (is_valid, error_messages)
        """
        errors: List[str] = []

        # Convert dictionary to schema if necessary
        rule_obj: DetectionRuleDefinition
        if isinstance(rule, dict):
            try:
                rule_obj = DetectionRuleDefinition.model_validate(rule)
            except Exception as exc:
                return False, [f"Schema structure error: {str(exc)}"]
        else:
            rule_obj = rule

        # 1. Identifier & Category Validation
        if not rule_obj.rule_id or not rule_obj.rule_id.strip():
            errors.append("Rule ID must not be empty")
        if rule_obj.category.upper() not in cls.SUPPORTED_CATEGORIES:
            errors.append(
                f"Unsupported category '{rule_obj.category}'. Supported categories: {sorted(list(cls.SUPPORTED_CATEGORIES))}"
            )

        # 2. Condition Tree Validation & Safety Bounds
        condition_count = [0]
        try:
            cls._validate_condition_group(
                rule_obj.conditions,
                current_depth=1,
                condition_count=condition_count,
            )
        except RuleValidationError as rve:
            errors.append(str(rve))
        except Exception as exc:
            errors.append(f"Unexpected condition error: {str(exc)}")

        if condition_count[0] > cls.MAX_TOTAL_CONDITIONS:
            errors.append(
                f"Condition count {condition_count[0]} exceeds maximum allowed ({cls.MAX_TOTAL_CONDITIONS})"
            )

        # 3. Threshold and Time Window Validation
        if rule_obj.evaluation_mode.value in ("SESSION", "TIME_WINDOW"):
            if rule_obj.time_window_seconds is not None:
                if rule_obj.time_window_seconds <= 0 or rule_obj.time_window_seconds > 86400:
                    errors.append(f"Invalid time_window_seconds ({rule_obj.time_window_seconds}). Must be between 1 and 86400")

        return len(errors) == 0, errors

    @classmethod
    def _validate_condition_group(
        cls,
        group: ConditionGroup,
        current_depth: int,
        condition_count: List[int],
    ) -> None:
        """Recursively validates condition groups and child atomic conditions."""
        if current_depth > cls.MAX_NESTING_DEPTH:
            raise RuleValidationError(
                f"Nesting depth {current_depth} exceeds maximum allowable depth ({cls.MAX_NESTING_DEPTH})"
            )

        if not group.all and not group.any:
            raise RuleValidationError("Logical group must define at least one 'all' or 'any' condition set")

        if group.all:
            for item in group.all:
                if isinstance(item, ConditionGroup) or (isinstance(item, dict) and ("all" in item or "any" in item)):
                    sub_grp = item if isinstance(item, ConditionGroup) else ConditionGroup.model_validate(item)
                    cls._validate_condition_group(sub_grp, current_depth + 1, condition_count)
                else:
                    atomic = item if isinstance(item, AtomicCondition) else AtomicCondition.model_validate(item)
                    condition_count[0] += 1
                    cls._validate_atomic_condition(atomic)

        if group.any:
            for item in group.any:
                if isinstance(item, ConditionGroup) or (isinstance(item, dict) and ("all" in item or "any" in item)):
                    sub_grp = item if isinstance(item, ConditionGroup) else ConditionGroup.model_validate(item)
                    cls._validate_condition_group(sub_grp, current_depth + 1, condition_count)
                else:
                    atomic = item if isinstance(item, AtomicCondition) else AtomicCondition.model_validate(item)
                    condition_count[0] += 1
                    cls._validate_atomic_condition(atomic)

    @classmethod
    def _validate_atomic_condition(cls, condition: AtomicCondition) -> None:
        """Validates field name, operator, and operand bounds for an atomic condition."""
        field_name = condition.field.strip()

        # Check prohibited fields
        if field_name.lower() in PROHIBITED_SENSITIVE_FIELDS:
            raise RestrictedFieldError(
                f"Condition targets prohibited sensitive field '{field_name}'",
                field=field_name,
            )

        # Validate against field registry
        field_def = FieldRegistry.get_field_def(field_name)

        # Validate operator
        try:
            op = Operator(condition.operator.upper())
        except (ValueError, AttributeError):
            raise InvalidOperatorError(
                f"Operator '{condition.operator}' is not supported",
                field=field_name,
            )

        # Validate operand size and type
        val = condition.value
        if op in (Operator.EXISTS, Operator.NOT_EXISTS):
            # No operand required for existence operators
            pass
        elif op in (Operator.IN, Operator.NOT_IN):
            if not isinstance(val, (list, tuple, set)):
                raise RuleValidationError(
                    f"Operator '{op.value}' requires a collection operand, got {type(val).__name__}",
                    field=field_name,
                )
            if len(val) > cls.MAX_COLLECTION_OPERAND_LENGTH:
                raise RuleValidationError(
                    f"Collection operand exceeds maximum length ({cls.MAX_COLLECTION_OPERAND_LENGTH})",
                    field=field_name,
                )
        else:
            if isinstance(val, str) and len(val) > cls.MAX_STRING_OPERAND_LENGTH:
                raise RuleValidationError(
                    f"String operand exceeds maximum allowable length ({cls.MAX_STRING_OPERAND_LENGTH})",
                    field=field_name,
                )
            if op in (Operator.GREATER_THAN, Operator.GREATER_THAN_OR_EQUAL, Operator.LESS_THAN, Operator.LESS_THAN_OR_EQUAL):
                if not isinstance(val, (int, float)):
                    raise RuleValidationError(
                        f"Numeric comparison operator '{op.value}' requires numeric operand, got {type(val).__name__}",
                        field=field_name,
                    )

