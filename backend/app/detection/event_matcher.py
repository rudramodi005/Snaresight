"""Event condition matching engine for SnareSight detection rules.

Traverses condition trees against normalized security event records, evaluates
predicates safely, and compiles explainable match diagnostics.
"""

from typing import Any, Dict, List, Tuple
from app.detection.condition_evaluator import ConditionEvaluator
from app.detection.exceptions import DetectionError
from app.detection.field_registry import FieldRegistry
from app.detection.rule_schema import AtomicCondition, ConditionGroup, DetectionRuleDefinition


class EventMatcher:
    """Evaluates declarative condition trees against individual normalized events."""

    @classmethod
    def evaluate_rule(
        cls,
        event: Dict[str, Any],
        rule: DetectionRuleDefinition,
    ) -> Tuple[bool, List[Dict[str, Any]], str]:
        """Evaluates a rule against an event.
        
        Returns:
            (is_match, matched_conditions_list, explanation_string)
        """
        matched_conditions: List[Dict[str, Any]] = []
        is_match = cls._evaluate_group(rule.conditions, event, matched_conditions)

        if is_match:
            explanation = (
                f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                f"Evaluated {len(matched_conditions)} conditions successfully on event {event.get('event_id')}."
            )
        else:
            explanation = (
                f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                f"Event {event.get('event_id')} did not satisfy configured criteria."
            )

        return is_match, matched_conditions, explanation

    @classmethod
    def _evaluate_group(
        cls,
        group: ConditionGroup,
        event: Dict[str, Any],
        matched_accumulator: List[Dict[str, Any]],
    ) -> bool:
        """Evaluates logical ALL / ANY group semantics."""
        # 1. Evaluate 'all' block (logical AND)
        if group.all:
            for item in group.all:
                if isinstance(item, ConditionGroup) or (isinstance(item, dict) and ("all" in item or "any" in item)):
                    sub_grp = item if isinstance(item, ConditionGroup) else ConditionGroup.model_validate(item)
                    if not cls._evaluate_group(sub_grp, event, matched_accumulator):
                        return False
                else:
                    cond = item if isinstance(item, AtomicCondition) else AtomicCondition.model_validate(item)
                    matched, diag = cls._evaluate_atomic(cond, event)
                    if not matched:
                        return False
                    matched_accumulator.append(diag)

        # 2. Evaluate 'any' block (logical OR)
        if group.any:
            any_matched = False
            temp_matches: List[Dict[str, Any]] = []
            for item in group.any:
                if isinstance(item, ConditionGroup) or (isinstance(item, dict) and ("all" in item or "any" in item)):
                    sub_grp = item if isinstance(item, ConditionGroup) else ConditionGroup.model_validate(item)
                    if cls._evaluate_group(sub_grp, event, temp_matches):
                        any_matched = True
                        break
                else:
                    cond = item if isinstance(item, AtomicCondition) else AtomicCondition.model_validate(item)
                    matched, diag = cls._evaluate_atomic(cond, event)
                    if matched:
                        temp_matches.append(diag)
                        any_matched = True
                        break
            if not any_matched:
                return False
            matched_accumulator.extend(temp_matches)

        return True

    @classmethod
    def _evaluate_atomic(
        cls,
        condition: AtomicCondition,
        event: Dict[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluates a single atomic condition and produces diagnostic telemetry."""
        field_name = condition.field.strip()
        actual_val = FieldRegistry.extract_value(event, field_name)

        matched = ConditionEvaluator.evaluate(
            field_value=actual_val,
            operator_str=condition.operator,
            expected_value=condition.value,
        )

        diag = {
            "field": field_name,
            "operator": condition.operator,
            "expected_value": condition.value,
            "actual_value": actual_val,
            "matched": matched,
        }
        return matched, diag

