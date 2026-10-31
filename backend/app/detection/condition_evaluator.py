"""Deterministic condition evaluation engine for SnareSight detection rules.

Evaluates field values against configured operands using an explicit allowlist
of safe operators. Prohibits any dynamic execution (eval, exec, SQL, shell).
"""

from enum import Enum
from typing import Any, List, Union
from app.detection.exceptions import InvalidOperatorError, ConditionEvaluationError


class Operator(str, Enum):
    """Explicitly supported, safe evaluation operators."""
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    GREATER_THAN = "GREATER_THAN"
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"
    IN = "IN"
    NOT_IN = "NOT_IN"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"


class ConditionEvaluator:
    """Safe, deterministic evaluator for atomic rule conditions."""

    @classmethod
    def evaluate(cls, field_value: Any, operator_str: str, expected_value: Any) -> bool:
        """Evaluates an atomic condition against a field value."""
        try:
            op = Operator(operator_str.upper())
        except (ValueError, AttributeError):
            raise InvalidOperatorError(f"Unsupported detection operator: '{operator_str}'")

        try:
            return cls._apply_operator(field_value, op, expected_value)
        except TypeError as exc:
            raise ConditionEvaluationError(
                f"Type error during evaluation of operator '{op.value}': {str(exc)}"
            )

    @classmethod
    def _apply_operator(cls, actual: Any, op: Operator, expected: Any) -> bool:
        """Applies operator deterministically with type-safe semantics."""
        # 1. Existence Operators (value may be None)
        if op == Operator.EXISTS:
            return actual is not None and actual != ""
        if op == Operator.NOT_EXISTS:
            return actual is None or actual == ""

        # If actual value is None for non-existence operators, default to False
        if actual is None:
            return False

        # 2. Equality Operators
        if op == Operator.EQUALS:
            if isinstance(actual, str) and isinstance(expected, str):
                return actual.lower() == expected.lower()
            return actual == expected

        if op == Operator.NOT_EQUALS:
            if isinstance(actual, str) and isinstance(expected, str):
                return actual.lower() != expected.lower()
            return actual != expected

        # 3. String Operators
        if op == Operator.CONTAINS:
            if not isinstance(actual, (str, list, tuple)):
                return False
            if isinstance(actual, str) and isinstance(expected, str):
                return expected.lower() in actual.lower()
            if isinstance(actual, (list, tuple)):
                return expected in actual
            return False

        if op == Operator.STARTS_WITH:
            if not (isinstance(actual, str) and isinstance(expected, str)):
                return False
            return actual.lower().startswith(expected.lower())

        if op == Operator.ENDS_WITH:
            if not (isinstance(actual, str) and isinstance(expected, str)):
                return False
            return actual.lower().endswith(expected.lower())

        # 4. Numeric Comparison Operators
        if op == Operator.GREATER_THAN:
            return float(actual) > float(expected)

        if op == Operator.GREATER_THAN_OR_EQUAL:
            return float(actual) >= float(expected)

        if op == Operator.LESS_THAN:
            return float(actual) < float(expected)

        if op == Operator.LESS_THAN_OR_EQUAL:
            return float(actual) <= float(expected)

        # 5. Set Membership Operators
        if op == Operator.IN:
            if not isinstance(expected, (list, set, tuple)):
                return False
            if isinstance(actual, str):
                return actual.lower() in [str(x).lower() for x in expected]
            return actual in expected

        if op == Operator.NOT_IN:
            if not isinstance(expected, (list, set, tuple)):
                return False
            if isinstance(actual, str):
                return actual.lower() not in [str(x).lower() for x in expected]
            return actual not in expected

        raise InvalidOperatorError(f"Unhandled operator: {op}")

