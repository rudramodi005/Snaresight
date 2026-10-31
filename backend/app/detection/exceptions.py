"""Domain-specific exceptions for SnareSight threat detection engine."""


class DetectionError(Exception):
    """Base exception for all detection engine errors."""
    pass


class RuleValidationError(DetectionError):
    """Raised when a detection rule definition violates schema or validation invariants."""

    def __init__(self, message: str, field: str | None = None, rule_id: str | None = None):
        super().__init__(message)
        self.field = field
        self.rule_id = rule_id


class InvalidOperatorError(RuleValidationError):
    """Raised when an unrecognized or unapproved operator is specified in a condition."""
    pass


class UnsupportedFieldError(RuleValidationError):
    """Raised when a rule condition targets a field not in the approved field registry."""
    pass


class RestrictedFieldError(RuleValidationError):
    """Raised when a rule condition attempts to access sensitive or prohibited fields."""
    pass


class ConditionEvaluationError(DetectionError):
    """Raised when condition evaluation encounters an unexpected runtime type error."""
    pass


class DuplicateRuleError(DetectionError):
    """Raised when attempting to register a duplicate rule version."""
    pass


class RuleNotFoundError(DetectionError):
    """Raised when a specified rule ID or version cannot be located."""
    pass


class ScoringPolicyError(DetectionError):
    """Base exception for scoring policy violations."""
    pass


class InvalidPolicyError(ScoringPolicyError):
    """Raised when a scoring policy definition violates schema or validation invariants."""
    pass


class AssessmentError(DetectionError):
    """Raised when threat assessment calculation encounters an unexpected error."""
    pass

