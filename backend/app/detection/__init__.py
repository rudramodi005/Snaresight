"""SnareSight Detection Engine package exports."""

from app.detection.engine import DetectionEngine, detection_engine
from app.detection.registry import RuleRegistry, rule_registry
from app.detection.rule_schema import (
    DetectionRuleDefinition,
    AtomicCondition,
    ConditionGroup,
    EvaluationMode,
    DetectionType,
    RuleSeverity,
    RuleStatus,
)
from app.detection.rule_validator import RuleValidator
from app.detection.field_registry import FieldRegistry, FieldSensitivity, FieldDefinition
from app.detection.condition_evaluator import ConditionEvaluator, Operator
from app.detection.event_matcher import EventMatcher
from app.detection.execution_tracker import ExecutionTracker, execution_tracker
from app.detection.result_builder import ResultBuilder
from app.detection.session_evaluator import SessionEvaluator
from app.detection.window_evaluator import TimeWindowEvaluator
from app.detection.scoring_policy import (
    SeverityLevel,
    ConfidenceLevel,
    EvidenceStrength,
    ProvenanceType,
    ConfidenceWeights,
    ScoringPolicyDefinition,
    ScoringPolicyRegistry,
    scoring_policy_registry,
)
from app.detection.severity_assessor import SeverityAssessor
from app.detection.confidence_scorer import ConfidenceScorer
from app.detection.evidence_assessor import EvidenceAssessor
from app.detection.assessment_result import (
    ThreatAssessmentResult,
    AnalystReview,
    AssessmentHistoryRecord,
)
from app.detection.exceptions import (
    DetectionError,
    RuleValidationError,
    InvalidOperatorError,
    UnsupportedFieldError,
    RestrictedFieldError,
    ConditionEvaluationError,
    DuplicateRuleError,
    RuleNotFoundError,
    ScoringPolicyError,
    InvalidPolicyError,
    AssessmentError,
)

__all__ = [
    "DetectionEngine",
    "detection_engine",
    "RuleRegistry",
    "rule_registry",
    "DetectionRuleDefinition",
    "AtomicCondition",
    "ConditionGroup",
    "EvaluationMode",
    "DetectionType",
    "RuleSeverity",
    "RuleStatus",
    "RuleValidator",
    "FieldRegistry",
    "FieldSensitivity",
    "FieldDefinition",
    "ConditionEvaluator",
    "Operator",
    "EventMatcher",
    "ExecutionTracker",
    "execution_tracker",
    "ResultBuilder",
    "SessionEvaluator",
    "TimeWindowEvaluator",
    "SeverityLevel",
    "ConfidenceLevel",
    "EvidenceStrength",
    "ProvenanceType",
    "ConfidenceWeights",
    "ScoringPolicyDefinition",
    "ScoringPolicyRegistry",
    "scoring_policy_registry",
    "SeverityAssessor",
    "ConfidenceScorer",
    "EvidenceAssessor",
    "ThreatAssessmentResult",
    "AnalystReview",
    "AssessmentHistoryRecord",
    "DetectionError",
    "RuleValidationError",
    "InvalidOperatorError",
    "UnsupportedFieldError",
    "RestrictedFieldError",
    "ConditionEvaluationError",
    "DuplicateRuleError",
    "RuleNotFoundError",
    "ScoringPolicyError",
    "InvalidPolicyError",
    "AssessmentError",
]
