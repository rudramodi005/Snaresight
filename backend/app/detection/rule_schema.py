"""Pydantic schemas for declarative SnareSight detection rules and conditions."""

from enum import Enum
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


class EvaluationMode(str, Enum):
    """Execution scope for detection rules."""
    EVENT = "EVENT"
    SESSION = "SESSION"
    TIME_WINDOW = "TIME_WINDOW"


class DetectionType(str, Enum):
    """Categorization of detection logic."""
    SINGLE_EVENT = "SINGLE_EVENT"
    THRESHOLD = "THRESHOLD"
    CORRELATION = "CORRELATION"


class RuleSeverity(str, Enum):
    """Default severity assignment for rule detections."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleStatus(str, Enum):
    """Operational lifecycle state of a detection rule."""
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DRAFT = "DRAFT"


class AtomicCondition(BaseModel):
    """Single field comparison condition."""
    field: str = Field(..., description="Target event field from FieldRegistry")
    operator: str = Field(..., description="Allowlisted comparison operator")
    value: Optional[Any] = Field(None, description="Expected literal operand")


class ConditionGroup(BaseModel):
    """Logical grouping of conditions with ALL / ANY evaluation semantics."""
    all: Optional[List[Union[AtomicCondition, "ConditionGroup"]]] = Field(
        None, description="All child conditions must match (logical AND)"
    )
    any: Optional[List[Union[AtomicCondition, "ConditionGroup"]]] = Field(
        None, description="At least one child condition must match (logical OR)"
    )


class ThresholdConfiguration(BaseModel):
    """Configuration for threshold-based counting rules."""
    threshold: int = Field(..., ge=1, le=10000, description="Minimum count to trigger match")
    group_by: Optional[List[str]] = Field(default_factory=lambda: ["session_id"], description="Fields to group count")


class DetectionRuleDefinition(BaseModel):
    """Complete declarative specification of a SnareSight detection rule."""
    rule_id: str = Field(..., min_length=3, max_length=64, description="Stable rule identifier")
    rule_name: str = Field(..., min_length=3, max_length=128, description="Human-readable rule name")
    rule_version: str = Field("1.0", min_length=1, max_length=16, description="SemVer or monotonic rule version")
    description: str = Field(..., min_length=5, max_length=2000, description="Purpose and threat rationale")
    category: str = Field(..., min_length=3, max_length=64, description="Security category")
    subcategory: Optional[str] = Field(None, max_length=64)
    detection_type: DetectionType = Field(default=DetectionType.SINGLE_EVENT)
    enabled: bool = Field(default=True, description="Whether rule evaluates active telemetry")
    rule_status: RuleStatus = Field(default=RuleStatus.ACTIVE)
    evaluation_mode: EvaluationMode = Field(default=EvaluationMode.EVENT)
    conditions: ConditionGroup = Field(..., description="Root condition tree")
    threshold_configuration: Optional[ThresholdConfiguration] = None
    time_window_seconds: Optional[int] = Field(None, ge=1, le=86400, description="Time window for aggregation")
    severity_default: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = "system"
    updated_by: Optional[str] = "system"
    rule_source: Optional[str] = "builtin"
    schema_version: str = Field("1.0", description="Contract version of the rule schema")

