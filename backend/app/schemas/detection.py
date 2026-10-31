"""Pydantic schemas for detection results, execution tracking, and evaluation statuses."""

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EvaluationStatus(str, Enum):
    """Lifecycle status of a detection rule evaluation."""
    MATCHED = "MATCHED"
    NO_MATCH = "NO_MATCH"
    SKIPPED = "SKIPPED"
    INVALID_RULE = "INVALID_RULE"
    UNSUPPORTED_EVENT = "UNSUPPORTED_EVENT"
    EVALUATION_ERROR = "EVALUATION_ERROR"


class DetectionResult(BaseModel):
    """Structured, explainable outcome of a detection rule evaluation."""
    detection_result_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    rule_version: str
    evaluated_event_id: str
    related_event_ids: List[str] = Field(default_factory=list)
    session_id: str
    decoy_id: str
    evaluation_status: EvaluationStatus
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    detection_explanation: str
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    engine_version: str = "1.0"
    provenance: Dict[str, Any] = Field(default_factory=dict)


class DetectionExecutionRecord(BaseModel):
    """Audit record capturing an individual rule evaluation execution."""
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    rule_version: str
    event_id: str
    execution_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    execution_status: EvaluationStatus
    processing_duration_ms: float
    result_reference: Optional[str] = None
    safe_error_category: Optional[str] = None

