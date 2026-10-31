"""Structured data models for threat assessments, manual analyst reviews, and audit history."""

from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from app.detection.scoring_policy import SeverityLevel, ConfidenceLevel, EvidenceStrength


class AnalystReview(BaseModel):
    """Encapsulates human analyst review without overwriting automated assessments."""
    reviewed: bool = False
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[str] = None
    proposed_severity: Optional[SeverityLevel] = None
    proposed_confidence: Optional[int] = Field(None, ge=0, le=100)
    review_reason: Optional[str] = None
    approval_status: str = "PENDING"  # PENDING, APPROVED, REJECTED


class ThreatAssessmentResult(BaseModel):
    """Explainable, evidence-backed threat assessment for a detection result."""
    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    detection_result_id: str
    rule_id: str
    rule_version: str
    severity_level: SeverityLevel
    severity_score: int = Field(..., ge=0, le=100)
    confidence_score: int = Field(..., ge=0, le=100)
    confidence_level: ConfidenceLevel
    evidence_strength: EvidenceStrength
    severity_explanation: str
    confidence_explanation: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    scoring_policy_id: str
    scoring_policy_version: str
    assessed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assessment_version: int = 1
    analyst_review: Optional[AnalystReview] = None


class AssessmentHistoryRecord(BaseModel):
    """Audit entry documenting changes, reassessments, or reviews of threat assessments."""
    history_id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str
    assessment_version: int
    previous_severity: SeverityLevel
    updated_severity: SeverityLevel
    previous_confidence: int
    updated_confidence: int
    reason: str
    initiator: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

