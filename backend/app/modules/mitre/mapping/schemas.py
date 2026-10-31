"""Pydantic schemas and enums for MITRE ATT&CK detection mapping (Task P20)."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MappingCategory(str, Enum):
    """Assessment category characterizing the evidential foundation of the mapping."""
    DIRECTLY_SUPPORTED = "DIRECTLY_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    REQUIRES_ANALYST_REVIEW = "REQUIRES_ANALYST_REVIEW"
    NOT_MAPPED = "NOT_MAPPED"


class MappingConfidenceLevel(str, Enum):
    """Categorical confidence rating derived from evidential correlation."""
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class ReviewStatus(str, Enum):
    """State transition lifecycle for human analyst reviews."""
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


class ReviewAction(str, Enum):
    """Valid actions an analyst can execute during mapping review."""
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"


# =============================================================================
# Definition Schemas
# =============================================================================

class MappingDefinitionSchema(BaseModel):
    """Curated definition specifying how a detection rule maps to ATT&CK techniques."""
    mapping_definition_id: str = Field(..., description="Unique definition identifier e.g. MAP-AUTH-001-T1110")
    rule_id: str = Field(..., description="Target SnareSight detection rule ID")
    rule_version_range: str = Field(default=">=1.0", description="Compatible rule version specification")
    technique_id: str = Field(..., description="Official ATT&CK external technique ID e.g. T1110")
    subtechnique_id: Optional[str] = Field(None, description="Optional sub-technique ID e.g. T1110.001")
    dataset_domain: str = Field(default="enterprise-attack", description="Framework domain")
    mapping_category: MappingCategory = Field(..., description="Evidential support category")
    default_confidence: int = Field(ge=0, le=100, description="Base confidence score")
    required_evidence_fields: List[str] = Field(default_factory=list, description="Mandatory event fields")
    optional_evidence_fields: List[str] = Field(default_factory=list, description="Corroborating event fields")
    exclusion_conditions: Dict[str, Any] = Field(default_factory=dict, description="Conditions disqualifying mapping")
    mapping_rationale: str = Field(..., description="Technical justification and operational caveats")
    version: str = Field(default="1.0", description="Mapping definition version")
    documentation_reference: Optional[str] = Field(None, description="Link or doc reference")
    is_active: bool = Field(default=True, description="Active status")


# =============================================================================
# Evidence Association Schema
# =============================================================================

class MappingEvidenceResponse(BaseModel):
    """Safe structured summary of supporting event evidence."""
    id: str
    mapping_id: str
    event_id: Optional[str] = None
    evidence_type: str
    evidence_description: str
    evidence_fields: Dict[str, Any]
    relevance_score: int
    evidence_timestamp: str
    provenance: Optional[Dict[str, Any]] = None
    created_at: str


# =============================================================================
# Detection Mapping Records
# =============================================================================

class DetectionMappingResponse(BaseModel):
    """Complete representation of an evidence-backed ATT&CK mapping record."""
    mapping_id: str
    detection_result_id: str
    alert_id: Optional[str] = None
    rule_id: str
    rule_version: str
    technique_id: str
    technique_name: Optional[str] = None
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    dataset_version: str
    mapping_definition_id: str
    mapping_definition_version: str
    mapping_category: MappingCategory
    mapping_confidence: int
    mapping_confidence_level: MappingConfidenceLevel
    confidence_explanation: str
    mapping_rationale: str
    review_status: ReviewStatus
    review_comment: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    assessed_at: str
    created_at: str
    updated_at: Optional[str] = None
    evidence: List[MappingEvidenceResponse] = Field(default_factory=list)


class PaginatedMappingsResponse(BaseModel):
    """Paginated list of detection mapping records."""
    total: int
    page: int
    page_size: int
    items: List[DetectionMappingResponse]


# =============================================================================
# Review Request & Response
# =============================================================================

class MappingReviewRequest(BaseModel):
    """Payload for submitting an analyst review action."""
    action: ReviewAction
    comment: str = Field(..., min_length=3, max_length=1000, description="Justification for the review action")


class MappingReviewResponse(BaseModel):
    """Outcome of an analyst review transaction."""
    mapping_id: str
    action: ReviewAction
    previous_status: ReviewStatus
    new_status: ReviewStatus
    reviewed_by: str
    reviewed_at: str
    comment: str


# =============================================================================
# Audit History & Statistics
# =============================================================================

class MappingHistoryResponse(BaseModel):
    """Historical audit entry for state and confidence transitions."""
    id: str
    mapping_id: str
    change_reason: str
    previous_confidence: Optional[int] = None
    new_confidence: int
    previous_status: Optional[str] = None
    new_status: str
    policy_version: str
    dataset_version: str
    details: Optional[Dict[str, Any]] = None
    recorded_at: str


class MappingStatisticsResponse(BaseModel):
    """Aggregated operational statistics across active mapping records."""
    total_mappings: int
    directly_supported: int
    partially_supported: int
    requires_analyst_review: int
    not_mapped_count: int
    pending_reviews: int
    accepted_mappings: int
    rejected_mappings: int
    needs_more_evidence_mappings: int
    by_confidence_level: Dict[str, int]
    by_tactic: Dict[str, int]
    by_technique: Dict[str, int]

