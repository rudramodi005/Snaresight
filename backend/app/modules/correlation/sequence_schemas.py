"""Pydantic schemas and enums for Behavioral Sequences and Multi-Session Correlation (Task P22)."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SequenceLifecycleStatus(str, Enum):
    """Lifecycle states for behavioral attack-chain candidates."""
    NEW = "NEW"
    OBSERVING = "OBSERVING"
    UNDER_REVIEW = "UNDER_REVIEW"
    REVIEWED = "REVIEWED"
    CLOSED = "CLOSED"
    DISMISSED = "DISMISSED"


class SequenceAnalystReviewStatus(str, Enum):
    """Analyst investigation conclusions."""
    UNREVIEWED = "UNREVIEWED"
    CONFIRMED_PROGRESSION = "CONFIRMED_PROGRESSION"
    DISMISSED_COINCIDENCE = "DISMISSED_COINCIDENCE"
    INCONCLUSIVE = "INCONCLUSIVE"


class SequencePatternType(str, Enum):
    """Recognized multi-session behavioral progression patterns."""
    REPEATED_AUTHENTICATION = "REPEATED_AUTHENTICATION"
    AUTH_THEN_ENUMERATION = "AUTH_THEN_ENUMERATION"
    ENUMERATION_THEN_EXPLOIT = "ENUMERATION_THEN_EXPLOIT"
    MULTI_TECHNIQUE_PROGRESSION = "MULTI_TECHNIQUE_PROGRESSION"
    RECURRING_HONEYPOT_TARGET = "RECURRING_HONEYPOT_TARGET"
    CROSS_PROTOCOL_INTERACTION = "CROSS_PROTOCOL_INTERACTION"


class SequenceMemberType(str, Enum):
    """Classification of sequence member entities."""
    SESSION = "SESSION"
    EVENT = "EVENT"
    DETECTION = "DETECTION"
    ATTACK_MAPPING = "ATTACK_MAPPING"


class SequenceRelationshipType(str, Enum):
    """Semantic directed relationships between sequence members."""
    OBSERVED_BEFORE = "OBSERVED_BEFORE"
    SAME_TRUSTED_INTERACTION = "SAME_TRUSTED_INTERACTION"
    SHARED_SOURCE_CONTEXT = "SHARED_SOURCE_CONTEXT"
    BEHAVIORALLY_SIMILAR = "BEHAVIORALLY_SIMILAR"
    RELATED_DETECTION_PATTERN = "RELATED_DETECTION_PATTERN"
    ANALYST_LINKED = "ANALYST_LINKED"


# =============================================================================
# Member, Relationship & Evidence Responses
# =============================================================================

class SequenceMemberResponse(BaseModel):
    """Associated member record within a behavioral sequence."""
    id: str
    sequence_id: str
    member_type: SequenceMemberType
    member_record_id: str
    sequence_position: int
    observed_at: str
    relationship_reason: str
    correlation_method: str
    created_at: str


class SequenceRelationshipResponse(BaseModel):
    """Directed relationship connecting two sequence members."""
    id: str
    sequence_id: str
    source_member_id: str
    target_member_id: str
    relationship_type: SequenceRelationshipType
    explanation: str
    confidence_score: int
    evidence_payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class SequenceEvidenceResponse(BaseModel):
    """Supporting field-level evidence record."""
    id: str
    sequence_id: str
    evidence_record_type: str
    evidence_record_id: str
    field_name: str
    field_value: str
    evidence_provenance: Dict[str, Any] = Field(default_factory=dict)
    observed_at: str
    created_at: str


class SequenceHistoryResponse(BaseModel):
    """Audit entry for lifecycle transitions and analyst reviews."""
    id: str
    sequence_id: str
    assessed_by: str
    previous_status: Optional[str] = None
    new_status: str
    assessment_action: str
    assessment_notes: Optional[str] = None
    policy_version: str
    timestamp: str


# =============================================================================
# Behavioral Sequence Master Schemas
# =============================================================================

class BehavioralSequenceResponse(BaseModel):
    """Core summary representation of a behavioral sequence."""
    sequence_id: str
    title: str
    sequence_pattern: SequencePatternType
    description: str
    lifecycle_status: SequenceLifecycleStatus
    first_observed_at: str
    last_observed_at: str
    session_count: int
    event_count: int
    detection_count: int
    correlation_confidence: int
    sequence_relevance: int
    aggregate_severity: Optional[str] = None
    analyst_review_status: SequenceAnalystReviewStatus
    primary_source_address: Optional[str] = None
    primary_decoy_id: Optional[str] = None
    correlation_policy_version: str
    metadata_summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: Optional[str] = None


class BehavioralSequenceDetailResponse(BehavioralSequenceResponse):
    """Comprehensive detail representation including graph members and evidence."""
    members: List[SequenceMemberResponse] = Field(default_factory=list)
    relationships: List[SequenceRelationshipResponse] = Field(default_factory=list)
    evidence_items: List[SequenceEvidenceResponse] = Field(default_factory=list)
    history_records: List[SequenceHistoryResponse] = Field(default_factory=list)


class PaginatedSequencesResponse(BaseModel):
    """Paginated collection of behavioral sequences."""
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[BehavioralSequenceResponse]


# =============================================================================
# Timeline Schemas
# =============================================================================

class SequenceTimelineEntryResponse(BaseModel):
    """Chronologically sorted timeline observation across multiple sessions."""
    entry_id: str
    sequence_id: str
    member_type: SequenceMemberType
    member_record_id: str
    timestamp: str
    title: str
    description: str
    category: str
    severity: Optional[str] = None
    session_id: Optional[str] = None
    decoy_id: Optional[str] = None
    technique_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class SequenceTimelineResponse(BaseModel):
    """Chronological multi-session timeline for SOC investigation."""
    sequence_id: str
    title: str
    total_entries: int
    first_observed_at: str
    last_observed_at: str
    entries: List[SequenceTimelineEntryResponse]


# =============================================================================
# Mutation Requests
# =============================================================================

class SequenceAssessmentRequest(BaseModel):
    """Analyst review request payload."""
    assessment_action: str = Field(..., description="Action: CONFIRM, DISMISS, INCONCLUSIVE")
    review_notes: str = Field(..., min_length=5, description="Documented justification for analyst conclusion")
    new_status: Optional[SequenceLifecycleStatus] = Field(None, description="Optional lifecycle status transition")


class SequenceStatusUpdateRequest(BaseModel):
    """Direct lifecycle status transition request."""
    new_status: SequenceLifecycleStatus
    reason: str = Field(..., min_length=3, description="Justification for status change")


# =============================================================================
# Statistics
# =============================================================================

class SequenceStatisticsResponse(BaseModel):
    """Operational and discovery metrics across behavioral sequences."""
    total_sequences: int
    new_sequences: int
    observing_sequences: int
    under_review_sequences: int
    reviewed_sequences: int
    dismissed_sequences: int
    closed_sequences: int
    average_sessions_per_sequence: float
    by_pattern: Dict[str, int]
    by_severity: Dict[str, int]
    by_review_status: Dict[str, int]

