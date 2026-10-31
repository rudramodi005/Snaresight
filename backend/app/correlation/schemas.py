"""Pydantic schemas and enums for Session-Based Event Correlation and Timelines (Task P21)."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    """Operational lifecycle status of an activity session."""
    ACTIVE = "ACTIVE"
    IDLE = "IDLE"
    CLOSED = "CLOSED"
    TIMED_OUT = "TIMED_OUT"
    UNKNOWN = "UNKNOWN"


class CorrelationMethod(str, Enum):
    """Layered methodology used to synthesize or resolve session identity."""
    EXPLICIT_SESSION_ID = "EXPLICIT_SESSION_ID"
    EXPLICIT_CONNECTION_ID = "EXPLICIT_CONNECTION_ID"
    CONTEXTUAL_FALLBACK = "CONTEXTUAL_FALLBACK"
    STANDALONE = "STANDALONE"


class TimelineEntryType(str, Enum):
    """Categorical classification of timeline entries."""
    SESSION_STARTED = "SESSION_STARTED"
    CONNECTION_ESTABLISHED = "CONNECTION_ESTABLISHED"
    HTTP_REQUEST = "HTTP_REQUEST"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    DECOY_AUTHENTICATION_ACCEPTED = "DECOY_AUTHENTICATION_ACCEPTED"
    ENUMERATION_ACTIVITY = "ENUMERATION_ACTIVITY"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    DETECTION_GENERATED = "DETECTION_GENERATED"
    ATTACK_MAPPING_GENERATED = "ATTACK_MAPPING_GENERATED"
    ANALYST_REVIEW_ACTION = "ANALYST_REVIEW_ACTION"
    SESSION_IDLE = "SESSION_IDLE"
    SESSION_TIMEOUT = "SESSION_TIMEOUT"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"


# =============================================================================
# Session Response Schemas
# =============================================================================

class ActivitySessionSummary(BaseModel):
    """Compact summary of a correlated activity session."""
    session_id: str
    decoy_id: str
    honeypot_type: str
    source_address: str
    source_port: Optional[int] = None
    target_service: str
    protocol: str
    correlation_method: CorrelationMethod
    first_observed_at: str
    last_activity_at: str
    ended_at: Optional[str] = None
    session_status: SessionStatus
    event_count: int
    detection_count: int
    highest_severity: Optional[str] = None
    duration_seconds: Optional[float] = None


class ActivitySessionResponse(BaseModel):
    """Detailed activity session record."""
    session_id: str
    decoy_id: str
    honeypot_type: str
    explicit_session_id: Optional[str] = None
    connection_id: Optional[str] = None
    correlation_method: CorrelationMethod
    correlation_key: str
    source_address: str
    source_port: Optional[int] = None
    target_service: str
    protocol: str
    first_observed_at: str
    last_activity_at: str
    ended_at: Optional[str] = None
    first_ingested_at: str
    last_ingested_at: str
    session_status: SessionStatus
    event_count: int
    detection_count: int
    highest_severity: Optional[str] = None
    duration_seconds: Optional[float] = None
    correlation_policy_version: str
    metadata_summary: Dict[str, Any]
    created_at: str
    updated_at: Optional[str] = None


class PaginatedSessionsResponse(BaseModel):
    """Paginated collection of activity sessions."""
    total: int
    page: int
    page_size: int
    items: List[ActivitySessionSummary]


# =============================================================================
# Timeline Schemas
# =============================================================================

class TimelineEntryResponse(BaseModel):
    """Chronologically ordered item in an investigation timeline."""
    entry_id: str
    session_id: str
    source_record_id: str
    timestamp: str
    ingestion_timestamp: Optional[str] = None
    entry_type: TimelineEntryType
    title: str
    description: str
    component: str
    category: str
    severity: Optional[str] = None
    is_detection: bool = False
    is_late_arrival: bool = False
    related_detection_id: Optional[str] = None
    related_technique_id: Optional[str] = None
    related_mapping_id: Optional[str] = None
    mapping_status: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SessionTimelineResponse(BaseModel):
    """Complete chronological timeline for an activity session."""
    session_id: str
    decoy_id: str
    source_address: str
    total_entries: int
    first_observed_at: str
    last_activity_at: str
    session_status: SessionStatus
    entries: List[TimelineEntryResponse]


# =============================================================================
# Associated Events & Statistics
# =============================================================================

class SessionEventResponse(BaseModel):
    """Normalized security event reference attached to an activity session."""
    event_id: str
    raw_event_id: Optional[str] = None
    event_type: str
    event_category: str
    action: str
    outcome: str
    source_address: str
    target_service: str
    observed_at: str
    ingested_at: str
    association_method: str
    correlation_confidence: int
    is_late_arrival: bool
    sanitized_metadata: Dict[str, Any]


class SessionStatisticsResponse(BaseModel):
    """Aggregated operational metrics for correlated activity sessions."""
    total_sessions: int
    active_sessions: int
    idle_sessions: int
    closed_sessions: int
    timed_out_sessions: int
    sessions_with_detections: int
    total_events_correlated: int
    average_events_per_session: float
    by_honeypot: Dict[str, int]
    by_protocol: Dict[str, int]
    by_correlation_method: Dict[str, int]

