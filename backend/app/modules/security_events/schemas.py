"""Pydantic schemas for Security Events Explorer & Advanced Event Investigation (Task P27).

Defines typed request and response models for event search, filtering, server-side pagination,
forensic detail inspection, credential-redacted payloads, correlation relationships,
chronological session timelines, multi-event comparison, and analyst audit actions.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


ReviewStatusLiteral = Literal["UNREVIEWED", "UNDER_REVIEW", "REVIEWED", "ESCALATED", "DISMISSED"]
DetectionStatusLiteral = Literal["DETECTED", "NORMAL"]


class SecurityEventItem(BaseModel):
    """Normalized security event table row representation."""
    event_id: str
    raw_event_id: str
    timestamp: str  # ISO UTC
    event_category: str
    event_type: str
    action: str
    outcome: str
    sensor_id: str
    protocol: str
    session_id: str
    source_address: str
    source_port: Optional[int] = None
    target_service: str
    target_port: int
    detection_status: DetectionStatusLiteral
    has_alerts: bool
    alerts_count: int
    highest_alert_severity: Optional[str] = None
    review_status: ReviewStatusLiteral = "UNREVIEWED"
    investigation_cluster_id: Optional[str] = None
    investigation_code: Optional[str] = None


class PaginatedSecurityEventsResponse(BaseModel):
    """Paginated list of normalized security events."""
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[SecurityEventItem]


class SecurityEventSummaryResponse(BaseModel):
    """Aggregate statistics for Security Events Explorer header metrics."""
    total_events: int
    detected_events: int
    clean_events: int
    distinct_sources: int
    distinct_sensors: int
    categories_breakdown: Dict[str, int]
    sensors_breakdown: Dict[str, int]
    outcomes_breakdown: Dict[str, int]


class EventRelationshipItem(BaseModel):
    """Relationship link connecting an event to correlated platform entities."""
    entity_type: str  # SESSION, SOURCE_PROFILE, ALERT, BEHAVIORAL_SEQUENCE, INVESTIGATION_CLUSTER, RAW_EVENT, MITRE_TECHNIQUE
    entity_id: str
    relationship_type: str  # SAME_SESSION, OBSERVED_SOURCE, TRIGGERING_EVIDENCE, ATTACK_STEP, INVESTIGATION_MEMBER, ORIGINAL_CAPTURE
    label: str
    description: str
    severity: Optional[str] = None
    confidence: Optional[int] = None
    navigation_url: Optional[str] = None


class EventProcessingStage(BaseModel):
    """Audit entry documenting an event ingestion/processing stage."""
    stage: str
    timestamp: str
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)


class EventAuditLogItem(BaseModel):
    """Audit record of analyst notes, status reviews, or investigation links."""
    id: str
    action_type: str
    analyst_id: str
    review_status: str
    notes: Optional[str] = None
    created_at: str
    extra_data: Dict[str, Any] = Field(default_factory=dict)


class EventDetailResponse(BaseModel):
    """Complete forensic inspection record for a normalized security event."""
    overview: SecurityEventItem
    normalized_payload: Dict[str, Any]
    provenance: Dict[str, Any]
    relationships: List[EventRelationshipItem]
    processing_history: List[EventProcessingStage]
    evidence_provenance: Dict[str, Any]
    audit_logs: List[EventAuditLogItem]


class EventTimelineEntry(BaseModel):
    """Chronological event entry in a session or temporal investigation timeline."""
    event_id: str
    timestamp: str
    event_category: str
    event_type: str
    action: str
    outcome: str
    sensor_id: str
    source_address: str
    is_current_event: bool = False
    relationship_context: str  # SAME_SESSION, TEMPORAL_CONTEXT_ONLY
    has_alert: bool = False
    alert_severity: Optional[str] = None
    alert_title: Optional[str] = None


class EventTimelineResponse(BaseModel):
    """Chronological event timeline for the session or window surrounding an event."""
    event_id: str
    session_id: Optional[str] = None
    context_type: str  # SESSION_TIMELINE or TEMPORAL_TIMELINE
    total_events: int
    timeline: List[EventTimelineEntry]


class EventComparisonRequest(BaseModel):
    """Request to compare 2 to 5 events side-by-side."""
    event_ids: List[str] = Field(..., min_length=2, max_length=5)


class EventComparisonField(BaseModel):
    """Attribute comparison across multiple events."""
    field_name: str
    is_match: bool
    values_by_event_id: Dict[str, Any]


class EventComparisonResponse(BaseModel):
    """Side-by-side comparison matrix of normalized security events."""
    compared_event_ids: List[str]
    matching_fields_count: int
    differing_fields_count: int
    fields: List[EventComparisonField]
    caveat_notice: str = "Similarities in observed network attributes do not prove common real-world human attribution or threat actor identity."


class AddEventNoteRequest(BaseModel):
    """Request to attach an analyst note to a security event."""
    note: str = Field(..., min_length=1, max_length=2000)
    analyst_id: str = Field("soc_lead", min_length=1, max_length=128)


class UpdateEventReviewRequest(BaseModel):
    """Request to update an event's investigation review status."""
    review_status: ReviewStatusLiteral
    note: Optional[str] = Field(None, max_length=2000)
    analyst_id: str = Field("soc_lead", min_length=1, max_length=128)


class AssociateInvestigationRequest(BaseModel):
    """Request to associate an event with an existing investigation cluster."""
    cluster_id: str = Field(..., min_length=1, max_length=64)
    reason: str = Field("Analyst correlated event with investigation cluster", min_length=1, max_length=500)
    analyst_id: str = Field("soc_lead", min_length=1, max_length=128)

