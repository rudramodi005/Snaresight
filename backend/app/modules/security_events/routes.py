"""FastAPI REST endpoints for Security Events Explorer & Event Investigation (Task P27)."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, Path, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.security_events.schemas import (
    PaginatedSecurityEventsResponse,
    SecurityEventSummaryResponse,
    EventDetailResponse,
    EventRelationshipItem,
    EventProcessingStage,
    EventTimelineResponse,
    EventComparisonRequest,
    EventComparisonResponse,
    AddEventNoteRequest,
    UpdateEventReviewRequest,
    AssociateInvestigationRequest,
    EventAuditLogItem,
)
from app.modules.security_events.service import SecurityEventsService


router = APIRouter(prefix="/events", tags=["Security Events Explorer"])


@router.get(
    "",
    response_model=PaginatedSecurityEventsResponse,
    summary="List normalized security events with advanced multi-attribute filtering",
)
def list_security_events(
    start_time: Optional[datetime] = Query(None, description="Start observed timestamp"),
    end_time: Optional[datetime] = Query(None, description="End observed timestamp"),
    category: Optional[str] = Query(None, description="Filter by event category (e.g. AUTHENTICATION, RECONNAISSANCE)"),
    event_type: Optional[str] = Query(None, description="Filter by event type (e.g. LOGIN_ATTEMPT, PORT_SCAN)"),
    sensor_id: Optional[str] = Query(None, description="Filter by honeypot sensor decoy ID (e.g. WEB-001)"),
    protocol: Optional[str] = Query(None, description="Filter by network protocol (e.g. TCP, UDP)"),
    source_address: Optional[str] = Query(None, description="Filter by source IP address"),
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    detection_status: Optional[str] = Query(None, description="Filter by detection status: DETECTED or NORMAL"),
    outcome: Optional[str] = Query(None, description="Filter by outcome: SUCCESS, FAILURE, BLOCKED, ERROR"),
    severity: Optional[str] = Query(None, description="Filter by associated alert severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    search: Optional[str] = Query(None, description="Free text search term"),
    sort_by: str = Query("observed_at", description="Sort column: observed_at, event_type, source_address"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
) -> PaginatedSecurityEventsResponse:
    """Retrieves paginated normalized security events with server-side filtering and sorting."""
    service = SecurityEventsService(db)
    return service.list_events(
        start_time=start_time,
        end_time=end_time,
        category=category,
        event_type=event_type,
        sensor_id=sensor_id,
        protocol=protocol,
        source_address=source_address,
        session_id=session_id,
        detection_status=detection_status,
        outcome=outcome,
        severity=severity,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/summary",
    response_model=SecurityEventSummaryResponse,
    summary="Get aggregated event metrics and category breakdowns for page header",
)
def get_events_summary(
    start_time: Optional[datetime] = Query(None, description="Start timestamp"),
    end_time: Optional[datetime] = Query(None, description="End timestamp"),
    db: Session = Depends(get_db),
) -> SecurityEventSummaryResponse:
    """Computes summary statistics across all persisted normalized security events."""
    service = SecurityEventsService(db)
    return service.get_events_summary(start_time=start_time, end_time=end_time)


@router.get(
    "/search",
    response_model=PaginatedSecurityEventsResponse,
    summary="Fast search over security events",
)
def search_events(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
) -> PaginatedSecurityEventsResponse:
    """Searches security events by source address, event type, sensor, or session."""
    service = SecurityEventsService(db)
    return service.list_events(search=q, page_size=limit)


@router.post(
    "/compare",
    response_model=EventComparisonResponse,
    summary="Compare 2 to 5 events side-by-side",
)
def compare_security_events(
    request: EventComparisonRequest,
    db: Session = Depends(get_db),
) -> EventComparisonResponse:
    """Performs structured side-by-side comparison across safe normalized event fields."""
    service = SecurityEventsService(db)
    return service.compare_events(request.event_ids)


@router.get(
    "/{event_id}",
    response_model=EventDetailResponse,
    summary="Get full forensic event details, scrubbed payloads, relationships, and history",
)
def get_event_detail(
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> EventDetailResponse:
    """Fetches full event record with credential redaction, processing history, and audit log."""
    service = SecurityEventsService(db)
    return service.get_event_detail(event_id)


@router.get(
    "/{event_id}/relationships",
    response_model=List[EventRelationshipItem],
    summary="Get cross-subsystem correlation links for an event",
)
def get_event_relationships(
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> List[EventRelationshipItem]:
    """Resolves links to raw event, session, source profile, alerts, sequence, and investigation."""
    service = SecurityEventsService(db)
    return service.get_event_relationships(event_id)


@router.get(
    "/{event_id}/timeline",
    response_model=EventTimelineResponse,
    summary="Get chronological event timeline for the session or temporal context",
)
def get_event_timeline(
    event_id: str = Path(..., description="UUID or string event identifier"),
    window_minutes: int = Query(60, ge=5, le=1440, description="Temporal context window in minutes"),
    db: Session = Depends(get_db),
) -> EventTimelineResponse:
    """Assembles chronological event timeline in session or nearby temporal context."""
    service = SecurityEventsService(db)
    return service.get_event_timeline(event_id, window_minutes=window_minutes)


@router.get(
    "/{event_id}/processing-history",
    response_model=List[EventProcessingStage],
    summary="Get event ingestion and processing pipeline history",
)
def get_event_processing_history(
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> List[EventProcessingStage]:
    """Retrieves ingestion, validation, normalization, deduplication, and detection audit stages."""
    service = SecurityEventsService(db)
    detail = service.get_event_detail(event_id)
    return detail.processing_history


@router.get(
    "/{event_id}/evidence",
    summary="Get evidence provenance and collection metadata",
)
def get_event_evidence(
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Returns safe evidence provenance and deduplication fingerprint."""
    service = SecurityEventsService(db)
    detail = service.get_event_detail(event_id)
    return detail.evidence_provenance


@router.post(
    "/{event_id}/notes",
    response_model=EventAuditLogItem,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to a security event",
)
def add_event_note(
    request: AddEventNoteRequest,
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> EventAuditLogItem:
    """Records an immutable analyst note in the event audit log without modifying original evidence."""
    service = SecurityEventsService(db)
    return service.add_event_note(
        event_id=event_id,
        analyst_id=request.analyst_id,
        note=request.note,
    )


@router.post(
    "/{event_id}/review",
    response_model=EventAuditLogItem,
    summary="Update investigation review status of a security event",
)
def update_event_review(
    request: UpdateEventReviewRequest,
    event_id: str = Path(..., description="UUID or string event identifier"),
    db: Session = Depends(get_db),
) -> EventAuditLogItem:
    """Updates event review status (e.g. UNDER_REVIEW, REVIEWED, ESCALATED, DISMISSED) with audit trail."""
    service = SecurityEventsService(db)
    return service.update_event_review(
        event_id=event_id,
        analyst_id=request.analyst_id,
        review_status=request.review_status,
        note=request.note,
    )


@router.post(
    "/{event_id}/investigations/{cluster_id}",
    summary="Associate event with an existing investigation cluster",
)
def associate_event_with_investigation(
    event_id: str = Path(..., description="UUID or string event identifier"),
    cluster_id: str = Path(..., description="Target investigation cluster identifier"),
    request: Optional[AssociateInvestigationRequest] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Adds event to an investigation cluster with explicit reason and audit recording."""
    service = SecurityEventsService(db)
    analyst_id = request.analyst_id if request else "soc_lead"
    reason = request.reason if request else "Analyst linked event to investigation"
    return service.associate_with_investigation(
        event_id=event_id,
        cluster_id=cluster_id,
        analyst_id=analyst_id,
        reason=reason,
    )

