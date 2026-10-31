"""FastAPI REST endpoints for SnareSight Activity Sessions and Investigation Timelines (Task P21)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.correlation.exceptions import SessionNotFoundError
from app.correlation.schemas import (
    ActivitySessionResponse,
    PaginatedSessionsResponse,
    SessionEventResponse,
    SessionStatisticsResponse,
    SessionTimelineResponse,
)
from app.correlation.service import CorrelationService

router = APIRouter(prefix="/sessions", tags=["Session Correlation"])


@router.get("", response_model=PaginatedSessionsResponse)
def list_sessions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    decoy_id: Optional[str] = Query(None, description="Filter by honeypot decoy ID (e.g. WEB-001)"),
    honeypot_type: Optional[str] = Query(None, description="Filter by decoy type (e.g. WEB_LOGIN)"),
    source_address: Optional[str] = Query(None, description="Filter by source IP address"),
    status: Optional[str] = Query(None, description="Filter by session status (ACTIVE, IDLE, CLOSED, TIMED_OUT)"),
    min_events: Optional[int] = Query(None, ge=1, description="Minimum number of correlated events"),
    has_detections: Optional[bool] = Query(None, description="Filter sessions having threat detections"),
    db: Session = Depends(get_db),
) -> PaginatedSessionsResponse:
    """Retrieves paginated, filtered activity sessions."""
    return CorrelationService.list_sessions(
        db=db,
        page=page,
        page_size=page_size,
        decoy_id=decoy_id,
        honeypot_type=honeypot_type,
        source_address=source_address,
        status=status,
        min_events=min_events,
        has_detections=has_detections,
    )


@router.get("/statistics", response_model=SessionStatisticsResponse)
def get_session_statistics(
    db: Session = Depends(get_db),
) -> SessionStatisticsResponse:
    """Returns aggregated operational and lifecycle metrics across all activity sessions."""
    return CorrelationService.get_statistics(db=db)


@router.get("/{session_id}", response_model=ActivitySessionResponse)
def get_session_details(
    session_id: str,
    db: Session = Depends(get_db),
) -> ActivitySessionResponse:
    """Retrieves detailed information and summary metrics for an activity session."""
    try:
        return CorrelationService.get_session(db=db, session_id=session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/{session_id}/timeline", response_model=SessionTimelineResponse)
def get_session_timeline(
    session_id: str,
    limit: int = Query(200, ge=1, le=500, description="Maximum timeline entries to return"),
    db: Session = Depends(get_db),
) -> SessionTimelineResponse:
    """Builds and returns a unified, chronological timeline of events, alerts, and ATT&CK mappings."""
    try:
        return CorrelationService.get_timeline(db=db, session_id=session_id, limit=limit)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/{session_id}/events", response_model=List[SessionEventResponse])
def get_session_events(
    session_id: str,
    db: Session = Depends(get_db),
) -> List[SessionEventResponse]:
    """Retrieves all normalized security events attached to an activity session."""
    try:
        return CorrelationService.get_session_events(db=db, session_id=session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/{session_id}/detections", response_model=List[Dict[str, Any]])
def get_session_detections(
    session_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Retrieves threat detection findings and alerts associated with an activity session."""
    try:
        return CorrelationService.get_session_detections(db=db, session_id=session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/{session_id}/mitre-mappings", response_model=List[Dict[str, Any]])
def get_session_mitre_mappings(
    session_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Retrieves ATT&CK technique mappings associated with an activity session."""
    try:
        return CorrelationService.get_session_mitre_mappings(db=db, session_id=session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)

