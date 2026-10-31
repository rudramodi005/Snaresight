"""FastAPI routes for Observed Source Profiles and Behavioral Intelligence (Task P23)."""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.source_intelligence.schemas import (
    SourceProfileResponse,
    SourceProfileListResponse,
    ProfileBehaviorResponse,
    ProfileTrendsResponse,
    SimilarProfileResponse,
    AddNoteRequest,
    UpdateAssociationRequest,
    AggregationTriggerRequest,
)
from app.modules.source_intelligence.service import SourceIntelligenceService


router = APIRouter(prefix="/source-profiles", tags=["Source Intelligence"])


@router.get("", response_model=SourceProfileListResponse)
def list_source_profiles(
    search: Optional[str] = Query(None, description="Search profile_id, display_label, or source_ip"),
    priority: Optional[str] = Query(None, description="Filter by priority: LOW, MEDIUM, HIGH, CRITICAL, INSUFFICIENT_DATA"),
    status: Optional[str] = Query(None, description="Filter by status: ACTIVE, DORMANT, ARCHIVED"),
    sort_by: str = Query("last_observed_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort direction: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
):
    """Lists observed source profiles with multi-attribute filtering and pagination."""
    service = SourceIntelligenceService(db)
    return service.list_profiles(
        search=search,
        priority=priority,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )


@router.post("/aggregate", status_code=status.HTTP_200_OK)
def trigger_aggregation(
    request: AggregationTriggerRequest = AggregationTriggerRequest(),
    db: Session = Depends(get_db),
):
    """Triggers on-demand profile aggregation and behavioral feature calculation."""
    service = SourceIntelligenceService(db)
    return service.trigger_aggregation(
        profile_id=request.profile_id,
        force_all=request.force_all,
    )


@router.get("/{profile_id}", response_model=SourceProfileResponse)
def get_source_profile(
    profile_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves an Observed Source Profile by profile identifier."""
    service = SourceIntelligenceService(db)
    p = service.get_profile(profile_id)
    return service._to_profile_response(p)


@router.get("/{profile_id}/sessions")
def get_profile_sessions(
    profile_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves correlated activity sessions linked to this observed source profile."""
    service = SourceIntelligenceService(db)
    return service.get_profile_sessions(profile_id, limit=limit, offset=offset)


@router.get("/{profile_id}/events")
def get_profile_events(
    profile_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves security telemetry events observed from this source IP."""
    service = SourceIntelligenceService(db)
    return service.get_profile_events(profile_id, limit=limit, offset=offset)


@router.get("/{profile_id}/alerts")
def get_profile_alerts(
    profile_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves detection alerts generated against this observed source profile."""
    service = SourceIntelligenceService(db)
    return service.get_profile_alerts(profile_id, limit=limit, offset=offset)


@router.get("/{profile_id}/behavior", response_model=ProfileBehaviorResponse)
def get_profile_behavior(
    profile_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves behavioral baselines, features across windows, recurrences, and history."""
    service = SourceIntelligenceService(db)
    return service.get_profile_behavior(profile_id)


@router.get("/{profile_id}/trends", response_model=ProfileTrendsResponse)
def get_profile_trends(
    profile_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves activity timelines and multi-window metrics for trend analysis."""
    service = SourceIntelligenceService(db)
    return service.get_profile_trends(profile_id)


@router.get("/{profile_id}/similar", response_model=list[SimilarProfileResponse])
def get_similar_profiles(
    profile_id: str,
    limit: int = Query(5, ge=1, le=20),
    min_similarity: float = Query(30.0, ge=0.0, le=100.0),
    db: Session = Depends(get_db),
):
    """Discovers behaviorally similar profiles with explainable contributing factors."""
    service = SourceIntelligenceService(db)
    return service.get_similar_profiles(profile_id, limit=limit, min_similarity=min_similarity)


@router.post("/{profile_id}/notes", status_code=status.HTTP_201_CREATED)
def add_analyst_note(
    profile_id: str,
    request: AddNoteRequest,
    db: Session = Depends(get_db),
):
    """Appends an analyst observation note and increments the note counter."""
    service = SourceIntelligenceService(db)
    return service.add_analyst_note(
        profile_id=profile_id,
        analyst_id=request.analyst_id,
        notes=request.notes,
    )


@router.post("/{profile_id}/association", response_model=SourceProfileResponse)
def update_profile_association(
    profile_id: str,
    request: UpdateAssociationRequest,
    db: Session = Depends(get_db),
):
    """Performs an analyst association review (e.g. flagging shared infrastructure or status change)."""
    service = SourceIntelligenceService(db)
    return service.update_association(profile_id, request)
