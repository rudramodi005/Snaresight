"""FastAPI REST Endpoints for Behavioral Sequences and Multi-Session Analysis (Task P22)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.correlation.sequence_schemas import (
    BehavioralSequenceDetailResponse,
    BehavioralSequenceResponse,
    PaginatedSequencesResponse,
    SequenceAssessmentRequest,
    SequenceEvidenceResponse,
    SequenceStatisticsResponse,
    SequenceStatusUpdateRequest,
    SequenceTimelineResponse,
)
from app.modules.correlation.sequence_service import SequenceService

router = APIRouter(prefix="/sequences", tags=["Behavioral Sequences"])


@router.get("", response_model=PaginatedSequencesResponse)
def list_sequences(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by lifecycle status (NEW, OBSERVING, UNDER_REVIEW, REVIEWED, CLOSED, DISMISSED)"),
    pattern: Optional[str] = Query(None, description="Filter by behavioral pattern type"),
    source_address: Optional[str] = Query(None, description="Filter by primary source IP"),
    decoy_id: Optional[str] = Query(None, description="Filter by primary decoy ID"),
    min_sessions: Optional[int] = Query(None, ge=1, description="Minimum number of correlated sessions"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100, description="Minimum correlation confidence"),
    min_relevance: Optional[int] = Query(None, ge=0, le=100, description="Minimum sequence relevance"),
    db: Session = Depends(get_db),
) -> PaginatedSequencesResponse:
    """Retrieves paginated, filtered multi-session behavioral sequence candidates."""
    return SequenceService.list_sequences(
        db=db,
        page=page,
        page_size=page_size,
        status=status,
        pattern=pattern,
        source_address=source_address,
        decoy_id=decoy_id,
        min_sessions=min_sessions,
        min_confidence=min_confidence,
        min_relevance=min_relevance,
    )


@router.get("/statistics", response_model=SequenceStatisticsResponse)
def get_sequence_statistics(
    db: Session = Depends(get_db),
) -> SequenceStatisticsResponse:
    """Returns aggregated operational and discovery statistics across all behavioral sequences."""
    return SequenceService.get_statistics(db=db)


@router.get("/{sequence_id}", response_model=BehavioralSequenceDetailResponse)
def get_sequence_details(
    sequence_id: str,
    db: Session = Depends(get_db),
) -> BehavioralSequenceDetailResponse:
    """Retrieves complete behavioral sequence detail with members, relationships, and evidence."""
    return SequenceService.get_sequence(db=db, sequence_id=sequence_id)


@router.get("/{sequence_id}/timeline", response_model=SequenceTimelineResponse)
def get_sequence_timeline(
    sequence_id: str,
    limit: int = Query(300, ge=1, le=1000, description="Maximum timeline entries to return"),
    db: Session = Depends(get_db),
) -> SequenceTimelineResponse:
    """Builds and returns a unified multi-session chronological timeline."""
    return SequenceService.get_sequence_timeline(db=db, sequence_id=sequence_id, limit=limit)


@router.get("/{sequence_id}/evidence", response_model=List[SequenceEvidenceResponse])
def get_sequence_evidence(
    sequence_id: str,
    db: Session = Depends(get_db),
) -> List[SequenceEvidenceResponse]:
    """Returns field-level evidence traces justifying sequence relationships."""
    return SequenceService.get_sequence_evidence(db=db, sequence_id=sequence_id)


@router.get("/{sequence_id}/sessions", response_model=List[Dict[str, Any]])
def get_sequence_sessions(
    sequence_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns referenced ActivitySession records attached to the sequence."""
    return SequenceService.get_sequence_sessions(db=db, sequence_id=sequence_id)


@router.get("/{sequence_id}/detections", response_model=List[Dict[str, Any]])
def get_sequence_detections(
    sequence_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns referenced detection findings associated with the sequence."""
    return SequenceService.get_sequence_detections(db=db, sequence_id=sequence_id)


@router.get("/{sequence_id}/mitre", response_model=List[Dict[str, Any]])
def get_sequence_mitre_mappings(
    sequence_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns referenced MITRE ATT&CK technique mappings associated with the sequence."""
    return SequenceService.get_sequence_mitre(db=db, sequence_id=sequence_id)


@router.post("/{sequence_id}/assessment", response_model=BehavioralSequenceResponse)
def record_analyst_assessment(
    sequence_id: str,
    req: SequenceAssessmentRequest,
    db: Session = Depends(get_db),
) -> BehavioralSequenceResponse:
    """Records an authorized analyst investigation assessment with required documented justification."""
    return SequenceService.record_assessment(
        db=db,
        sequence_id=sequence_id,
        req=req,
        analyst_id="analyst",
    )


@router.post("/{sequence_id}/status", response_model=BehavioralSequenceResponse)
def update_sequence_status(
    sequence_id: str,
    req: SequenceStatusUpdateRequest,
    db: Session = Depends(get_db),
) -> BehavioralSequenceResponse:
    """Transitions sequence lifecycle status with documented reason."""
    return SequenceService.update_status(
        db=db,
        sequence_id=sequence_id,
        req=req,
        actor_id="analyst",
    )

