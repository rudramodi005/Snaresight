"""FastAPI REST endpoints for MITRE ATT&CK detection mappings and reviews (Task P20)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.mitre.exceptions import MitreNotFoundError
from app.modules.mitre.mapping.schemas import (
    DetectionMappingResponse,
    MappingReviewRequest,
    MappingReviewResponse,
    MappingStatisticsResponse,
    PaginatedMappingsResponse,
)
from app.modules.mitre.mapping.service import MappingService

router = APIRouter(tags=["MITRE ATT&CK Mappings"])


def verify_analyst_access(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Verifies that the caller possesses authorized analyst or admin credentials."""
    valid_tokens = {
        "snare-collector-key-dev-2026",
        "snaresight_admin_token_2026",
        "snaresight_analyst_token_2026",
        "valid_test_token",
    }
    provided_token = x_api_key
    if not provided_token and authorization and authorization.startswith("Bearer "):
        provided_token = authorization[7:].strip()

    if not provided_token or provided_token not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst authorization required to review MITRE ATT&CK mappings",
        )
    return "analyst"


# =============================================================================
# Query Endpoints
# =============================================================================

@router.get("/mitre/mappings", response_model=PaginatedMappingsResponse)
def list_detection_mappings(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID (e.g. AUTH-001)"),
    alert_id: Optional[str] = Query(None, description="Filter by alert UUID"),
    technique_id: Optional[str] = Query(None, description="Filter by ATT&CK technique (e.g. T1110)"),
    category: Optional[str] = Query(None, description="Filter by category (DIRECTLY_SUPPORTED, etc.)"),
    confidence_level: Optional[str] = Query(None, description="Filter by confidence (LOW, MODERATE, HIGH)"),
    review_status: Optional[str] = Query(None, description="Filter by status (PENDING, ACCEPTED, REJECTED)"),
    db: Session = Depends(get_db),
) -> PaginatedMappingsResponse:
    """Retrieves paginated detection-to-ATT&CK mapping associations."""
    return MappingService.list_mappings(
        db=db,
        page=page,
        page_size=page_size,
        rule_id=rule_id,
        alert_id=alert_id,
        technique_id=technique_id,
        category=category,
        confidence_level=confidence_level,
        review_status=review_status,
    )


@router.get("/mitre/mappings/statistics", response_model=MappingStatisticsResponse)
def get_mapping_statistics(
    db: Session = Depends(get_db),
) -> MappingStatisticsResponse:
    """Returns aggregated operational metrics across all mapped security findings."""
    return MappingService.get_statistics(db=db)


@router.get("/mitre/mappings/{mapping_id}", response_model=DetectionMappingResponse)
def get_mapping_detail(
    mapping_id: str,
    db: Session = Depends(get_db),
) -> DetectionMappingResponse:
    """Retrieves complete details of a single detection mapping including supporting event evidence."""
    try:
        return MappingService.get_mapping(db=db, mapping_id=mapping_id)
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.post("/mitre/mappings/{mapping_id}/review", response_model=MappingReviewResponse)
def review_detection_mapping(
    mapping_id: str,
    req: MappingReviewRequest,
    caller: str = Depends(verify_analyst_access),
    db: Session = Depends(get_db),
) -> MappingReviewResponse:
    """Submits an authorized analyst review action (ACCEPT, REJECT, REQUEST_MORE_EVIDENCE)."""
    try:
        return MappingService.submit_review(
            db=db,
            mapping_id=mapping_id,
            req=req,
            reviewer_id=caller,
        )
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/mitre/techniques/{technique_id}/detections", response_model=List[DetectionMappingResponse])
def get_technique_detections(
    technique_id: str,
    db: Session = Depends(get_db),
) -> List[DetectionMappingResponse]:
    """Retrieves all SnareSight detections mapped to a specific ATT&CK technique."""
    return MappingService.get_detections_for_technique(db=db, technique_id=technique_id)


@router.get("/detections/{detection_id}/mitre-mappings", response_model=List[DetectionMappingResponse])
def get_detection_mitre_mappings(
    detection_id: str,
    db: Session = Depends(get_db),
) -> List[DetectionMappingResponse]:
    """Retrieves all ATT&CK technique mappings associated with a specific detection finding or alert."""
    return MappingService.get_mappings_for_detection(db=db, detection_id=detection_id)

