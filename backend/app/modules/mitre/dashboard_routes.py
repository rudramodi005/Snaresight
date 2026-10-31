"""FastAPI REST routes for MITRE ATT&CK Threat Intelligence and Mapping Dashboard (Task P29)."""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.mitre.dashboard_service import AttackDashboardService
from app.modules.mitre.dashboard_schemas import (
    AttackCatalogueMetadata,
    AttackDashboardSummary,
    AttackTacticOverviewResponse,
    AttackMatrixResponse,
    AttackTechniqueExplorerResponse,
    AttackTechniqueDetailResponse,
    AttackTechniqueMappingItem,
    AttackTechniqueEvidenceItem,
    AttackCoverageAnalyticsResponse,
    AttackTraceabilityResponse,
    MappingReviewActionRequest,
)

router = APIRouter(prefix="/attack", tags=["MITRE ATT&CK Threat Intelligence Dashboard"])


@router.get(
    "/summary",
    response_model=AttackDashboardSummary,
    summary="Get aggregated MITRE ATT&CK dashboard summary",
)
def get_attack_summary(db: Session = Depends(get_db)) -> AttackDashboardSummary:
    """Returns high-level catalogue KPIs, mapped technique totals, alert evidence counts, and rule coverage."""
    return AttackDashboardService.get_summary(db)


@router.get(
    "/catalogue/metadata",
    response_model=AttackCatalogueMetadata,
    summary="Get active MITRE ATT&CK catalogue metadata",
)
def get_catalogue_metadata(db: Session = Depends(get_db)) -> AttackCatalogueMetadata:
    """Returns official catalogue release version, checksum, STIX version, and provenance."""
    return AttackDashboardService.get_catalogue_metadata(db)


@router.get(
    "/tactics",
    response_model=AttackTacticOverviewResponse,
    summary="Get Enterprise ATT&CK tactics overview",
)
def get_tactic_overview(db: Session = Depends(get_db)) -> AttackTacticOverviewResponse:
    """Returns all 14 Enterprise ATT&CK tactics with counts of mapped techniques, rules, alerts, and investigations."""
    return AttackDashboardService.get_tactic_overview(db)


@router.get(
    "/matrix",
    response_model=AttackMatrixResponse,
    summary="Get interactive Enterprise ATT&CK matrix columns and cells",
)
def get_attack_matrix(
    tactic: Optional[str] = Query(None, description="Filter by tactic ID or shortname (e.g. TA0001, initial-access)"),
    status: Optional[str] = Query(None, description="Filter: UNMAPPED, RULE_MAPPED, ALERT_EVIDENCE, REVIEW_REQUIRED"),
    search: Optional[str] = Query(None, description="Search term in technique ID or name"),
    db: Session = Depends(get_db),
) -> AttackMatrixResponse:
    """Returns columnar matrix data arranged by Enterprise ATT&CK tactics with visual mapping states."""
    return AttackDashboardService.get_matrix(
        db=db,
        filter_tactic=tactic,
        filter_status=status,
        search=search,
    )


@router.get(
    "/techniques",
    response_model=AttackTechniqueExplorerResponse,
    summary="Search and explore ATT&CK techniques with pagination",
)
def list_techniques_explorer(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search technique ID, name, or description"),
    tactic: Optional[str] = Query(None, description="Filter by tactic ID or name"),
    status: Optional[str] = Query(None, description="Filter: MAPPED, UNMAPPED, RULE_MAPPED, ALERT_EVIDENCE, REVIEW_REQUIRED"),
    is_subtechnique: Optional[bool] = Query(None, description="Filter sub-techniques vs parent techniques"),
    sort_by: str = Query("technique_id", description="Sort by technique_id, technique_name, or tactic_name"),
    sort_order: str = Query("asc", pattern="^(asc|desc)$", description="Sort order: asc or desc"),
    db: Session = Depends(get_db),
) -> AttackTechniqueExplorerResponse:
    """Queries paginated techniques with server-side keyword searching and multi-attribute filters."""
    return AttackDashboardService.list_techniques_explorer(
        db=db,
        page=page,
        page_size=limit,
        search=search,
        tactic=tactic,
        status_filter=status,
        is_subtechnique=is_subtechnique,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get(
    "/techniques/{technique_id}",
    response_model=AttackTechniqueDetailResponse,
    summary="Get full technique detail, mapping definitions, and supporting evidence",
)
def get_technique_detail(
    technique_id: str = Path(..., description="External ATT&CK technique ID (e.g. T1110)"),
    db: Session = Depends(get_db),
) -> AttackTechniqueDetailResponse:
    """Retrieves authoritative ATT&CK metadata, SnareSight mapping definitions, live alert evidence, and caveats."""
    detail = AttackDashboardService.get_technique_detail(db, technique_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique '{technique_id}' not found in active ATT&CK catalogue.",
        )
    return detail


@router.get(
    "/techniques/{technique_id}/mappings",
    response_model=List[AttackTechniqueMappingItem],
    summary="Get configured detection rule mappings for a technique",
)
def get_technique_mappings(
    technique_id: str = Path(..., description="External ATT&CK technique ID (e.g. T1110)"),
    db: Session = Depends(get_db),
) -> List[AttackTechniqueMappingItem]:
    """Retrieves all SnareSight detection rule mappings defined for this technique."""
    detail = AttackDashboardService.get_technique_detail(db, technique_id)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Technique '{technique_id}' not found.")
    return detail.mappings


@router.get(
    "/techniques/{technique_id}/evidence",
    response_model=List[AttackTechniqueEvidenceItem],
    summary="Get live supporting alert and event evidence for a technique",
)
def get_technique_evidence(
    technique_id: str = Path(..., description="External ATT&CK technique ID (e.g. T1110)"),
    db: Session = Depends(get_db),
) -> List[AttackTechniqueEvidenceItem]:
    """Retrieves live security alerts and events corroborating this technique."""
    detail = AttackDashboardService.get_technique_detail(db, technique_id)
    if not detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Technique '{technique_id}' not found.")
    return detail.supporting_evidence


@router.get(
    "/coverage",
    response_model=AttackCoverageAnalyticsResponse,
    summary="Get mapping coverage analytics and tactic breakdowns",
)
def get_coverage_analytics(db: Session = Depends(get_db)) -> AttackCoverageAnalyticsResponse:
    """Calculates coverage percentages across catalogue techniques, detection rules, and alert evidence."""
    return AttackDashboardService.get_coverage_analytics(db)


@router.get(
    "/traceability",
    response_model=AttackTraceabilityResponse,
    summary="Get end-to-end detection traceability chains",
)
def get_traceability(db: Session = Depends(get_db)) -> AttackTraceabilityResponse:
    """Resolves complete traceability paths: Technique -> Mapping -> Rule -> Alert -> Event -> Investigation."""
    return AttackDashboardService.get_traceability(db)


# --- Mapping Review Actions ---

@router.post(
    "/mappings/{mapping_id}/approve",
    summary="Approve an ATT&CK detection mapping",
)
def approve_mapping(
    mapping_id: str = Path(..., description="UUID or identifier of the detection mapping"),
    analyst_id: str = Query("analyst_current", description="Reviewing analyst identifier"),
    comment: str = Query("Approved mapping based on observed honeypot evidence", description="Approval justification"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Approves a detection mapping, updating review status to ACCEPTED with audit logging."""
    req = MappingReviewActionRequest(analyst_id=analyst_id, action="APPROVE", comment=comment)
    result = AttackDashboardService.review_mapping(db, mapping_id, req)
    if result.get("status") == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result


@router.post(
    "/mappings/{mapping_id}/reject",
    summary="Reject an ATT&CK detection mapping",
)
def reject_mapping(
    mapping_id: str = Path(..., description="UUID or identifier of the detection mapping"),
    analyst_id: str = Query("analyst_current", description="Reviewing analyst identifier"),
    comment: str = Query("Rejected mapping: evidence does not warrant this technique", description="Rejection reason"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Rejects a detection mapping, updating review status to REJECTED with audit logging."""
    req = MappingReviewActionRequest(analyst_id=analyst_id, action="REJECT", comment=comment)
    result = AttackDashboardService.review_mapping(db, mapping_id, req)
    if result.get("status") == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result


@router.post(
    "/mappings/{mapping_id}/review",
    summary="Submit structured analyst review for an ATT&CK mapping",
)
def submit_mapping_review(
    mapping_id: str = Path(..., description="UUID or identifier of the detection mapping"),
    body: MappingReviewActionRequest = ...,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Records an analyst review decision (APPROVE, REJECT, or REQUEST_REVIEW) with audit history."""
    result = AttackDashboardService.review_mapping(db, mapping_id, body)
    if result.get("status") == 404:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["error"])
    return result

