"""FastAPI REST router for Defensive Response and Incident Handling Workflow."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.security.dependencies import (
    get_current_user,
    require_permission,
    AuthenticatedUser,
)
from app.modules.security.permissions import Permission
from app.modules.response.schemas import (
    ResponseDashboardSummary,
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseStatusTransitionRequest,
    CaseNoteCreateRequest,
    CaseLinkEntityRequest,
    CaseListResponse,
    ResponseCaseResponse,
    CaseNoteResponse,
    CaseRelationshipResponse,
    ResponseRecommendationResponse,
    RecommendationDecisionRequest,
    PlaybookDefinitionResponse,
    PlaybookExecuteRequest,
    PlaybookExecutionResponse,
    ResponseApprovalResponse,
    ApprovalDecisionRequest,
    ActionExecuteRequest,
    ResponseActionResponse,
    EvidenceHoldCreateRequest,
    EvidenceHoldReleaseRequest,
    EvidencePreservationHoldResponse,
)
from app.modules.response.service import response_service

response_router = APIRouter(prefix="/response", tags=["Defensive Response & Incident Handling"])


# -------------------------------------------------------------
# Summary & Metrics
# -------------------------------------------------------------
@response_router.get(
    "/summary",
    response_model=ResponseDashboardSummary,
    summary="Retrieve live Defensive Response Center summary metrics",
)
def get_response_summary(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns aggregated response case counts, priority distributions, and pending approvals."""
    return response_service.get_dashboard_summary(db)


# -------------------------------------------------------------
# Case Management Routes
# -------------------------------------------------------------
@response_router.get(
    "/cases",
    response_model=CaseListResponse,
    summary="List, search, filter, and paginate response cases",
)
def list_cases(
    status: Optional[str] = Query(None, description="Filter by case status (e.g. OPEN, INVESTIGATING)"),
    priority: Optional[str] = Query(None, description="Filter by priority (e.g. P1_CRITICAL, P2_HIGH)"),
    assigned_analyst: Optional[str] = Query(None, description="Filter by assigned analyst username"),
    search: Optional[str] = Query(None, description="Search term for case title or ID"),
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns paginated cases filtered by status, priority, or analyst."""
    cases, total = response_service.list_cases(
        db=db,
        status=status,
        priority=priority,
        assigned_analyst=assigned_analyst,
        search=search,
        page=page,
        limit=limit,
    )
    return CaseListResponse(total=total, page=page, limit=limit, items=cases)


@response_router.post(
    "/cases",
    response_model=ResponseCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new incident response case",
)
def create_case(
    payload: CaseCreateRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_ALERTS)),
    db: Session = Depends(get_db),
):
    """Creates a new incident response case and generates initial grounded recommendations."""
    return response_service.create_case(
        db=db,
        payload=payload,
        actor_username=current_user.username,
        actor_role=current_user.role,
    )


@response_router.get(
    "/cases/{case_id}",
    response_model=ResponseCaseResponse,
    summary="Retrieve full response case detail workspace",
)
def get_case_detail(
    case_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns complete case details including linked relationships, notes, and recommendations."""
    case = response_service.get_case_detail(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


@response_router.patch(
    "/cases/{case_id}",
    response_model=ResponseCaseResponse,
    summary="Update case metadata",
)
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ASSIGN_ALERTS)),
    db: Session = Depends(get_db),
):
    """Updates case title, priority, or assigned analyst."""
    case = response_service.update_case(
        db=db,
        case_id=case_id,
        payload=payload,
        actor_username=current_user.username,
        actor_role=current_user.role,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


@response_router.post(
    "/cases/{case_id}/status",
    response_model=ResponseCaseResponse,
    summary="Transition case lifecycle status",
)
def transition_case_status(
    case_id: str,
    payload: CaseStatusTransitionRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.RESOLVE_ALERTS)),
    db: Session = Depends(get_db),
):
    """Validates and applies allowed lifecycle status transitions with audit notes."""
    try:
        case = response_service.transition_status(
            db=db,
            case_id=case_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
        return case
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@response_router.post(
    "/cases/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to a response case",
)
def add_case_note(
    case_id: str,
    payload: CaseNoteCreateRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ADD_INVESTIGATION_NOTES)),
    db: Session = Depends(get_db),
):
    """Adds a comment or note to the case timeline."""
    try:
        return response_service.add_case_note(
            db=db,
            case_id=case_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@response_router.post(
    "/cases/{case_id}/links",
    response_model=CaseRelationshipResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Link an alert, event, session, profile, or campaign to a case",
)
def link_entity(
    case_id: str,
    payload: CaseLinkEntityRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ADD_INVESTIGATION_NOTES)),
    db: Session = Depends(get_db),
):
    """Creates a junction relationship between a case and another SnareSight entity."""
    try:
        return response_service.link_entity(
            db=db,
            case_id=case_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# -------------------------------------------------------------
# Recommendations Routes
# -------------------------------------------------------------
@response_router.get(
    "/cases/{case_id}/recommendations",
    response_model=List[ResponseRecommendationResponse],
    summary="List defensive recommendations for a case",
)
def get_case_recommendations(
    case_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns rule-generated recommendations associated with a case."""
    case = response_service.get_case_detail(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case.recommendations


@response_router.post(
    "/recommendations/{recommendation_id}/decision",
    response_model=ResponseRecommendationResponse,
    summary="Accept or reject a defensive recommendation",
)
def decide_recommendation(
    recommendation_id: str,
    payload: RecommendationDecisionRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ACKNOWLEDGE_ALERTS)),
    db: Session = Depends(get_db),
):
    """Records an analyst's decision on a recommendation and queues approval if necessary."""
    try:
        return response_service.decide_recommendation(
            db=db,
            recommendation_id=recommendation_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# -------------------------------------------------------------
# Playbook Catalogue & Execution Routes
# -------------------------------------------------------------
@response_router.get(
    "/playbooks",
    response_model=List[PlaybookDefinitionResponse],
    summary="List all available defensive response playbooks",
)
def list_playbooks(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the catalogue of configured, versioned defensive playbooks."""
    return response_service.list_playbooks(db)


@response_router.post(
    "/playbooks/{playbook_id}/execute/{case_id}",
    response_model=PlaybookExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate playbook execution on a case",
)
def execute_playbook(
    playbook_id: str,
    case_id: str,
    payload: PlaybookExecuteRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ACKNOWLEDGE_ALERTS)),
    db: Session = Depends(get_db),
):
    """Starts an auditable step-by-step playbook run."""
    try:
        return response_service.execute_playbook(
            db=db,
            playbook_id=playbook_id,
            case_id=case_id,
            inputs=payload.inputs or {},
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# -------------------------------------------------------------
# Human Approval Routes
# -------------------------------------------------------------
@response_router.get(
    "/approvals",
    response_model=List[ResponseApprovalResponse],
    summary="List pending or historical human approval requests",
)
def list_approvals(
    status: Optional[str] = Query("PENDING", description="Filter by approval status (PENDING, APPROVED, REJECTED)"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns approval queue items for authorized analysts and administrators."""
    return response_service.list_approvals(db, status=status)


@response_router.post(
    "/approvals/{approval_id}/decision",
    response_model=ResponseApprovalResponse,
    summary="Approve or reject a response action approval request",
)
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.CLOSE_ALERTS)),
    db: Session = Depends(get_db),
):
    """Records formal approval decision with human accountability."""
    try:
        return response_service.decide_approval(
            db=db,
            approval_id=approval_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# -------------------------------------------------------------
# Action Execution Routes (Controlled Catalogue)
# -------------------------------------------------------------
@response_router.post(
    "/cases/{case_id}/actions",
    response_model=ResponseActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute a safe defensive action from the catalogue",
)
def execute_action(
    case_id: str,
    payload: ActionExecuteRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ACKNOWLEDGE_ALERTS)),
    db: Session = Depends(get_db),
):
    """Executes a permitted internal application action (notes, priority change, evidence hold)."""
    try:
        return response_service.execute_action(
            db=db,
            case_id=case_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# -------------------------------------------------------------
# Evidence Preservation Holds Routes
# -------------------------------------------------------------
@response_router.post(
    "/cases/{case_id}/holds",
    response_model=EvidencePreservationHoldResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Apply an evidence preservation hold",
)
def create_evidence_hold(
    case_id: str,
    payload: EvidenceHoldCreateRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.EXPORT_DATA)),
    db: Session = Depends(get_db),
):
    """Applies a retention hold to an event or session with SHA-256 integrity metadata."""
    try:
        return response_service.create_evidence_hold(
            db=db,
            case_id=case_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@response_router.post(
    "/holds/{hold_id}/release",
    response_model=EvidencePreservationHoldResponse,
    summary="Release an evidence preservation hold",
)
def release_evidence_hold(
    hold_id: str,
    payload: EvidenceHoldReleaseRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.EXPORT_DATA)),
    db: Session = Depends(get_db),
):
    """Releases a preservation hold with documented analyst justification."""
    try:
        return response_service.release_evidence_hold(
            db=db,
            hold_id=hold_id,
            payload=payload,
            actor_username=current_user.username,
            actor_role=current_user.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

