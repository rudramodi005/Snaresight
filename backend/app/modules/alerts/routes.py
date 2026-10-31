"""FastAPI REST routes for SOC Alert Management and Triage Center (Task P28)."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, Query, Path, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.alerts.service import AlertTriageService
from app.services.alert_service import alert_service as core_alert_service
from app.modules.alerts.schemas import (
    AlertQueueResponse,
    AlertSummaryResponse,
    AlertDetailResponse,
    AlertEvidenceItem,
    AlertRelationshipsResponse,
    AlertAuditLogItem,
    AlertNoteItem,
    AcknowledgeRequest,
    AssignRequest,
    InvestigateRequest,
    EscalateRequest,
    ResolveRequest,
    CloseRequest,
    AddNoteRequest,
    TriageDecisionRequest,
)

router = APIRouter(prefix="/alerts", tags=["SOC Alert Management"])


@router.get(
    "",
    response_model=AlertQueueResponse,
    summary="List and filter alerts in the SOC queue",
)
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    status: Optional[str] = Query(None, description="Filter: NEW, ACKNOWLEDGED, INVESTIGATING, ESCALATED, RESOLVED, CLOSED"),
    category: Optional[str] = Query(None, description="Filter by detection category (e.g. BRUTE_FORCE, RECONNAISSANCE)"),
    assigned_analyst: Optional[str] = Query(None, description="Filter by assigned analyst ID"),
    unassigned_only: bool = Query(False, description="Filter for unassigned alerts only"),
    search: Optional[str] = Query(None, description="Free-text search in title, summary, source, decoy, or rule"),
    date_start: Optional[datetime] = Query(None, description="Filter alerts generated on or after this UTC timestamp"),
    date_end: Optional[datetime] = Query(None, description="Filter alerts generated on or before this UTC timestamp"),
    sort_by: str = Query("generated_at", description="Sort column: generated_at, priority_score, severity, confidence"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
) -> AlertQueueResponse:
    """Retrieves server-side filtered, sorted, and paginated alerts from the database."""
    service = AlertTriageService(db)
    return service.get_alerts_queue(
        severity=severity,
        status_filter=status,
        category=category,
        assigned_analyst=assigned_analyst,
        unassigned_only=unassigned_only,
        search=search,
        date_start=date_start,
        date_end=date_end,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=limit,
    )


@router.get(
    "/summary",
    response_model=AlertSummaryResponse,
    summary="Get aggregated SOC alert summary metrics",
)
def get_alerts_summary(
    db: Session = Depends(get_db),
) -> AlertSummaryResponse:
    """Returns real-time aggregated metrics across alert lifecycle statuses, severities, and priorities."""
    service = AlertTriageService(db)
    return service.get_alerts_summary()


@router.get(
    "/suppression/history",
    summary="Get suppression audit history",
)
def get_suppression_history() -> List[Dict[str, Any]]:
    """Returns the auditable history of alerts suppressed by cooldown or explicit suppression rules."""
    return core_alert_service.get_suppression_audit_log()


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get full forensic detail and triage status for an alert",
)
def get_alert_detail(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Retrieves complete explainable detection metadata, severity/confidence reasons, and priority score."""
    service = AlertTriageService(db)
    return service.get_alert_detail(alert_id)


@router.get(
    "/{alert_id}/evidence",
    response_model=List[AlertEvidenceItem],
    summary="Get supporting security events tied to an alert",
)
def get_alert_evidence(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    db: Session = Depends(get_db),
) -> List[AlertEvidenceItem]:
    """Retrieves the normalized supporting events linked to this alert with direct links to Security Events Explorer."""
    service = AlertTriageService(db)
    return service.get_alert_evidence(alert_id)


@router.get(
    "/{alert_id}/relationships",
    response_model=AlertRelationshipsResponse,
    summary="Get correlated cross-subsystem entities for an alert",
)
def get_alert_relationships(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    db: Session = Depends(get_db),
) -> AlertRelationshipsResponse:
    """Resolves correlated sessions, source intelligence profiles, attack sequences, and MITRE ATT&CK techniques."""
    service = AlertTriageService(db)
    return service.get_alert_relationships(alert_id)


@router.get(
    "/{alert_id}/history",
    response_model=List[AlertAuditLogItem],
    summary="Get audit trail and history of analyst actions for an alert",
)
def get_alert_history(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    db: Session = Depends(get_db),
) -> List[AlertAuditLogItem]:
    """Retrieves an immutable chronological record of triage actions, status transitions, and notes."""
    service = AlertTriageService(db)
    return service.get_alert_history(alert_id)


@router.get(
    "/{alert_id}/notes",
    response_model=List[AlertNoteItem],
    summary="Get notes attached to an alert",
)
def get_alert_notes(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    db: Session = Depends(get_db),
) -> List[AlertNoteItem]:
    """Retrieves append-only analyst notes attached to this alert."""
    service = AlertTriageService(db)
    return service.get_alert_notes(alert_id)


# --- Triage Actions ---

@router.post(
    "/{alert_id}/acknowledge",
    response_model=AlertDetailResponse,
    summary="Acknowledge an alert",
)
def acknowledge_alert(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: AcknowledgeRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Transitions alert status to ACKNOWLEDGED and assigns the acknowledging analyst."""
    service = AlertTriageService(db)
    return service.acknowledge_alert(alert_id, body)


@router.post(
    "/{alert_id}/assign",
    response_model=AlertDetailResponse,
    summary="Assign or reassign an alert to an analyst",
)
def assign_alert(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: AssignRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Assigns an alert to an authorized analyst and logs the assignment event."""
    service = AlertTriageService(db)
    return service.assign_alert(alert_id, body)


@router.post(
    "/{alert_id}/investigate",
    response_model=AlertDetailResponse,
    summary="Start investigation on an alert",
)
def start_investigation(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: InvestigateRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Transitions status to INVESTIGATING and optionally associates an existing investigation cluster."""
    service = AlertTriageService(db)
    return service.start_investigation(alert_id, body)


@router.post(
    "/{alert_id}/escalate",
    response_model=AlertDetailResponse,
    summary="Escalate an alert",
)
def escalate_alert(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: EscalateRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Escalates an alert to a higher tier or incident response team; requires an explicit reason."""
    service = AlertTriageService(db)
    return service.escalate_alert(alert_id, body)


@router.post(
    "/{alert_id}/resolve",
    response_model=AlertDetailResponse,
    summary="Resolve an alert",
)
def resolve_alert(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: ResolveRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Resolves an alert with categorization and required justification."""
    service = AlertTriageService(db)
    return service.resolve_alert(alert_id, body)


@router.post(
    "/{alert_id}/close",
    response_model=AlertDetailResponse,
    summary="Close an alert",
)
def close_alert(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: CloseRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Closes an alert with mandatory disposition reason."""
    service = AlertTriageService(db)
    return service.close_alert(alert_id, body)


@router.post(
    "/{alert_id}/notes",
    response_model=AlertNoteItem,
    status_code=status.HTTP_201_CREATED,
    summary="Append a note to an alert",
)
def add_note(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: AddNoteRequest = ...,
    db: Session = Depends(get_db),
) -> AlertNoteItem:
    """Appends an immutable analyst note to the alert and writes an audit log entry."""
    service = AlertTriageService(db)
    return service.add_note(alert_id, body)


@router.post(
    "/{alert_id}/triage-decision",
    response_model=AlertDetailResponse,
    summary="Record structured triage assessment",
)
def record_triage_decision(
    alert_id: str = Path(..., description="UUID or identifier of the security alert"),
    body: TriageDecisionRequest = ...,
    db: Session = Depends(get_db),
) -> AlertDetailResponse:
    """Records a structured triage decision (e.g. TRUE_POSITIVE, FALSE_POSITIVE) with evidence justification."""
    service = AlertTriageService(db)
    return service.record_triage_decision(alert_id, body)

