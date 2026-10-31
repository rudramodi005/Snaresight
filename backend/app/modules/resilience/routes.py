"""FastAPI REST router for Security Monitoring, Incident Readiness, Backup, Recovery, and Resilience."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.session import get_db
from app.db.models.resilience import DatabaseBackupModel
from app.modules.security.dependencies import (
    get_current_user,
    require_permission,
    AuthenticatedUser,
)
from app.modules.security.permissions import Permission
from app.modules.resilience.schemas import (
    SystemHealthOverviewResponse,
    AuditVerificationResponse,
    InternalSecurityEventCreate,
    InternalSecurityEventResponse,
    InternalSecurityAlertResponse,
    InternalAlertAcknowledgeRequest,
    InternalAlertResolveRequest,
    DatabaseBackupCreateRequest,
    DatabaseBackupResponse,
    RestoreTestRunRequest,
    RestoreTestResponse,
    DisasterRecoveryConfigResponse,
    DisasterRecoveryConfigUpdateRequest,
    DisasterRecoveryChecklistResponse,
    ChecklistScenarioUpdateRequest,
    ChecklistItemToggleRequest,
    InternalIncidentCreateRequest,
    InternalIncidentUpdateRequest,
    InternalIncidentNoteCreateRequest,
    InternalIncidentNoteResponse,
    InternalIncidentResponse,
)
from app.modules.resilience.health_service import health_service
from app.modules.resilience.backup_service import backup_service
from app.modules.resilience.service import resilience_service

resilience_router = APIRouter(prefix="/resilience", tags=["Operational Resilience & Platform Security"])


# -----------------------------------------------------------------------------
# 1. Health Probes & Diagnostics
# -----------------------------------------------------------------------------

@resilience_router.get(
    "/health/live",
    summary="Application liveness probe for orchestrators and container runtimes",
)
def liveness_probe() -> Dict[str, Any]:
    return health_service.check_liveness()


@resilience_router.get(
    "/health/ready",
    summary="Application and database persistence readiness probe",
)
def readiness_probe(db: Session = Depends(get_db)) -> Dict[str, Any]:
    return health_service.check_readiness(db)


@resilience_router.get(
    "/health/diagnostics",
    response_model=SystemHealthOverviewResponse,
    summary="Comprehensive multi-component system diagnostics overview",
)
def get_diagnostics(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> SystemHealthOverviewResponse:
    return health_service.check_detailed_diagnostics(db)


@resilience_router.post(
    "/audit/verify",
    response_model=AuditVerificationResponse,
    summary="Perform cryptographic hash chain verification on system audit logs",
)
def verify_audit_trail(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
) -> AuditVerificationResponse:
    return health_service.verify_audit_chain_integrity(db)


# -----------------------------------------------------------------------------
# 2. Internal Security Events & Alerts
# -----------------------------------------------------------------------------

@resilience_router.post(
    "/events",
    response_model=InternalSecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record an internal control-plane security event and evaluate rules",
)
def record_internal_security_event(
    req: InternalSecurityEventCreate,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> InternalSecurityEventResponse:
    if not req.actor_username:
        req.actor_username = current_user.username
    if not req.actor_role:
        req.actor_role = current_user.role

    event, _ = resilience_service.record_internal_event(db, req)
    return InternalSecurityEventResponse.model_validate(event)


@resilience_router.get(
    "/events",
    response_model=List[InternalSecurityEventResponse],
    summary="List internal control-plane security events",
)
def list_internal_security_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> List[InternalSecurityEventResponse]:
    events = resilience_service.list_internal_events(
        db, limit=limit, offset=offset, event_type=event_type, severity=severity
    )
    return [InternalSecurityEventResponse.model_validate(e) for e in events]


@resilience_router.get(
    "/alerts",
    response_model=List[InternalSecurityAlertResponse],
    summary="List internal security alerts",
)
def list_internal_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_ALERTS)),
) -> List[InternalSecurityAlertResponse]:
    alerts = resilience_service.list_internal_alerts(
        db, status=status, severity=severity, limit=limit, offset=offset
    )
    return [InternalSecurityAlertResponse.model_validate(a) for a in alerts]


@resilience_router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=InternalSecurityAlertResponse,
    summary="Acknowledge an internal security alert",
)
def acknowledge_internal_alert(
    alert_id: str,
    req: InternalAlertAcknowledgeRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ACKNOWLEDGE_ALERTS)),
) -> InternalSecurityAlertResponse:
    try:
        alert = resilience_service.acknowledge_alert(
            db, alert_id=alert_id, username=current_user.username, notes=req.notes
        )
        return InternalSecurityAlertResponse.model_validate(alert)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@resilience_router.post(
    "/alerts/{alert_id}/resolve",
    response_model=InternalSecurityAlertResponse,
    summary="Resolve an internal security alert with resolution notes",
)
def resolve_internal_alert(
    alert_id: str,
    req: InternalAlertResolveRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.RESOLVE_ALERTS)),
) -> InternalSecurityAlertResponse:
    try:
        alert = resilience_service.resolve_alert(
            db, alert_id=alert_id, username=current_user.username, resolution_notes=req.resolution_notes
        )
        return InternalSecurityAlertResponse.model_validate(alert)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# -----------------------------------------------------------------------------
# 3. Database Backups & Isolated Restore Verification
# -----------------------------------------------------------------------------

@resilience_router.get(
    "/backups",
    response_model=List[DatabaseBackupResponse],
    summary="List managed database backup artifacts and verification status",
)
def list_backups(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> List[DatabaseBackupResponse]:
    backups = db.scalars(
        select(DatabaseBackupModel)
        .order_by(DatabaseBackupModel.started_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return [DatabaseBackupResponse.model_validate(b) for b in backups]


@resilience_router.post(
    "/backups",
    response_model=DatabaseBackupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate a controlled database backup with cryptographic SHA-256",
)
def initiate_backup(
    req: DatabaseBackupCreateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> DatabaseBackupResponse:
    backup = backup_service.initiate_backup(
        db=db,
        backup_type=req.backup_type,
        initiated_by=current_user.username,
        retention_hold=req.retention_hold,
    )
    return DatabaseBackupResponse.model_validate(backup)


@resilience_router.post(
    "/backups/{backup_id}/restore-test",
    response_model=RestoreTestResponse,
    summary="Execute an isolated backup restoration verification test in sandbox environment",
)
def run_isolated_restore_test(
    backup_id: str,
    req: RestoreTestRunRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> RestoreTestResponse:
    try:
        test_record = backup_service.run_isolated_restore_test(
            db=db,
            backup_id=backup_id,
            verified_by=current_user.username,
            test_environment=req.test_environment,
        )
        return RestoreTestResponse.model_validate(test_record)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# -----------------------------------------------------------------------------
# 4. Disaster Recovery Config & Runbooks
# -----------------------------------------------------------------------------

@resilience_router.get(
    "/dr/config",
    response_model=DisasterRecoveryConfigResponse,
    summary="Retrieve current Disaster Recovery RPO/RTO targets and retention rules",
)
def get_dr_config(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> DisasterRecoveryConfigResponse:
    return resilience_service.get_or_create_dr_config(db)


@resilience_router.put(
    "/dr/config",
    response_model=DisasterRecoveryConfigResponse,
    summary="Update Disaster Recovery RPO/RTO parameters and retention governance",
)
def update_dr_config(
    req: DisasterRecoveryConfigUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> DisasterRecoveryConfigResponse:
    return resilience_service.update_dr_config(db, req, username=current_user.username)


@resilience_router.get(
    "/dr/checklists",
    response_model=List[DisasterRecoveryChecklistResponse],
    summary="List all 5 Disaster Recovery failure scenario checklists",
)
def list_dr_checklists(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> List[DisasterRecoveryChecklistResponse]:
    checklists = resilience_service.get_dr_checklists(db)
    return [DisasterRecoveryChecklistResponse.model_validate(c) for c in checklists]


@resilience_router.get(
    "/dr/checklists/{scenario_id}",
    response_model=DisasterRecoveryChecklistResponse,
    summary="Retrieve specific scenario runbook checklist",
)
def get_dr_checklist_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> DisasterRecoveryChecklistResponse:
    try:
        chk = resilience_service.get_dr_checklist(db, scenario_id)
        return DisasterRecoveryChecklistResponse.model_validate(chk)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@resilience_router.put(
    "/dr/checklists/{scenario_id}",
    response_model=DisasterRecoveryChecklistResponse,
    summary="Update scenario status and full checklist items",
)
def update_dr_checklist_scenario(
    scenario_id: str,
    req: ChecklistScenarioUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> DisasterRecoveryChecklistResponse:
    try:
        chk = resilience_service.update_scenario(
            db,
            scenario_id=scenario_id,
            status=req.current_status,
            items=req.checklist_items,
            username=current_user.username,
        )
        return DisasterRecoveryChecklistResponse.model_validate(chk)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@resilience_router.post(
    "/dr/checklists/{scenario_id}/items/toggle",
    response_model=DisasterRecoveryChecklistResponse,
    summary="Toggle specific item completion in scenario checklist",
)
def toggle_dr_checklist_item(
    scenario_id: str,
    req: ChecklistItemToggleRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> DisasterRecoveryChecklistResponse:
    try:
        chk = resilience_service.toggle_checklist_item(
            db,
            scenario_id=scenario_id,
            item_id=req.item_id,
            completed=req.completed,
            notes=req.notes,
            username=current_user.username,
        )
        return DisasterRecoveryChecklistResponse.model_validate(chk)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


# -----------------------------------------------------------------------------
# 5. Internal Security Incidents
# -----------------------------------------------------------------------------

@resilience_router.get(
    "/incidents",
    response_model=List[InternalIncidentResponse],
    summary="List internal control-plane security incidents",
)
def list_internal_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_ALERTS)),
) -> List[InternalIncidentResponse]:
    incidents = resilience_service.list_incidents(
        db, status=status, severity=severity, limit=limit, offset=offset
    )
    return [InternalIncidentResponse.model_validate(i) for i in incidents]


@resilience_router.post(
    "/incidents",
    response_model=InternalIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an internal control-plane security incident",
)
def create_internal_incident(
    req: InternalIncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> InternalIncidentResponse:
    inc = resilience_service.create_incident(db, req, username=current_user.username)
    return InternalIncidentResponse.model_validate(inc)


@resilience_router.get(
    "/incidents/{incident_id}",
    response_model=InternalIncidentResponse,
    summary="Retrieve internal security incident details and response notes",
)
def get_internal_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_ALERTS)),
) -> InternalIncidentResponse:
    try:
        inc = resilience_service.get_incident(db, incident_id)
        return InternalIncidentResponse.model_validate(inc)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@resilience_router.patch(
    "/incidents/{incident_id}",
    response_model=InternalIncidentResponse,
    summary="Update internal security incident containment status and resolution",
)
def update_internal_incident(
    incident_id: str,
    req: InternalIncidentUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> InternalIncidentResponse:
    try:
        inc = resilience_service.update_incident(
            db, incident_id=incident_id, req=req, username=current_user.username
        )
        return InternalIncidentResponse.model_validate(inc)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@resilience_router.post(
    "/incidents/{incident_id}/notes",
    response_model=InternalIncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Append an investigation or containment note to an internal security incident",
)
def add_internal_incident_note(
    incident_id: str,
    req: InternalIncidentNoteCreateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ADD_INVESTIGATION_NOTES)),
) -> InternalIncidentNoteResponse:
    try:
        note = resilience_service.add_incident_note(
            db, incident_id=incident_id, req=req, username=current_user.username
        )
        return InternalIncidentNoteResponse.model_validate(note)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
