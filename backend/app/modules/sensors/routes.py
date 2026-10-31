"""FastAPI REST router for Honeypot Sensor Management, Health Monitoring, and Reliability."""

from typing import Optional, List, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models.sensor import SensorModel, SensorCredentialModel
from app.modules.security.dependencies import (
    get_current_user,
    require_permission,
    AuthenticatedUser,
)
from app.modules.security.permissions import Permission
from app.modules.sensors.schemas import (
    SensorCreateRequest,
    SensorUpdateRequest,
    SensorStatusUpdateRequest,
    MaintenanceModeRequest,
    SensorRegistrationResult,
    SensorResponse,
    SensorDetailResponse,
    SensorListResponse,
    SensorCredentialResponse,
    HeartbeatSubmitRequest,
    HeartbeatRecordResponse,
    SensorConfigurationCreateRequest,
    SensorConfigurationRollbackRequest,
    SensorConfigurationResponse,
    OperationalAlertResponse,
    OperationalAlertListResponse,
    OperationalAlertResolveRequest,
    SensorOperationsSummary,
)
from app.modules.sensors.service import sensor_service
from app.modules.sensors.health_engine import SensorHealthEngine
from app.modules.sensors.auth import authenticate_sensor_request

sensors_router = APIRouter(prefix="/sensors", tags=["Honeypot Sensor Operations"])


# -----------------------------------------------------------------------------
# Operations Summary & Metrics
# -----------------------------------------------------------------------------

@sensors_router.get(
    "/summary",
    response_model=SensorOperationsSummary,
    summary="Retrieve live Honeypot Sensor Operations overview metrics",
)
def get_sensor_operations_summary(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> SensorOperationsSummary:
    """Returns aggregated sensor fleet vitals, health status, and operational alert counts."""
    return sensor_service.get_summary(db)


# -----------------------------------------------------------------------------
# Sensor Inventory CRUD
# -----------------------------------------------------------------------------

@sensors_router.get(
    "",
    response_model=SensorListResponse,
    summary="List sensor inventory with search and status filters",
)
def list_sensors(
    status: Optional[str] = Query(None, description="Filter by operational status"),
    sensor_type: Optional[str] = Query(None, description="Filter by archetype"),
    environment: Optional[str] = Query(None, description="Filter by deployment environment"),
    search: Optional[str] = Query(None, description="Search by ID, name, or lab zone"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> SensorListResponse:
    """Returns a paginated list of registered honeypot sensors."""
    total, items = sensor_service.list_sensors(
        db=db,
        status=status,
        sensor_type=sensor_type,
        environment=environment,
        search=search,
        page=page,
        limit=limit,
    )
    return SensorListResponse(
        total=total,
        page=page,
        limit=limit,
        items=[SensorResponse.model_validate(s) for s in items],
    )


@sensors_router.post(
    "",
    response_model=SensorRegistrationResult,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new honeypot sensor and generate initial credentials",
)
def register_sensor(
    payload: SensorCreateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_SENSORS)),
) -> SensorRegistrationResult:
    """Registers a sensor, generates an unrecoverable raw API key, and creates baseline config."""
    try:
        sensor, credential, raw_key = sensor_service.register_sensor(
            db=db, payload=payload, user=current_user
        )
        return SensorRegistrationResult(
            sensor=SensorResponse.model_validate(sensor),
            credential=SensorCredentialResponse.model_validate(credential),
            raw_api_key=raw_key,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@sensors_router.get(
    "/{sensor_id}",
    response_model=SensorDetailResponse,
    summary="Retrieve complete sensor detail workspace",
)
def get_sensor_detail(
    sensor_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> SensorDetailResponse:
    """Returns sensor metadata, credentials list (masked), recent heartbeats, and current config."""
    sensor = sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sensor '{sensor_id}' not found")

    open_alerts = [a for a in sensor.operational_alerts if a.status in ("OPEN", "ACKNOWLEDGED")]
    current_config = next((c for c in sensor.configurations if c.is_current), None)

    return SensorDetailResponse(
        id=sensor.id,
        sensor_id=sensor.sensor_id,
        name=sensor.name,
        sensor_type=sensor.sensor_type,
        sensor_version=sensor.sensor_version,
        deployment_environment=sensor.deployment_environment,
        lab_zone=sensor.lab_zone,
        operational_status=sensor.operational_status,
        health_status=sensor.health_status,
        heartbeat_interval_seconds=sensor.heartbeat_interval_seconds,
        missed_heartbeat_count=sensor.missed_heartbeat_count,
        last_heartbeat_at=sensor.last_heartbeat_at,
        last_telemetry_at=sensor.last_telemetry_at,
        current_config_version=sensor.current_config_version,
        supported_telemetry_types=sensor.supported_telemetry_types,
        admin_notes=sensor.admin_notes,
        created_at=sensor.created_at,
        updated_at=sensor.updated_at,
        credentials=[SensorCredentialResponse.model_validate(c) for c in sensor.credentials],
        recent_heartbeats=[HeartbeatRecordResponse.model_validate(h) for h in sensor.heartbeats[-15:]],
        current_configuration=SensorConfigurationResponse.model_validate(current_config) if current_config else None,
        open_operational_alerts=[OperationalAlertResponse.model_validate(a) for a in open_alerts],
    )


@sensors_router.post(
    "/{sensor_id}/status",
    response_model=SensorResponse,
    summary="Update sensor operational status (enable, disable, retire)",
)
def update_sensor_status(
    sensor_id: str,
    payload: SensorStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_SENSORS)),
) -> SensorResponse:
    """Updates operational state: ACTIVE, DISABLED, RETIRED."""
    try:
        updated = sensor_service.update_sensor_status(
            db=db,
            sensor_id=sensor_id,
            new_status=payload.operational_status,
            reason=payload.reason,
            user=current_user,
        )
        return SensorResponse.model_validate(updated)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# -----------------------------------------------------------------------------
# Sensor Credentials
# -----------------------------------------------------------------------------

@sensors_router.post(
    "/{sensor_id}/credentials/rotate",
    summary="Rotate sensor API key (returns new raw secret once)",
)
def rotate_sensor_credentials(
    sensor_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_SENSORS)),
):
    """Revokes active credentials and returns a new raw API key."""
    try:
        cred, raw_key = sensor_service.rotate_credentials(db, sensor_id, user=current_user)
        return {
            "credential": SensorCredentialResponse.model_validate(cred),
            "raw_api_key": raw_key,
            "warning": "Copy this secret immediately. It will not be displayed again.",
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@sensors_router.post(
    "/{sensor_id}/credentials/{key_id}/revoke",
    response_model=SensorCredentialResponse,
    summary="Revoke an individual sensor credential",
)
def revoke_sensor_credential(
    sensor_id: str,
    key_id: str,
    reason: str = Query(..., description="Justification for revocation"),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_SENSORS)),
) -> SensorCredentialResponse:
    """Revokes a specific sensor credential."""
    try:
        cred = sensor_service.revoke_credential(
            db=db, sensor_id=sensor_id, key_id=key_id, reason=reason, user=current_user
        )
        return SensorCredentialResponse.model_validate(cred)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# -----------------------------------------------------------------------------
# Heartbeat Ingestion
# -----------------------------------------------------------------------------

@sensors_router.post(
    "/heartbeat",
    response_model=HeartbeatRecordResponse,
    summary="Submit periodic sensor heartbeat (authenticated via X-Sensor-Key)",
)
def submit_sensor_heartbeat(
    payload: HeartbeatSubmitRequest,
    sensor_auth: Tuple[SensorModel, SensorCredentialModel] = Depends(authenticate_sensor_request),
    db: Session = Depends(get_db),
) -> HeartbeatRecordResponse:
    """
    Ingests sensor heartbeat, updates vital metrics, and computes health classification.
    Anti-impersonation: verifies that the authenticated sensor ID matches payload sensor_id.
    """
    sensor, _ = sensor_auth
    if sensor.sensor_id != payload.sensor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sensor impersonation prohibited: authenticated key is for '{sensor.sensor_id}', but payload claims '{payload.sensor_id}'",
        )

    record = sensor_service.record_heartbeat(db=db, sensor=sensor, payload=payload)
    return HeartbeatRecordResponse.model_validate(record)


@sensors_router.get(
    "/{sensor_id}/heartbeats",
    response_model=List[HeartbeatRecordResponse],
    summary="List recent heartbeat history for a sensor",
)
def get_sensor_heartbeats(
    sensor_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> List[HeartbeatRecordResponse]:
    """Returns chronological heartbeat telemetry records."""
    sensor = sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sensor '{sensor_id}' not found")
    return [HeartbeatRecordResponse.model_validate(h) for h in sensor.heartbeats[-limit:]]


# -----------------------------------------------------------------------------
# Configuration Management
# -----------------------------------------------------------------------------

@sensors_router.get(
    "/{sensor_id}/configurations",
    response_model=List[SensorConfigurationResponse],
    summary="Retrieve versioned configuration history for a sensor",
)
def get_sensor_configurations(
    sensor_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> List[SensorConfigurationResponse]:
    """Returns chronological configuration versions."""
    sensor = sensor_service.get_sensor(db, sensor_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sensor '{sensor_id}' not found")
    return [SensorConfigurationResponse.model_validate(c) for c in sensor.configurations]


@sensors_router.post(
    "/{sensor_id}/configurations",
    response_model=SensorConfigurationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Commit a new versioned configuration for a sensor",
)
def update_sensor_configuration(
    sensor_id: str,
    payload: SensorConfigurationCreateRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> SensorConfigurationResponse:
    """Updates approved configuration options and increments desired version."""
    try:
        config = sensor_service.update_configuration(
            db=db, sensor_id=sensor_id, payload=payload, user=current_user
        )
        return SensorConfigurationResponse.model_validate(config)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@sensors_router.post(
    "/{sensor_id}/configurations/rollback",
    response_model=SensorConfigurationResponse,
    summary="Rollback sensor configuration to a previously approved version",
)
def rollback_sensor_configuration(
    sensor_id: str,
    payload: SensorConfigurationRollbackRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> SensorConfigurationResponse:
    """Reverts configuration to a designated prior version."""
    try:
        config = sensor_service.rollback_configuration(
            db=db,
            sensor_id=sensor_id,
            target_version=payload.target_version,
            reason=payload.change_reason,
            user=current_user,
        )
        return SensorConfigurationResponse.model_validate(config)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# -----------------------------------------------------------------------------
# Maintenance Mode
# -----------------------------------------------------------------------------

@sensors_router.post(
    "/{sensor_id}/maintenance",
    response_model=SensorResponse,
    summary="Toggle maintenance mode for a sensor",
)
def set_sensor_maintenance_mode(
    sensor_id: str,
    payload: MaintenanceModeRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_SENSORS)),
) -> SensorResponse:
    """Puts a sensor into maintenance mode or returns it to active operations."""
    try:
        sensor = sensor_service.set_maintenance_mode(
            db=db,
            sensor_id=sensor_id,
            enabled=payload.enabled,
            reason=payload.reason,
            user=current_user,
        )
        return SensorResponse.model_validate(sensor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# -----------------------------------------------------------------------------
# Operational Alerts
# -----------------------------------------------------------------------------

@sensors_router.get(
    "/alerts/operational",
    response_model=OperationalAlertListResponse,
    summary="List operational health alerts segregated from threat detections",
)
def list_operational_alerts(
    sensor_id: Optional[str] = Query(None, description="Filter by sensor ID"),
    category: Optional[str] = Query(None, description="Filter by alert category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, ACKNOWLEDGED, RESOLVED)"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> OperationalAlertListResponse:
    """Queries operational alerts with filtering and pagination."""
    total, items = sensor_service.list_operational_alerts(
        db=db,
        sensor_id=sensor_id,
        category=category,
        severity=severity,
        status=status,
        page=page,
        limit=limit,
    )
    return OperationalAlertListResponse(
        total=total,
        page=page,
        limit=limit,
        items=[OperationalAlertResponse.model_validate(a) for a in items],
    )


@sensors_router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=OperationalAlertResponse,
    summary="Acknowledge an open operational alert",
)
def acknowledge_operational_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.ACKNOWLEDGE_ALERTS)),
) -> OperationalAlertResponse:
    """Marks an operational alert as acknowledged."""
    try:
        alert = sensor_service.acknowledge_operational_alert(db, alert_id, user=current_user)
        return OperationalAlertResponse.model_validate(alert)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@sensors_router.post(
    "/alerts/{alert_id}/resolve",
    response_model=OperationalAlertResponse,
    summary="Resolve an operational alert with resolution notes",
)
def resolve_operational_alert(
    alert_id: str,
    payload: OperationalAlertResolveRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.RESOLVE_ALERTS)),
) -> OperationalAlertResponse:
    """Marks an operational alert as resolved with documented justification."""
    try:
        alert = sensor_service.resolve_operational_alert(
            db, alert_id, notes=payload.resolution_notes, user=current_user
        )
        return OperationalAlertResponse.model_validate(alert)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@sensors_router.post(
    "/evaluate-health",
    summary="Trigger a sweep to evaluate sensor health and update operational statuses",
)
def sweep_sensor_health(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Sweeps all registered sensors, updates health status, and triggers overdue/offline alerts."""
    sensors = db.query(SensorModel).filter(SensorModel.operational_status != "RETIRED").all()
    updated = []
    for s in sensors:
        op_stat, h_stat = SensorHealthEngine.evaluate_sensor_health(db, s)
        updated.append({"sensor_id": s.sensor_id, "operational_status": op_stat, "health_status": h_stat})
    db.commit()
    return {"total_evaluated": len(updated), "results": updated}
