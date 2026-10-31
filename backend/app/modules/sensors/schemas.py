"""Pydantic schemas for Honeypot Sensor Management, Health Monitoring, and Operational Alerts."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# -------------------------------------------------------------------------
# SENSOR INVENTORY SCHEMAS
# -------------------------------------------------------------------------

class SensorCreateRequest(BaseModel):
    sensor_id: str = Field(..., min_length=3, max_length=64, description="Unique internal sensor identifier")
    name: str = Field(..., min_length=2, max_length=128, description="Display name for sensor")
    sensor_type: str = Field("WEB_LOGIN_DECOY", description="Sensor archetype: WEB_LOGIN_DECOY, COWRIE_SSH, GENERIC_COLLECTOR")
    sensor_version: str = Field("1.0.0", description="Sensor software version")
    deployment_environment: str = Field("isolated_lab", description="isolated_lab, dmz_canary, staging, production")
    lab_zone: str = Field("zone_alpha", description="Network or honeynet zone")
    heartbeat_interval_seconds: int = Field(60, ge=10, le=3600, description="Expected interval between heartbeats")
    supported_telemetry_types: List[str] = Field(default_factory=lambda: ["http_request", "auth_attempt", "session_event"])
    admin_notes: Optional[str] = None
    initial_config: Optional[Dict[str, Any]] = None


class SensorUpdateRequest(BaseModel):
    name: Optional[str] = None
    sensor_version: Optional[str] = None
    deployment_environment: Optional[str] = None
    lab_zone: Optional[str] = None
    heartbeat_interval_seconds: Optional[int] = Field(None, ge=10, le=3600)
    supported_telemetry_types: Optional[List[str]] = None
    admin_notes: Optional[str] = None


class SensorStatusUpdateRequest(BaseModel):
    operational_status: str = Field(..., description="REGISTERED, ACTIVE, DEGRADED, OFFLINE, MAINTENANCE, DISABLED, RETIRED")
    reason: str = Field(..., min_length=3, description="Administrative justification")


class MaintenanceModeRequest(BaseModel):
    enabled: bool = Field(..., description="True to enter maintenance, False to exit")
    reason: str = Field(..., min_length=3, description="Reason for maintenance mode toggle")


class SensorCredentialResponse(BaseModel):
    id: Any
    key_id: str
    sensor_id: str
    key_prefix: str
    status: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SensorRegistrationResult(BaseModel):
    sensor: Any
    credential: SensorCredentialResponse
    raw_api_key: str = Field(..., description="Raw secret API key shown ONLY ONCE on creation/rotation")


class SensorResponse(BaseModel):
    id: Any
    sensor_id: str
    name: str
    sensor_type: str
    sensor_version: str
    deployment_environment: str
    lab_zone: str
    operational_status: str
    health_status: str
    heartbeat_interval_seconds: int
    missed_heartbeat_count: int
    last_heartbeat_at: Optional[datetime] = None
    last_telemetry_at: Optional[datetime] = None
    current_config_version: str
    supported_telemetry_types: List[str]
    admin_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SensorDetailResponse(SensorResponse):
    credentials: List[SensorCredentialResponse] = []
    recent_heartbeats: List[Any] = []
    current_configuration: Optional[Any] = None
    open_operational_alerts: List[Any] = []


class SensorListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[SensorResponse]


# -------------------------------------------------------------------------
# HEARTBEAT & HEALTH SCHEMAS
# -------------------------------------------------------------------------

class HeartbeatSubmitRequest(BaseModel):
    sensor_id: str = Field(..., description="Sensor unique identifier")
    status: str = Field("HEALTHY", description="HEALTHY, DEGRADED, ERROR")
    latency_ms: float = Field(0.0, ge=0.0)
    metrics_payload: Dict[str, Any] = Field(default_factory=dict, description="Vitals: cpu_percent, memory_mb, events_buffered")
    error_category: Optional[str] = None


class HeartbeatRecordResponse(BaseModel):
    id: Any
    sensor_id: str
    timestamp: datetime
    status: str
    latency_ms: float
    metrics_payload: Dict[str, Any]
    error_category: Optional[str] = None

    class Config:
        from_attributes = True


# -------------------------------------------------------------------------
# CONFIGURATION MANAGEMENT SCHEMAS
# -------------------------------------------------------------------------

class SensorConfigurationCreateRequest(BaseModel):
    version: str = Field(..., min_length=1, max_length=32, description="Semantic version string (e.g. 1.1.0)")
    config_payload: Dict[str, Any] = Field(..., description="Key-value approved configuration settings")
    change_reason: str = Field(..., min_length=3, description="Justification for configuration revision")


class SensorConfigurationRollbackRequest(BaseModel):
    target_version: str = Field(..., description="Target version to roll back to")
    change_reason: str = Field(..., min_length=3, description="Reason for rollback")


class SensorConfigurationResponse(BaseModel):
    id: Any
    sensor_id: str
    version: str
    config_payload: Dict[str, Any]
    is_current: bool
    change_reason: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# -------------------------------------------------------------------------
# OPERATIONAL ALERTS SCHEMAS
# -------------------------------------------------------------------------

class OperationalAlertResponse(BaseModel):
    id: Any
    alert_id: str
    sensor_id: str
    alert_category: str
    severity: str
    status: str
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_payload: Dict[str, Any]
    recommended_action: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class OperationalAlertListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[OperationalAlertResponse]


class OperationalAlertAcknowledgeRequest(BaseModel):
    pass


class OperationalAlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=3, description="Resolution justification and actions taken")


# -------------------------------------------------------------------------
# OPERATIONS DASHBOARD SUMMARY
# -------------------------------------------------------------------------

class SensorOperationsSummary(BaseModel):
    total_registered_sensors: int
    active_sensors: int
    degraded_sensors: int
    offline_sensors: int
    maintenance_sensors: int
    disabled_sensors: int
    retired_sensors: int
    last_telemetry_receipt: Optional[datetime] = None
    total_telemetry_events_received: int
    ingestion_success_rate: float
    open_operational_alerts_count: int
    critical_operational_alerts_count: int
    sensors_by_type: Dict[str, int]
    sensors_by_environment: Dict[str, int]

