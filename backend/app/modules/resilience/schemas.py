"""Pydantic schemas for Security Monitoring, Incident Readiness, Backup, Recovery, and Resilience."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# HEALTH & DIAGNOSTICS SCHEMAS
# -----------------------------------------------------------------------------

class ComponentHealthItem(BaseModel):
    name: str
    status: str  # HEALTHY, DEGRADED, CRITICAL, UNKNOWN
    latency_ms: float = 0.0
    checked_at: datetime
    details: Dict[str, Any] = Field(default_factory=dict)


class SystemHealthOverviewResponse(BaseModel):
    overall_status: str  # HEALTHY, DEGRADED, CRITICAL
    timestamp: datetime
    uptime_seconds: float
    components: List[ComponentHealthItem]
    open_internal_alerts_count: int
    critical_alerts_count: int
    last_successful_backup: Optional[datetime] = None
    rpo_compliance_status: str  # COMPLIANT, WARNING, BREACHED
    rto_compliance_status: str  # COMPLIANT, WARNING, BREACHED


# -----------------------------------------------------------------------------
# INTERNAL SECURITY EVENTS & ALERTS SCHEMAS
# -----------------------------------------------------------------------------

class InternalSecurityEventCreate(BaseModel):
    event_type: str = Field(..., max_length=64, description="Event archetype, e.g. AUTH_FAILURE, ROLE_CHANGE, CFG_EDIT")
    actor_username: Optional[str] = Field(None, max_length=64)
    actor_role: Optional[str] = Field(None, max_length=32)
    source_component: str = Field(..., max_length=64, description="FastAPI, Ingestion, Auth, Database, etc.")
    outcome: str = Field("SUCCESS", max_length=32, description="SUCCESS, FAILURE, BLOCKED, ERROR")
    severity: str = Field("INFO", max_length=32, description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    correlation_id: Optional[str] = Field(None, max_length=64)
    metadata_payload: Dict[str, Any] = Field(default_factory=dict)


class InternalSecurityEventResponse(BaseModel):
    id: Any
    event_type: str
    timestamp: datetime
    actor_username: Optional[str] = None
    actor_role: Optional[str] = None
    source_component: str
    outcome: str
    severity: str
    correlation_id: Optional[str] = None
    metadata_payload: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class InternalSecurityAlertResponse(BaseModel):
    id: Any
    alert_id: str
    rule_id: str
    rule_version: str
    title: str
    description: str
    severity: str
    status: str
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_payload: Dict[str, Any] = Field(default_factory=dict)
    recommended_action: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class InternalAlertAcknowledgeRequest(BaseModel):
    notes: Optional[str] = None


class InternalAlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=3, description="Resolution rationale and remedial actions")


# -----------------------------------------------------------------------------
# BACKUP & RESTORE TEST SCHEMAS
# -----------------------------------------------------------------------------

class DatabaseBackupCreateRequest(BaseModel):
    backup_type: str = Field("MANUAL", description="FULL, PRE_MIGRATION, MANUAL")
    retention_hold: bool = Field(False, description="Protect backup from automatic lifecycle pruning")


class RestoreTestRunRequest(BaseModel):
    test_environment: str = Field("isolated_sandbox_db", description="Target isolated test container or schema")


class RestoreTestResponse(BaseModel):
    id: Any
    test_id: str
    backup_id: str
    test_environment: str
    status: str
    duration_seconds: float
    schema_compatibility_verified: bool
    table_count_verified: int
    integrity_check_passed: bool
    verified_by: str
    verified_at: datetime
    diagnostic_notes: Optional[str] = None

    class Config:
        from_attributes = True


class DatabaseBackupResponse(BaseModel):
    id: Any
    backup_id: str
    backup_type: str
    status: str
    size_bytes: int
    checksum_sha256: Optional[str] = None
    storage_location_ref: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_category: Optional[str] = None
    error_details: Optional[str] = None
    initiated_by: str
    retention_hold: bool
    restore_verified: bool
    restore_verified_at: Optional[datetime] = None
    restore_tests: List[RestoreTestResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


# -----------------------------------------------------------------------------
# DISASTER RECOVERY & CHECKLIST SCHEMAS
# -----------------------------------------------------------------------------

class DisasterRecoveryConfigResponse(BaseModel):
    id: Any
    config_name: str
    rpo_target_minutes: int
    rto_target_minutes: int
    backup_frequency_hours: int
    backup_retention_days: int
    cold_archive_retention_days: int
    auto_restore_test_frequency_days: int
    updated_by: Optional[str] = None
    updated_at: datetime
    actual_rpo_minutes: float
    actual_rto_estimate_minutes: float
    rpo_status: str  # COMPLIANT, BREACHED
    rto_status: str  # COMPLIANT, BREACHED

    class Config:
        from_attributes = True


class DisasterRecoveryConfigUpdateRequest(BaseModel):
    rpo_target_minutes: int = Field(..., ge=5, le=1440)
    rto_target_minutes: int = Field(..., ge=5, le=720)
    backup_frequency_hours: int = Field(..., ge=1, le=168)
    backup_retention_days: int = Field(..., ge=1, le=3650)
    cold_archive_retention_days: int = Field(..., ge=1, le=3650)
    auto_restore_test_frequency_days: int = Field(..., ge=1, le=365)


class ChecklistItem(BaseModel):
    item_id: str
    step_number: int
    title: str
    instruction: str
    completed: bool = False
    verification_criterion: str
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    notes: Optional[str] = None


class DisasterRecoveryChecklistResponse(BaseModel):
    id: Any
    scenario_id: str
    scenario_title: str
    current_status: str  # READINESS_VERIFIED, ACTION_REQUIRED, ACTIVE_DRILL, DRILL_COMPLETED
    checklist_items: List[Dict[str, Any]] = Field(default_factory=list)
    last_reviewed_by: Optional[str] = None
    last_reviewed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ChecklistScenarioUpdateRequest(BaseModel):
    current_status: str = Field(..., description="READINESS_VERIFIED, ACTION_REQUIRED, ACTIVE_DRILL, DRILL_COMPLETED")
    checklist_items: List[Dict[str, Any]] = Field(..., description="Full updated items array")


class ChecklistItemToggleRequest(BaseModel):
    item_id: str
    completed: bool
    notes: Optional[str] = None


# -----------------------------------------------------------------------------
# INTERNAL SECURITY INCIDENT SCHEMAS
# -----------------------------------------------------------------------------

class InternalIncidentNoteCreateRequest(BaseModel):
    content: str = Field(..., min_length=2, description="Observation or remedial note")
    note_type: str = Field("OBSERVATION", description="OBSERVATION, CONTAINMENT, RECOVERY, ROOT_CAUSE")


class InternalIncidentNoteResponse(BaseModel):
    id: Any
    incident_id: str
    author_username: str
    content: str
    note_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class InternalIncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=128)
    description: str = Field(..., min_length=5)
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    affected_components: List[str] = Field(default_factory=list)
    linked_alert_ids: List[str] = Field(default_factory=list)
    assigned_administrator: Optional[str] = None


class InternalIncidentUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    assigned_administrator: Optional[str] = None
    affected_components: Optional[List[str]] = None
    containment_notes: Optional[str] = None
    recovery_actions_taken: Optional[str] = None
    resolution_summary: Optional[str] = None


class InternalIncidentResponse(BaseModel):
    id: Any
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    assigned_administrator: Optional[str] = None
    affected_components: List[str] = Field(default_factory=list)
    linked_alert_ids: List[str] = Field(default_factory=list)
    containment_notes: Optional[str] = None
    recovery_actions_taken: Optional[str] = None
    resolution_summary: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    notes: List[InternalIncidentNoteResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


# -----------------------------------------------------------------------------
# AUDIT VERIFICATION SCHEMAS
# -----------------------------------------------------------------------------

class AuditVerificationResponse(BaseModel):
    verified: bool
    total_records: int
    verified_hashes: int
    corrupted_records: int
    details: str
    timestamp: datetime

