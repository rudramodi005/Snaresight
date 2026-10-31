"""SQLAlchemy models for Security Monitoring, Incident Readiness, Backup, Recovery, and Operational Resilience."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class InternalSecurityEventModel(Base):
    """Immutable event stream monitoring SnareSight's own control plane security."""

    __tablename__ = "internal_security_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    actor_username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    source_component: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS")
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="INFO", index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    metadata_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_internal_events_type_time", "event_type", "timestamp"),
    )


class InternalSecurityAlertModel(Base):
    """Rule-triggered internal platform security alert."""

    __tablename__ = "internal_security_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN", index=True)

    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)

    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_internal_alerts_rule_status", "rule_id", "status"),
        Index("ix_internal_alerts_sev_status", "severity", "status"),
    )


class ComponentHealthRecordModel(Base):
    """Time-series health snapshot of individual platform components."""

    __tablename__ = "component_health_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    component_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="HEALTHY")
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    details: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_comp_health_name_time", "component_name", "checked_at"),
    )


class DatabaseBackupModel(Base):
    """Managed database backup artifact record with cryptographic checksum."""

    __tablename__ = "database_backups"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    backup_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    backup_type: Mapped[str] = mapped_column(String(32), nullable=False, default="FULL")  # FULL, PRE_MIGRATION, MANUAL
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETED", index=True)  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checksum_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    storage_location_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    retention_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    restore_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    restore_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    restore_tests: Mapped[List["RestoreTestRecordModel"]] = relationship(
        "RestoreTestRecordModel", back_populates="backup", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_database_backups_status_time", "status", "started_at"),
    )


class RestoreTestRecordModel(Base):
    """Audit log of isolated backup restoration tests proving recovery capability."""

    __tablename__ = "restore_test_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    test_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    backup_id: Mapped[str] = mapped_column(String(64), ForeignKey("database_backups.backup_id", ondelete="CASCADE"), nullable=False, index=True)
    test_environment: Mapped[str] = mapped_column(String(64), nullable=False, default="isolated_sandbox_db")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS")  # SUCCESS, FAILED
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    schema_compatibility_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    table_count_verified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    integrity_check_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verified_by: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    diagnostic_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    backup: Mapped["DatabaseBackupModel"] = relationship("DatabaseBackupModel", back_populates="restore_tests")


class DisasterRecoveryConfigModel(Base):
    """Target recovery objectives (RPO/RTO) and backup retention governance."""

    __tablename__ = "dr_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    config_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, default="default")
    rpo_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    rto_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    backup_frequency_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    backup_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    cold_archive_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    auto_restore_test_frequency_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class DisasterRecoveryChecklistModel(Base):
    """Structured recovery runbooks and step status across 5 failure scenarios."""

    __tablename__ = "dr_checklists"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    scenario_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scenario_title: Mapped[str] = mapped_column(String(128), nullable=False)
    current_status: Mapped[str] = mapped_column(String(32), nullable=False, default="READINESS_VERIFIED")
    checklist_items: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    last_reviewed_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class InternalIncidentModel(Base):
    """Platform security incident entity for internal control-plane handling."""

    __tablename__ = "internal_security_incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN", index=True)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    assigned_administrator: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    affected_components: Mapped[List[str]] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    linked_alert_ids: Mapped[List[str]] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    containment_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery_actions_taken: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[List["InternalIncidentNoteModel"]] = relationship(
        "InternalIncidentNoteModel", back_populates="incident", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_internal_incidents_status_sev", "status", "severity"),
    )


class InternalIncidentNoteModel(Base):
    """Administrator observation or containment note on an internal security incident."""

    __tablename__ = "internal_incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[str] = mapped_column(String(64), ForeignKey("internal_security_incidents.incident_id", ondelete="CASCADE"), nullable=False, index=True)
    author_username: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    note_type: Mapped[str] = mapped_column(String(32), nullable=False, default="OBSERVATION")  # OBSERVATION, CONTAINMENT, RECOVERY, ROOT_CAUSE
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    incident: Mapped["InternalIncidentModel"] = relationship("InternalIncidentModel", back_populates="notes")

