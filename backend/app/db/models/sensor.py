"""SQLAlchemy models for Honeypot Sensor Management, Health Monitoring, and Operational Reliability."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class SensorModel(Base):
    """Central managed inventory record for honeypot sensors and collector forwarders."""

    __tablename__ = "sensors"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # WEB_LOGIN_DECOY, COWRIE_SSH, GENERIC_COLLECTOR
    sensor_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    deployment_environment: Mapped[str] = mapped_column(String(32), nullable=False, default="isolated_lab", index=True)
    lab_zone: Mapped[str] = mapped_column(String(64), nullable=False, default="zone_alpha")
    
    # Lifecycle: REGISTERED, ACTIVE, DEGRADED, OFFLINE, MAINTENANCE, DISABLED, RETIRED
    operational_status: Mapped[str] = mapped_column(String(32), nullable=False, default="REGISTERED", index=True)
    # Health: HEALTHY, DEGRADED, CRITICAL, UNKNOWN
    health_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN", index=True)

    heartbeat_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    missed_heartbeat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_telemetry_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    current_config_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    supported_telemetry_types: Mapped[List[str]] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    admin_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    credentials: Mapped[List["SensorCredentialModel"]] = relationship(
        "SensorCredentialModel", back_populates="sensor", cascade="all, delete-orphan"
    )
    heartbeats: Mapped[List["SensorHeartbeatModel"]] = relationship(
        "SensorHeartbeatModel", back_populates="sensor", cascade="all, delete-orphan"
    )
    configurations: Mapped[List["SensorConfigurationModel"]] = relationship(
        "SensorConfigurationModel", back_populates="sensor", cascade="all, delete-orphan"
    )
    operational_alerts: Mapped[List["OperationalAlertModel"]] = relationship(
        "OperationalAlertModel", back_populates="sensor", cascade="all, delete-orphan"
    )
    maintenance_records: Mapped[List["SensorMaintenanceHistoryModel"]] = relationship(
        "SensorMaintenanceHistoryModel", back_populates="sensor", cascade="all, delete-orphan"
    )
    telemetry_metrics: Mapped[List["SensorTelemetryMetricModel"]] = relationship(
        "SensorTelemetryMetricModel", back_populates="sensor", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_sensors_type_status", "sensor_type", "operational_status"),
        Index("ix_sensors_env_status", "deployment_environment", "operational_status"),
    )


class SensorCredentialModel(Base):
    """Cryptographically hashed credential metadata for sensor telemetry and heartbeat auth."""

    __tablename__ = "sensor_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(24), nullable=False)  # Safe masked prefix (e.g. snr_live_ab12...)
    hashed_api_key: Mapped[str] = mapped_column(String(128), nullable=False)  # SHA-256 digest of raw key
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, REVOKED, EXPIRED

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="credentials")


class SensorHeartbeatModel(Base):
    """Time-series heartbeat submission capturing sensor process vitals and health."""

    __tablename__ = "sensor_heartbeats"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="HEALTHY")  # HEALTHY, DEGRADED, ERROR
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metrics_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    error_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="heartbeats")

    __table_args__ = (
        Index("ix_sensor_heartbeats_sensor_time", "sensor_id", "timestamp"),
    )


class SensorConfigurationModel(Base):
    """Versioned configuration record for controlled sensor options."""

    __tablename__ = "sensor_configurations"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    config_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    change_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="configurations")

    __table_args__ = (
        Index("ix_sensor_config_sensor_ver", "sensor_id", "version"),
    )


class OperationalAlertModel(Base):
    """Operational health issue alerts strictly segregated from threat detections."""

    __tablename__ = "operational_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    alert_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, RESOLVED

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

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="operational_alerts")

    __table_args__ = (
        Index("ix_operational_alerts_cat_status", "alert_category", "status"),
        Index("ix_operational_alerts_sensor_status", "sensor_id", "status"),
    )


class SensorMaintenanceHistoryModel(Base):
    """Audit log of planned maintenance transitions and operational downtime."""

    __tablename__ = "sensor_maintenance_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    maintenance_mode_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    initiated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="maintenance_records")


class SensorTelemetryMetricModel(Base):
    """Aggregated window metrics tracking telemetry delivery reliability per sensor."""

    __tablename__ = "sensor_telemetry_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[str] = mapped_column(String(64), ForeignKey("sensors.sensor_id", ondelete="CASCADE"), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    events_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_validated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_persisted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    average_latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    sensor: Mapped["SensorModel"] = relationship("SensorModel", back_populates="telemetry_metrics")

    __table_args__ = (
        Index("ix_sensor_telemetry_metrics_window", "sensor_id", "window_start"),
    )

