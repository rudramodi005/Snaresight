"""SQLAlchemy declarative models for Session Correlation and Activity Timelines (Task P21)."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class ActivitySessionModel(Base):
    """Correlated activity session representing a coherent visitor interaction."""

    __tablename__ = "activity_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    decoy_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("honeypots.decoy_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    honeypot_type: Mapped[str] = mapped_column(String(32), nullable=False, default="WEB_LOGIN", index=True)
    explicit_session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    connection_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    correlation_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="EXPLICIT_SESSION_ID", index=True
    )
    correlation_key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_service: Mapped[str] = mapped_column(String(32), nullable=False, default="HTTP")
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="TCP")
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    session_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE", index=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    highest_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    correlation_policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    metadata_summary: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "session_status IN ('ACTIVE', 'IDLE', 'CLOSED', 'TIMED_OUT', 'UNKNOWN')",
            name="ck_activity_session_status",
        ),
        CheckConstraint(
            "correlation_method IN ('EXPLICIT_SESSION_ID', 'EXPLICIT_CONNECTION_ID', 'CONTEXTUAL_FALLBACK', 'STANDALONE')",
            name="ck_activity_session_correlation_method",
        ),
        Index("idx_act_sess_source_decoy", "source_address", "decoy_id"),
        Index("idx_act_sess_status_last_activity", "session_status", "last_activity_at"),
    )


class ActivitySessionEventModel(Base):
    """Junction entity binding a normalized event to a correlated activity session."""

    __tablename__ = "activity_session_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("activity_sessions.session_id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("security_events.event_id", ondelete="RESTRICT"), unique=True, nullable=False, index=True
    )
    raw_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID_TYPE, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    association_method: Mapped[str] = mapped_column(String(32), nullable=False, default="EXPLICIT_SESSION_ID")
    correlation_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=100)
    is_late_arrival: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    associated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("idx_ase_session_observed", "session_id", "observed_at"),
    )


class SessionCorrelationHistoryModel(Base):
    """Audit trace for session lifecycle events, late-arriving attachments, and status changes."""

    __tablename__ = "session_correlation_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_id: Mapped[uuid.UUID | None] = mapped_column(UUID_TYPE, nullable=True, index=True)
    correlation_action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )


class CorrelationPolicyVersionModel(Base):
    """Configurable correlation boundary parameters and timeouts."""

    __tablename__ = "correlation_policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    policy_version: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    policy_name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    inactivity_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=1800)
    max_session_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=43200)
    clock_skew_tolerance_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    configuration: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

