"""SQLAlchemy models for raw and normalized security events."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, Index, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class RawEventModel(Base):
    """Sanitized raw security telemetry captured from decoys."""
    
    __tablename__ = "raw_events"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    raw_event_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, unique=True, nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    decoy_id: Mapped[str] = mapped_column(String(64), ForeignKey("honeypots.decoy_id", ondelete="RESTRICT"), nullable=False, index=True)
    event_source_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    sanitized_payload: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    provenance: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VALID")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    honeypot: Mapped["HoneypotModel"] = relationship("HoneypotModel", back_populates="raw_events")
    security_event: Mapped["SecurityEventModel"] = relationship("SecurityEventModel", back_populates="raw_event", uselist=False)


class SecurityEventModel(Base):
    """Normalized security event used for detection, correlation, and SOC analytics."""
    
    __tablename__ = "security_events"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, unique=True, nullable=False, index=True)
    raw_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("raw_events.raw_event_id", ondelete="RESTRICT"), unique=True, nullable=False, index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    decoy_id: Mapped[str] = mapped_column(String(64), ForeignKey("honeypots.decoy_id", ondelete="RESTRICT"), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    observed_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    target_service: Mapped[str] = mapped_column(String(32), nullable=False)
    target_port: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    normalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    sanitized_metadata: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    provenance: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    processing_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PROCESSED")
    deduplication_reference: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Table-level constraints and composite indexes
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('SUCCESS', 'FAILURE', 'BLOCKED', 'ERROR', 'UNKNOWN')",
            name="ck_sec_events_outcome"
        ),
        Index("idx_sec_events_src_time", "source_address", "observed_at"),
        Index("idx_sec_events_decoy_time", "decoy_id", "observed_at"),
    )
    
    # Relationships
    raw_event: Mapped[RawEventModel] = relationship("RawEventModel", back_populates="security_event")
    honeypot: Mapped["HoneypotModel"] = relationship("HoneypotModel", back_populates="security_events")
    alert_evidence_links: Mapped[list["AlertEvidenceModel"]] = relationship("AlertEvidenceModel", back_populates="security_event")
    audit_logs: Mapped[list["EventAuditLogModel"]] = relationship("EventAuditLogModel", back_populates="security_event", cascade="all, delete-orphan")


class EventAuditLogModel(Base):
    """Immutable audit trail of analyst notes, review states, and investigation associations for security events."""
    
    __tablename__ = "event_audit_logs"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("security_events.event_id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)  # NOTE, REVIEW_STATUS_CHANGE, INVESTIGATION_ASSOCIATION
    analyst_id: Mapped[str] = mapped_column(String(128), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNREVIEWED")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra_data: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    security_event: Mapped["SecurityEventModel"] = relationship("SecurityEventModel", back_populates="audit_logs")


