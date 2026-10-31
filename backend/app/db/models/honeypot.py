"""SQLAlchemy models for registered honeypots and telemetry event sources."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE


class HoneypotModel(Base):
    """Registered honeypot deployment entity."""
    
    __tablename__ = "honeypots"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    decoy_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    decoy_type: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="isolated_lab")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    # Relationships
    raw_events: Mapped[list["RawEventModel"]] = relationship("RawEventModel", back_populates="honeypot", cascade="none")
    security_events: Mapped[list["SecurityEventModel"]] = relationship("SecurityEventModel", back_populates="honeypot", cascade="none")
    sessions: Mapped[list["SessionModel"]] = relationship("SessionModel", back_populates="honeypot", cascade="none")
    alerts: Mapped[list["AlertModel"]] = relationship("AlertModel", back_populates="honeypot", cascade="none")


class EventSourceModel(Base):
    """Telemetry collector agent or forwarder entity."""
    
    __tablename__ = "event_sources"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="isolated_lab")
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ONLINE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

