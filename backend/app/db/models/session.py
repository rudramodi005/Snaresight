"""SQLAlchemy model for honeypot visitor sessions."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class SessionModel(Base):
    """Session entity tracking correlated multi-step attacker visits."""
    
    __tablename__ = "sessions"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    decoy_id: Mapped[str] = mapped_column(String(64), ForeignKey("honeypots.decoy_id", ondelete="RESTRICT"), nullable=False, index=True)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent_summary: Mapped[str | None] = mapped_column(String(256), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provenance: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    session_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    honeypot: Mapped["HoneypotModel"] = relationship("HoneypotModel", back_populates="sessions")

