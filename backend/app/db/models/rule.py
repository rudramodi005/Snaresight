"""SQLAlchemy model for configurable detection rules."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Text, DateTime, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class DetectionRuleModel(Base):
    """Behavioral detection rule definition."""
    
    __tablename__ = "detection_rules"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    configuration: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    
    __table_args__ = (
        CheckConstraint(
            "severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_detection_rules_severity"
        ),
    )
    
    # Relationships
    alerts: Mapped[list["AlertModel"]] = relationship("AlertModel", back_populates="detection_rule")

