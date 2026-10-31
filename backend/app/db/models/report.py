"""SQLAlchemy declarative model for SnareSight Security Reports (Task P30).

Stores generated executive reports, forensic summaries, CSV/PDF artifacts,
audit metadata, applied filter criteria, and analyst attribution.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Integer, LargeBinary, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class SecurityReportModel(Base):
    """Persisted security audit and executive analytics reports."""

    __tablename__ = "security_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    report_title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False, default="EXECUTIVE_SUMMARY")
    time_range_label: Mapped[str] = mapped_column(String(64), nullable=False, default="24h")
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(128), nullable=False, default="analyst_soc_user")
    file_format: Mapped[str] = mapped_column(String(16), nullable=False, default="PDF")
    filters_applied: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    summary_metrics: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETED")
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pdf_content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    csv_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        Index("ix_security_reports_created_at", "created_at"),
        Index("ix_security_reports_generated_by", "generated_by"),
        Index("ix_security_reports_type", "report_type"),
    )

