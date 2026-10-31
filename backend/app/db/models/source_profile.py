"""SQLAlchemy models for multi-session source profiling and behavioral intelligence (Task P23)."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    Integer,
    Float,
    SmallInteger,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class SourceProfileModel(Base):
    """Observed Source Profile capturing multi-session activity and behavioral patterns."""

    __tablename__ = "source_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    display_label: Mapped[str] = mapped_column(String(128), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    ip_family: Mapped[str] = mapped_column(String(10), nullable=False, default="IPv4")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    total_sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_alerts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_categories: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_honeypots: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    protocol_distribution: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    behavioral_summary: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    profile_priority: Mapped[str] = mapped_column(String(20), nullable=False, default="INSUFFICIENT_DATA", index=True)
    profile_status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    is_shared_infrastructure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    analyst_notes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_aggregated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "profile_priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INSUFFICIENT_DATA')",
            name="ck_source_profile_priority",
        ),
        CheckConstraint(
            "profile_status IN ('ACTIVE', 'DORMANT', 'ARCHIVED')",
            name="ck_source_profile_status",
        ),
        CheckConstraint(
            "ip_family IN ('IPv4', 'IPv6')",
            name="ck_source_profile_ip_family",
        ),
        Index("ix_source_profile_ip_status", "source_ip", "profile_status"),
        Index("ix_source_profile_priority_last_obs", "profile_priority", "last_observed_at"),
    )

    # Relationships
    sessions: Mapped[list["SourceProfileSessionModel"]] = relationship(
        "SourceProfileSessionModel", back_populates="profile", cascade="all, delete-orphan"
    )
    features: Mapped[list["SourceProfileFeatureModel"]] = relationship(
        "SourceProfileFeatureModel", back_populates="profile", cascade="all, delete-orphan"
    )
    history: Mapped[list["SourceProfileHistoryModel"]] = relationship(
        "SourceProfileHistoryModel", back_populates="profile", cascade="all, delete-orphan"
    )
    recurrences: Mapped[list["SourceProfileRecurrenceModel"]] = relationship(
        "SourceProfileRecurrenceModel", back_populates="profile", cascade="all, delete-orphan"
    )


class SourceProfileSessionModel(Base):
    """Junction linking an Observed Source Profile to correlated Activity Sessions."""

    __tablename__ = "source_profile_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("source_profiles.profile_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("activity_sessions.session_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    associated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    confidence_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=100)
    association_type: Mapped[str] = mapped_column(String(32), nullable=False, default="DIRECT_IP")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("profile_id", "session_id", name="uq_source_profile_session"),
        CheckConstraint(
            "association_type IN ('DIRECT_IP', 'FINGERPRINT', 'ANALYST_MERGED', 'SUBNET_PROXIMITY')",
            name="ck_source_profile_session_association_type",
        ),
    )

    profile: Mapped["SourceProfileModel"] = relationship("SourceProfileModel", back_populates="sessions")


class SourceProfileFeatureModel(Base):
    """Behavioral feature metrics computed across specific time windows for a profile."""

    __tablename__ = "source_profile_features"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("source_profiles.profile_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    window_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    interaction_tempo: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    burstiness_ratio: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    concurrency_level: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    auth_attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_usernames_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    path_traversal_probes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_paths_probed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_honeypots_targeted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tactic_distribution: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    technique_distribution: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    severity_breakdown: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "window_type IN ('1H', '24H', '7D', '30D', 'ALL_TIME')",
            name="ck_source_profile_window_type",
        ),
        UniqueConstraint("profile_id", "window_type", name="uq_profile_window_feature"),
    )

    profile: Mapped["SourceProfileModel"] = relationship("SourceProfileModel", back_populates="features")


class SourceProfileHistoryModel(Base):
    """Audit trail for changes to source profiles, analyst notes, and association reviews."""

    __tablename__ = "source_profile_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("source_profiles.profile_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    analyst_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_value: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    profile: Mapped["SourceProfileModel"] = relationship("SourceProfileModel", back_populates="history")


class SourceProfileRecurrenceModel(Base):
    """Tracks detected recurrences of behavioral patterns from returning sources."""

    __tablename__ = "source_profile_recurrences"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("source_profiles.profile_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dormant_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    dormant_interval_display: Mapped[str] = mapped_column(String(64), nullable=False)
    reactivation_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reactivation_session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pattern_similarity: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    profile: Mapped["SourceProfileModel"] = relationship("SourceProfileModel", back_populates="recurrences")

