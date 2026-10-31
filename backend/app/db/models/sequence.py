"""SQLAlchemy models for multi-session behavioral sequences and attack-chain analysis (Task P22)."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    Integer,
    SmallInteger,
    Text,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class BehavioralSequenceModel(Base):
    """Correlated multi-session behavioral sequence candidate."""

    __tablename__ = "behavioral_sequences"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sequence_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    sequence_pattern: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW", index=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    session_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=70)
    sequence_relevance: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    aggregate_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    analyst_review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNREVIEWED", index=True)
    primary_source_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    primary_decoy_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    correlation_policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    metadata_summary: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "lifecycle_status IN ('NEW', 'OBSERVING', 'UNDER_REVIEW', 'REVIEWED', 'CLOSED', 'DISMISSED')",
            name="ck_seq_lifecycle_status",
        ),
        CheckConstraint(
            "analyst_review_status IN ('UNREVIEWED', 'CONFIRMED_PROGRESSION', 'DISMISSED_COINCIDENCE', 'INCONCLUSIVE')",
            name="ck_seq_analyst_review_status",
        ),
        CheckConstraint(
            "correlation_confidence >= 0 AND correlation_confidence <= 100",
            name="ck_seq_correlation_confidence",
        ),
        CheckConstraint(
            "sequence_relevance >= 0 AND sequence_relevance <= 100",
            name="ck_seq_sequence_relevance",
        ),
        Index("idx_seq_pattern_status", "sequence_pattern", "lifecycle_status"),
        Index("idx_seq_time_window", "first_observed_at", "last_observed_at"),
    )

    # Relationships
    members: Mapped[list["BehavioralSequenceMemberModel"]] = relationship(
        "BehavioralSequenceMemberModel", back_populates="sequence", cascade="all, delete-orphan"
    )
    relationships: Mapped[list["BehavioralSequenceRelationshipModel"]] = relationship(
        "BehavioralSequenceRelationshipModel", back_populates="sequence", cascade="all, delete-orphan"
    )
    evidence_items: Mapped[list["SequenceEvidenceModel"]] = relationship(
        "SequenceEvidenceModel", back_populates="sequence", cascade="all, delete-orphan"
    )
    history_records: Mapped[list["SequenceAssessmentHistoryModel"]] = relationship(
        "SequenceAssessmentHistoryModel", back_populates="sequence", cascade="all, delete-orphan"
    )


class BehavioralSequenceMemberModel(Base):
    """Associated member entity (Session, Event, Detection, ATT&CK Mapping) within a sequence."""

    __tablename__ = "behavioral_sequence_members"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sequence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("behavioral_sequences.sequence_id", ondelete="CASCADE"), nullable=False, index=True
    )
    member_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    member_record_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sequence_position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    relationship_reason: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_method: Mapped[str] = mapped_column(String(32), nullable=False, default="CONTEXTUAL")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("sequence_id", "member_type", "member_record_id", name="uq_seq_member_record"),
        CheckConstraint(
            "member_type IN ('SESSION', 'EVENT', 'DETECTION', 'ATTACK_MAPPING')",
            name="ck_seq_member_type",
        ),
        Index("idx_seq_member_observed", "sequence_id", "observed_at"),
    )

    # Relationships
    sequence: Mapped[BehavioralSequenceModel] = relationship("BehavioralSequenceModel", back_populates="members")


class BehavioralSequenceRelationshipModel(Base):
    """Directed edge connecting sequence members with explicit semantic relationship."""

    __tablename__ = "behavioral_sequence_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sequence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("behavioral_sequences.sequence_id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_member_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("behavioral_sequence_members.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_member_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("behavioral_sequence_members.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=70)
    evidence_payload: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "relationship_type IN ('OBSERVED_BEFORE', 'SAME_TRUSTED_INTERACTION', 'SHARED_SOURCE_CONTEXT', 'BEHAVIORALLY_SIMILAR', 'RELATED_DETECTION_PATTERN', 'ANALYST_LINKED')",
            name="ck_seq_rel_type",
        ),
        Index("idx_seq_rel_pair", "sequence_id", "source_member_id", "target_member_id"),
    )

    # Relationships
    sequence: Mapped[BehavioralSequenceModel] = relationship("BehavioralSequenceModel", back_populates="relationships")
    source_member: Mapped[BehavioralSequenceMemberModel] = relationship(
        "BehavioralSequenceMemberModel", foreign_keys=[source_member_id]
    )
    target_member: Mapped[BehavioralSequenceMemberModel] = relationship(
        "BehavioralSequenceMemberModel", foreign_keys=[target_member_id]
    )


class SequenceEvidenceModel(Base):
    """Field-level evidence trace supporting behavioral sequence linkages."""

    __tablename__ = "sequence_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sequence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("behavioral_sequences.sequence_id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_record_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    evidence_record_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    field_name: Mapped[str] = mapped_column(String(64), nullable=False)
    field_value: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_provenance: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "evidence_record_type IN ('EVENT', 'DETECTION', 'SESSION', 'ATTACK_MAPPING')",
            name="ck_seq_ev_record_type",
        ),
    )

    # Relationships
    sequence: Mapped[BehavioralSequenceModel] = relationship("BehavioralSequenceModel", back_populates="evidence_items")


class SequenceAssessmentHistoryModel(Base):
    """Immutable audit trail of lifecycle changes and analyst reviews."""

    __tablename__ = "sequence_assessment_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    sequence_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("behavioral_sequences.sequence_id", ondelete="CASCADE"), nullable=False, index=True
    )
    assessed_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_action: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # Relationships
    sequence: Mapped[BehavioralSequenceModel] = relationship("BehavioralSequenceModel", back_populates="history_records")

