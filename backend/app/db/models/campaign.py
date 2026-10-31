"""SQLAlchemy models for Threat Campaign Intelligence and Evidence-Based Investigation Grouping (Task P24)."""

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


class InvestigationClusterModel(Base):
    """Investigation Cluster grouping related observed activity, sessions, source profiles, and sequences."""

    __tablename__ = "investigation_clusters"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False, default="CANDIDATE", index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM", index=True)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNREVIEWED", index=True)
    analyst_owner: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cluster_methodology_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    evidence_summary: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    destination_cluster_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "lifecycle_status IN ('CANDIDATE', 'UNDER_REVIEW', 'ACTIVE', 'MONITORING', 'CLOSED', 'MERGED', 'SPLIT')",
            name="ck_cluster_lifecycle_status",
        ),
        CheckConstraint(
            "priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_cluster_priority",
        ),
        CheckConstraint(
            "review_status IN ('UNREVIEWED', 'UNDER_REVIEW', 'ACCEPTED', 'DISMISSED')",
            name="ck_cluster_review_status",
        ),
        Index("ix_cluster_status_prio", "lifecycle_status", "priority"),
        Index("ix_cluster_last_obs", "last_observed_at"),
    )

    # Relationships
    members: Mapped[list["ClusterMembershipModel"]] = relationship(
        "ClusterMembershipModel", back_populates="cluster", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["ClusterEvidenceModel"]] = relationship(
        "ClusterEvidenceModel", back_populates="cluster", cascade="all, delete-orphan"
    )
    outgoing_relationships: Mapped[list["ClusterRelationshipModel"]] = relationship(
        "ClusterRelationshipModel",
        foreign_keys="ClusterRelationshipModel.source_cluster_id",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list["ClusterAuditLogModel"]] = relationship(
        "ClusterAuditLogModel", back_populates="cluster", cascade="all, delete-orphan"
    )


class ClusterMembershipModel(Base):
    """Entity linking an observed item (session, source profile, alert, sequence, event) to a cluster."""

    __tablename__ = "cluster_memberships"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("investigation_clusters.cluster_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    member_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    member_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    association_method: Mapped[str] = mapped_column(String(64), nullable=False, default="BEHAVIORAL_SEQUENCE_OVERLAP")
    association_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=70)
    evidence_references: Mapped[list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    membership_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PROPOSED", index=True)
    analyst_review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "member_type IN ('SESSION', 'SOURCE_PROFILE', 'ALERT', 'SEQUENCE', 'EVENT')",
            name="ck_cluster_member_type",
        ),
        CheckConstraint(
            "membership_status IN ('PROPOSED', 'ACCEPTED', 'REJECTED', 'REMOVED')",
            name="ck_cluster_member_status",
        ),
        CheckConstraint(
            "analyst_review_status IN ('PENDING', 'APPROVED', 'DISMISSED')",
            name="ck_cluster_member_review_status",
        ),
        UniqueConstraint("cluster_id", "member_type", "member_id", name="uq_cluster_member"),
    )

    cluster: Mapped["InvestigationClusterModel"] = relationship("InvestigationClusterModel", back_populates="members")


class ClusterEvidenceModel(Base):
    """Supporting or contradicting evidence items attached to an investigation cluster."""

    __tablename__ = "cluster_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    evidence_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    cluster_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("investigation_clusters.cluster_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_description: Mapped[str] = mapped_column(Text, nullable=False)
    contribution_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="SUPPORTING", index=True)
    evidence_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "classification IN ('SUPPORTING', 'CONTRADICTING')",
            name="ck_cluster_evidence_classification",
        ),
        Index("ix_cluster_evidence_type", "cluster_id", "evidence_type"),
    )

    cluster: Mapped["InvestigationClusterModel"] = relationship("InvestigationClusterModel", back_populates="evidence")


class ClusterRelationshipModel(Base):
    """Inter-cluster relationship indicating shared techniques, progression, or sub-campaign structure."""

    __tablename__ = "cluster_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    relationship_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    source_cluster_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("investigation_clusters.cluster_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_cluster_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("investigation_clusters.cluster_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    supporting_evidence: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    relationship_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=70)
    analyst_review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PROPOSED", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "relationship_type IN ('BEHAVIORAL_SIMILARITY', 'SEQUENTIAL_PROGRESSION', 'SHARED_INFRASTRUCTURE', 'SHARED_TECHNIQUE_SET', 'SUB_CAMPAIGN')",
            name="ck_cluster_relationship_type",
        ),
        CheckConstraint(
            "analyst_review_status IN ('PROPOSED', 'ACCEPTED', 'REJECTED')",
            name="ck_cluster_relationship_review_status",
        ),
        UniqueConstraint("source_cluster_id", "target_cluster_id", "relationship_type", name="uq_cluster_pair_rel"),
    )


class ClusterAuditLogModel(Base):
    """Immutable audit trail for investigation clusters (lifecycle changes, merges, splits, reviews)."""

    __tablename__ = "cluster_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("investigation_clusters.cluster_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(128), nullable=True)
    previous_state: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    new_state: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    cluster: Mapped["InvestigationClusterModel"] = relationship("InvestigationClusterModel", back_populates="audit_logs")

