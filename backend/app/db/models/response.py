"""SQLAlchemy declarative models for Defensive Response and Incident Handling Workflow.

Implements ResponseCaseModel, CaseRelationshipModel, CaseNoteModel, ResponseRecommendationModel,
PlaybookDefinitionModel, PlaybookExecutionModel, ResponseApprovalModel, ResponseActionModel,
and EvidencePreservationHoldModel.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class ResponseCaseModel(Base):
    """Core incident handling response case linked to alerts and investigations."""

    __tablename__ = "response_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN", index=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="P3_MEDIUM", index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM", index=True)
    assigned_analyst: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    primary_alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    primary_cluster_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reopen_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'UNDER_REVIEW', 'INVESTIGATING', 'RESPONSE_RECOMMENDED', 'AWAITING_APPROVAL', "
            "'APPROVED', 'REJECTED', 'ACTION_IN_PROGRESS', 'MONITORING', 'RESOLVED', 'CLOSED', 'REOPENED')",
            name="ck_response_cases_status",
        ),
        CheckConstraint(
            "priority IN ('P1_CRITICAL', 'P2_HIGH', 'P3_MEDIUM', 'P4_LOW', 'P5_INFO')",
            name="ck_response_cases_priority",
        ),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="ck_response_cases_severity",
        ),
        Index("idx_response_cases_status_priority", "status", "priority"),
    )

    # Relationships
    relationships: Mapped[list["CaseRelationshipModel"]] = relationship(
        "CaseRelationshipModel", back_populates="case", cascade="all, delete-orphan"
    )
    notes: Mapped[list["CaseNoteModel"]] = relationship(
        "CaseNoteModel", back_populates="case", cascade="all, delete-orphan", order_by="CaseNoteModel.created_at.desc()"
    )
    recommendations: Mapped[list["ResponseRecommendationModel"]] = relationship(
        "ResponseRecommendationModel", back_populates="case", cascade="all, delete-orphan"
    )
    executions: Mapped[list["PlaybookExecutionModel"]] = relationship(
        "PlaybookExecutionModel", back_populates="case", cascade="all, delete-orphan"
    )
    approvals: Mapped[list["ResponseApprovalModel"]] = relationship(
        "ResponseApprovalModel", back_populates="case", cascade="all, delete-orphan"
    )
    actions: Mapped[list["ResponseActionModel"]] = relationship(
        "ResponseActionModel", back_populates="case", cascade="all, delete-orphan"
    )
    preservation_holds: Mapped[list["EvidencePreservationHoldModel"]] = relationship(
        "EvidencePreservationHoldModel", back_populates="case", cascade="all, delete-orphan"
    )


class CaseRelationshipModel(Base):
    """Junction table linking a response case to alerts, events, sessions, profiles, and campaigns."""

    __tablename__ = "case_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    related_entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # ALERT, EVENT, SESSION, SOURCE_PROFILE, CAMPAIGN, MITRE_TECHNIQUE
    related_entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    relationship_reason: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="relationships")


class CaseNoteModel(Base):
    """Analyst comments, notes, resolution reasons, and transition justifications."""

    __tablename__ = "case_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    author_username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    author_role: Mapped[str] = mapped_column(String(32), nullable=False)
    note_type: Mapped[str] = mapped_column(String(32), nullable=False, default="ANALYST_NOTE")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="notes")


class ResponseRecommendationModel(Base):
    """Rule-generated defensive suggestions based on observed telemetry and correlation evidence."""

    __tablename__ = "response_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    recommendation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    triggering_evidence: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    supporting_event_ids: Mapped[list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="HIGH")
    required_permission: Mapped[str] = mapped_column(String(64), nullable=False, default="execute_defensive_action")
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    potential_impact: Mapped[str] = mapped_column(Text, nullable=False)
    reversal_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    decision_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="recommendations")


class PlaybookDefinitionModel(Base):
    """Catalogue of versioned defensive playbooks with step-by-step guidance."""

    __tablename__ = "playbook_definitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    playbook_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_conditions: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    required_inputs: Mapped[list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    workflow_steps: Mapped[list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    required_permission: Mapped[str] = mapped_column(String(64), nullable=False, default="execute_defensive_action")
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class PlaybookExecutionModel(Base):
    """Active or historical execution run of a playbook against a case."""

    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    playbook_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    initiated_by: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="IN_PROGRESS", index=True)
    current_step_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    step_results: Mapped[list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    inputs: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    outcome_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="executions")


class ResponseApprovalModel(Base):
    """Explicit human approval request and decision record."""

    __tablename__ = "response_approvals"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    approval_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    recommendation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="approvals")


class ResponseActionModel(Base):
    """Audit log of executed application-level defensive actions."""

    __tablename__ = "response_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    approval_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    executed_by: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False, default="SUCCESS")
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parameters: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    result_details: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="actions")


class EvidencePreservationHoldModel(Base):
    """Legal/forensic preservation hold preventing routine retention deletion."""

    __tablename__ = "evidence_preservation_holds"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    hold_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("response_cases.case_id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # EVENT, SESSION, ALERT, PAYLOAD, ATTACK_CHAIN
    evidence_identifier: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    integrity_hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retention_hold_status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, RELEASED
    hold_reason: Mapped[str] = mapped_column(Text, nullable=False)
    applied_by: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    released_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    release_justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped["ResponseCaseModel"] = relationship("ResponseCaseModel", back_populates="preservation_holds")

