"""SQLAlchemy models for threat intelligence, MITRE ATT&CK integration, and source profiles."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    Integer,
    SmallInteger,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, UUID_TYPE, JSONB_TYPE


class AttackDatasetVersionModel(Base):
    """Tracks imported MITRE ATT&CK dataset releases, provenance, and active status."""

    __tablename__ = "attack_dataset_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    domain: Mapped[str] = mapped_column(String(32), nullable=False, default="enterprise-attack", index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    stix_version: Mapped[str] = mapped_column(String(16), nullable=False, default="2.1")
    source_repo: Mapped[str] = mapped_column(
        String(128), nullable=False, default="https://github.com/mitre-attack/attack-stix-data"
    )
    source_filename: Mapped[str] = mapped_column(String(128), nullable=False)
    retrieval_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    release_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sha256_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="CANDIDATE", index=True)
    object_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AttackTacticModel(Base):
    """Adversary objective classification (e.g. Initial Access, Credential Access)."""

    __tablename__ = "attack_tactics"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    stix_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tactic_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    tactic_name: Mapped[str] = mapped_column(String(128), nullable=False)
    short_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_references: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackTechniqueModel(Base):
    """Local MITRE ATT&CK technique catalog."""

    __tablename__ = "attack_techniques"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tactic_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    tactic_name: Mapped[str] = mapped_column(String(64), nullable=False)
    framework_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v14.1")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    stix_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tactics: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    platforms: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    data_sources: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_references: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AttackSubtechniqueModel(Base):
    """Specific technical implementation of a parent ATT&CK technique."""

    __tablename__ = "attack_subtechniques"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    stix_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    subtechnique_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    subtechnique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_technique_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    parent_stix_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    platforms: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    external_references: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackRelationshipModel(Base):
    """STIX 2.1 relationships connecting techniques, sub-techniques, and tactics."""

    __tablename__ = "attack_relationships"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    stix_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ref: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_ref: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackImportRunModel(Base):
    """Trace and audit log for dataset dry-run and commit operations."""

    __tablename__ = "attack_import_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    import_run_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    dataset_domain: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(128), nullable=False)
    sha256_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETED")
    initiated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="admin")
    total_parsed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_accepted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_unchanged: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_deprecated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_revoked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    validation_warnings: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    validation_errors: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    execution_duration_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TechniqueMappingModel(Base):
    """Evidence-backed associations between events/alerts and ATT&CK techniques (Task P20)."""

    __tablename__ = "technique_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_TYPE, ForeignKey("security_events.event_id", ondelete="CASCADE"), nullable=True, index=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_TYPE, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=True, index=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("attack_techniques.technique_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    mapping_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "mapping_confidence >= 0 AND mapping_confidence <= 100",
            name="ck_technique_mapping_confidence",
        ),
        CheckConstraint(
            "event_id IS NOT NULL OR alert_id IS NOT NULL",
            name="ck_technique_mapping_target_required",
        ),
    )


class ObservedSourceModel(Base):
    """Pseudonymous profile aggregating activity from observed source endpoints."""

    __tablename__ = "observed_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_identity_type: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    provenance: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class SimulationRunModel(Base):
    """Trace entity for controlled simulation or demonstration test runs."""

    __tablename__ = "simulation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    simulation_run_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    scenario_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, default="CONTROLLED_TEST")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="RUNNING")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackMappingDefinitionModel(Base):
    """Curated mapping definitions connecting detection rules to ATT&CK techniques."""

    __tablename__ = "attack_mapping_definitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    mapping_definition_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version_range: Mapped[str] = mapped_column(String(32), nullable=False, default=">=1.0")
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("attack_techniques.technique_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    subtechnique_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    dataset_domain: Mapped[str] = mapped_column(String(32), nullable=False, default="enterprise-attack")
    mapping_category: Mapped[str] = mapped_column(String(32), nullable=False, default="PARTIALLY_SUPPORTED", index=True)
    default_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    required_evidence_fields: Mapped[dict | list] = mapped_column(JSONB_TYPE, nullable=False, default=list)
    optional_evidence_fields: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True, default=list)
    exclusion_conditions: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True, default=dict)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    documentation_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AttackDetectionMappingModel(Base):
    """Persistent, evidence-backed ATT&CK association for a detection result or alert."""

    __tablename__ = "attack_detection_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    mapping_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, unique=True, nullable=False, index=True, default=uuid.uuid4)
    detection_result_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_TYPE, ForeignKey("alerts.alert_id", ondelete="CASCADE"), nullable=True, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False)
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("attack_techniques.technique_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    subtechnique_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    mapping_definition_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mapping_definition_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    mapping_category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    mapping_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    mapping_confidence_level: Mapped[str] = mapped_column(String(16), nullable=False, default="MODERATE", index=True)
    confidence_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    mapping_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "mapping_confidence >= 0 AND mapping_confidence <= 100",
            name="ck_attack_detection_mapping_confidence",
        ),
        CheckConstraint(
            "mapping_confidence_level IN ('LOW', 'MODERATE', 'HIGH')",
            name="ck_attack_detection_mapping_confidence_level",
        ),
        CheckConstraint(
            "review_status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'NEEDS_MORE_EVIDENCE')",
            name="ck_attack_detection_mapping_review_status",
        ),
        Index("idx_adm_rule_tech", "rule_id", "technique_id"),
        Index("idx_adm_status_conf", "review_status", "mapping_confidence_level"),
    )


class AttackMappingEvidenceModel(Base):
    """Corroborating evidence link connecting normalized events to ATT&CK mapping records."""

    __tablename__ = "attack_mapping_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    mapping_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("attack_detection_mappings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_TYPE, ForeignKey("security_events.event_id", ondelete="CASCADE"), nullable=True, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="EVENT_REFERENCE")
    evidence_description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_fields: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False, default=dict)
    relevance_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=100)
    evidence_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provenance: Mapped[dict | None] = mapped_column(JSONB_TYPE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackMappingReviewModel(Base):
    """Audit log of human analyst reviews, approvals, rejections, and feedback."""

    __tablename__ = "attack_mapping_reviews"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    mapping_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("attack_detection_mappings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reviewer_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    review_action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    previous_status: Mapped[str] = mapped_column(String(32), nullable=False)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    review_comment: Mapped[str] = mapped_column(Text, nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "review_action IN ('ACCEPT', 'REJECT', 'REQUEST_MORE_EVIDENCE')",
            name="ck_attack_mapping_review_action",
        ),
    )


class AttackMappingHistoryModel(Base):
    """Audit trace preserving assessment transitions and re-evaluations."""

    __tablename__ = "attack_mapping_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    mapping_id: Mapped[uuid.UUID] = mapped_column(
        UUID_TYPE, ForeignKey("attack_detection_mappings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    change_reason: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    previous_confidence: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    new_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict | list | None] = mapped_column(JSONB_TYPE, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AttackMappingPolicyVersionModel(Base):
    """Configurable scoring weights and parameters for mapping confidence assessment."""

    __tablename__ = "attack_mapping_policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=uuid.uuid4)
    policy_version: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    policy_name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    weights: Mapped[dict] = mapped_column(JSONB_TYPE, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
