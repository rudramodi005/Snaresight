"""Pydantic schemas for Threat Campaign Intelligence & Investigation Grouping (Task P24)."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class ClusterEvidenceResponse(BaseModel):
    """Supporting or contradicting evidence associated with a cluster."""

    evidence_id: str
    cluster_id: str
    evidence_type: str
    evidence_reference: str
    evidence_description: str
    contribution_score: float
    classification: str = Field(..., description="SUPPORTING or CONTRADICTING")
    evidence_timestamp: datetime
    methodology_version: str
    created_at: datetime


class ClusterMembershipResponse(BaseModel):
    """Entity bound to an investigation cluster."""

    id: str
    cluster_id: str
    member_type: str = Field(..., description="SESSION, SOURCE_PROFILE, ALERT, SEQUENCE, EVENT")
    member_id: str
    association_method: str
    association_confidence: int
    evidence_references: list[str] = Field(default_factory=list)
    membership_status: str = Field(..., description="PROPOSED, ACCEPTED, REJECTED, REMOVED")
    analyst_review_status: str = Field(..., description="PENDING, APPROVED, DISMISSED")
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime


class ClusterRelationshipResponse(BaseModel):
    """Inter-cluster relationship."""

    relationship_id: str
    source_cluster_id: str
    target_cluster_id: str
    relationship_type: str
    supporting_evidence: dict[str, Any] = Field(default_factory=dict)
    relationship_confidence: int
    analyst_review_status: str
    created_at: datetime


class ClusterAuditLogResponse(BaseModel):
    """Audit log entry for investigation cluster actions."""

    id: str
    cluster_id: str
    actor: str
    action: str
    target: Optional[str] = None
    previous_state: Optional[dict[str, Any]] = None
    new_state: Optional[dict[str, Any]] = None
    reason: Optional[str] = None
    timestamp: datetime


class InvestigationClusterResponse(BaseModel):
    """Investigation Cluster summary entity."""

    cluster_id: str
    title: str
    description: str
    lifecycle_status: str
    priority: str
    review_status: str
    analyst_owner: Optional[str] = None
    cluster_methodology_version: str
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    destination_cluster_id: Optional[str] = None
    session_count: int = 0
    source_profile_count: int = 0
    alert_count: int = 0
    sequence_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


class PaginatedClustersResponse(BaseModel):
    """Paginated list of investigation clusters."""

    items: list[InvestigationClusterResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ClusterSummaryResponse(BaseModel):
    """High-level metrics across all investigation clusters."""

    total_clusters: int
    active_investigations: int
    under_review_count: int
    candidate_clusters: int
    monitoring_count: int
    closed_count: int
    critical_priority_count: int
    high_priority_count: int


class ClusterTimelineItemResponse(BaseModel):
    """Unified chronological entry in an investigation cluster timeline."""

    item_id: str
    item_type: str = Field(
        ...,
        description="SESSION, ALERT, SEQUENCE, SOURCE_PROFILE_ACTIVITY, MITRE_MAPPING, ANALYST_ACTION, MERGE, SPLIT",
    )
    timestamp: datetime
    title: str
    summary: str
    reference_id: str
    source_identifier: Optional[str] = None
    decoy_id: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)


class ClusterTimelineResponse(BaseModel):
    """Unified investigation timeline response."""

    cluster_id: str
    items: list[ClusterTimelineItemResponse]
    total_items: int


class ClusterAttackTechniqueResponse(BaseModel):
    """MITRE ATT&CK technique represented within a cluster."""

    technique_id: str
    technique_name: str
    tactic: str
    supporting_rules: list[str] = Field(default_factory=list)
    associated_sessions: list[str] = Field(default_factory=list)
    mapping_confidence: int
    methodology_version: str


class ClusterDetailResponse(BaseModel):
    """Complete detail view for an investigation cluster."""

    cluster: InvestigationClusterResponse
    members: list[ClusterMembershipResponse]
    evidence: list[ClusterEvidenceResponse]
    relationships: list[ClusterRelationshipResponse]
    attack_techniques: list[ClusterAttackTechniqueResponse]
    audit_logs: list[ClusterAuditLogResponse]


# Request Schemas

class AddNoteRequest(BaseModel):
    """Request payload to add an analyst note to a cluster."""

    analyst_id: str = Field(..., min_length=1)
    notes: str = Field(..., min_length=1)


class LifecycleTransitionRequest(BaseModel):
    """Request payload to change the lifecycle state of a cluster."""

    analyst_id: str = Field(..., min_length=1)
    target_status: str = Field(
        ..., description="CANDIDATE, UNDER_REVIEW, ACTIVE, MONITORING, CLOSED, MERGED, SPLIT"
    )
    reason: str = Field(..., min_length=1)


class MemberDecisionRequest(BaseModel):
    """Request payload to accept or reject a proposed cluster membership."""

    analyst_id: str = Field(..., min_length=1)
    decision: str = Field(..., description="ACCEPT or REJECT")
    reason: Optional[str] = None


class ClusterMergeRequest(BaseModel):
    """Request payload to merge two investigation clusters."""

    analyst_id: str = Field(..., min_length=1)
    source_cluster_id: str = Field(..., description="Cluster to be merged and closed")
    reason: str = Field(..., min_length=1)


class ClusterSplitRequest(BaseModel):
    """Request payload to split selected memberships into a new cluster."""

    analyst_id: str = Field(..., min_length=1)
    member_ids: list[str] = Field(..., min_length=1, description="Members to transfer to the new cluster")
    new_cluster_title: str = Field(..., min_length=1)
    new_cluster_description: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)


class ClusterCloseRequest(BaseModel):
    """Request payload to close an investigation."""

    analyst_id: str = Field(..., min_length=1)
    closure_reason: str = Field(..., min_length=1)
    resolution_status: str = Field(default="RESOLVED", description="RESOLVED, FALSE_POSITIVE, BENIGN_ACTIVITY")


class TriggerClusteringRequest(BaseModel):
    """Request to trigger the clustering engine."""

    time_window_hours: int = Field(default=48, ge=1, le=720)
    force_all: bool = False

