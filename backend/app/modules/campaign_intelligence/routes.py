"""FastAPI REST routes for Threat Campaign Intelligence & Investigation Grouping (Task P24)."""

from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.campaign_intelligence.schemas import (
    InvestigationClusterResponse,
    PaginatedClustersResponse,
    ClusterSummaryResponse,
    ClusterMembershipResponse,
    ClusterEvidenceResponse,
    ClusterRelationshipResponse,
    ClusterAuditLogResponse,
    ClusterTimelineResponse,
    ClusterAttackTechniqueResponse,
    ClusterDetailResponse,
    AddNoteRequest,
    LifecycleTransitionRequest,
    MemberDecisionRequest,
    ClusterMergeRequest,
    ClusterSplitRequest,
    ClusterCloseRequest,
    TriggerClusteringRequest,
)
from app.modules.campaign_intelligence.service import CampaignIntelligenceService


router = APIRouter(prefix="/investigations", tags=["Campaign Investigations"])


@router.get("", response_model=PaginatedClustersResponse)
def list_investigation_clusters(
    status: Optional[str] = Query(None, description="Filter by status: CANDIDATE, UNDER_REVIEW, ACTIVE, MONITORING, CLOSED, MERGED, SPLIT"),
    priority: Optional[str] = Query(None, description="Filter by priority: LOW, MEDIUM, HIGH, CRITICAL"),
    review_status: Optional[str] = Query(None, description="Filter by review status: UNREVIEWED, UNDER_REVIEW, ACCEPTED, DISMISSED"),
    search: Optional[str] = Query(None, description="Search by cluster_id, title, or description"),
    sort_by: str = Query("last_observed_at", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort direction: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
):
    """Retrieves a paginated list of investigation clusters with multi-attribute filtering."""
    service = CampaignIntelligenceService(db)
    return service.list_clusters(
        status=status,
        priority=priority,
        review_status=review_status,
        search=search,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/summary", response_model=ClusterSummaryResponse)
def get_investigation_summary(db: Session = Depends(get_db)):
    """Retrieves high-level summary counters across all investigation clusters."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_summary()


@router.post("/cluster", status_code=status.HTTP_200_OK)
def trigger_clustering(
    request: TriggerClusteringRequest = TriggerClusteringRequest(),
    db: Session = Depends(get_db),
):
    """Triggers the deterministic investigation clustering engine."""
    service = CampaignIntelligenceService(db)
    return service.trigger_clustering(
        time_window_hours=request.time_window_hours,
        force_all=request.force_all,
    )


@router.get("/{cluster_id}", response_model=InvestigationClusterResponse)
def get_investigation_cluster(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves a single investigation cluster by identifier."""
    service = CampaignIntelligenceService(db)
    c = service.get_cluster(cluster_id)
    return service._to_cluster_response(c)


@router.get("/{cluster_id}/detail", response_model=ClusterDetailResponse)
def get_investigation_cluster_detail(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves complete investigation cluster details including members, evidence, relationships, and audit history."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_detail(cluster_id)


@router.get("/{cluster_id}/members", response_model=List[ClusterMembershipResponse])
def get_cluster_members(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves all sessions, source profiles, alerts, and sequences bound to this cluster."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_members(cluster_id)


@router.get("/{cluster_id}/evidence", response_model=List[ClusterEvidenceResponse])
def get_cluster_evidence(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves all supporting and contradicting evidence attached to this cluster."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_evidence(cluster_id)


@router.get("/{cluster_id}/timeline", response_model=ClusterTimelineResponse)
def get_cluster_timeline(
    cluster_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    chronological: bool = Query(True, description="True for oldest-first, False for newest-first"),
    db: Session = Depends(get_db),
):
    """Retrieves a unified chronological investigation timeline."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_timeline(
        cluster_id=cluster_id,
        limit=limit,
        offset=offset,
        chronological=chronological,
    )


@router.get("/{cluster_id}/relationships", response_model=List[ClusterRelationshipResponse])
def get_cluster_relationships(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves behavioral relationships linking this cluster to other clusters."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_relationships(cluster_id)


@router.get("/{cluster_id}/attack-techniques", response_model=List[ClusterAttackTechniqueResponse])
def get_cluster_attack_techniques(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves evidence-backed MITRE ATT&CK techniques represented within this cluster."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_attack_techniques(cluster_id)


@router.get("/{cluster_id}/audit", response_model=List[ClusterAuditLogResponse])
def get_cluster_audit_logs(
    cluster_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves immutable audit logs for this cluster."""
    service = CampaignIntelligenceService(db)
    return service.get_cluster_audit_logs(cluster_id)


@router.post("/{cluster_id}/notes", status_code=status.HTTP_201_CREATED)
def add_analyst_note(
    cluster_id: str,
    request: AddNoteRequest,
    db: Session = Depends(get_db),
):
    """Records an analyst investigation note."""
    service = CampaignIntelligenceService(db)
    return service.add_analyst_note(
        cluster_id=cluster_id,
        analyst_id=request.analyst_id,
        notes=request.notes,
    )


@router.post("/{cluster_id}/review", response_model=InvestigationClusterResponse)
def transition_cluster_lifecycle(
    cluster_id: str,
    request: LifecycleTransitionRequest,
    db: Session = Depends(get_db),
):
    """Executes a validated lifecycle transition (e.g. from CANDIDATE to ACTIVE or UNDER_REVIEW)."""
    service = CampaignIntelligenceService(db)
    return service.transition_lifecycle_status(
        cluster_id=cluster_id,
        analyst_id=request.analyst_id,
        target_status=request.target_status,
        reason=request.reason,
    )


@router.post("/{cluster_id}/members/{member_id}/decision")
def review_cluster_member(
    cluster_id: str,
    member_id: str,
    request: MemberDecisionRequest,
    db: Session = Depends(get_db),
):
    """Analyst accepts or rejects a proposed membership in the cluster."""
    service = CampaignIntelligenceService(db)
    return service.member_decision(
        cluster_id=cluster_id,
        member_id=member_id,
        analyst_id=request.analyst_id,
        decision=request.decision,
        reason=request.reason,
    )


@router.post("/{cluster_id}/merge", response_model=InvestigationClusterResponse)
def merge_clusters(
    cluster_id: str,
    request: ClusterMergeRequest,
    db: Session = Depends(get_db),
):
    """Non-destructively merges a source cluster into this destination cluster."""
    service = CampaignIntelligenceService(db)
    return service.merge_clusters(
        destination_cluster_id=cluster_id,
        source_cluster_id=request.source_cluster_id,
        analyst_id=request.analyst_id,
        reason=request.reason,
    )


@router.post("/{cluster_id}/split", response_model=InvestigationClusterResponse)
def split_cluster(
    cluster_id: str,
    request: ClusterSplitRequest,
    db: Session = Depends(get_db),
):
    """Non-destructively splits designated members out into a new investigation cluster."""
    service = CampaignIntelligenceService(db)
    return service.split_cluster(
        source_cluster_id=cluster_id,
        member_ids=request.member_ids,
        new_title=request.new_cluster_title,
        new_description=request.new_cluster_description,
        analyst_id=request.analyst_id,
        reason=request.reason,
    )


@router.post("/{cluster_id}/close", response_model=InvestigationClusterResponse)
def close_investigation(
    cluster_id: str,
    request: ClusterCloseRequest,
    db: Session = Depends(get_db),
):
    """Concludes an investigation cluster, marking it CLOSED."""
    service = CampaignIntelligenceService(db)
    return service.close_cluster(
        cluster_id=cluster_id,
        analyst_id=request.analyst_id,
        closure_reason=request.closure_reason,
        resolution_status=request.resolution_status,
    )

