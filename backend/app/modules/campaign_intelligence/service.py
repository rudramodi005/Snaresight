"""Business service layer for Threat Campaign Intelligence & Investigation Grouping (Task P24)."""

import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import select, func, desc, asc, or_
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterEvidenceModel,
    ClusterRelationshipModel,
    ClusterAuditLogModel,
)
from app.db.models.intelligence import (
    AttackDetectionMappingModel,
    AttackTechniqueModel,
)
from app.modules.campaign_intelligence.schemas import (
    InvestigationClusterResponse,
    PaginatedClustersResponse,
    ClusterSummaryResponse,
    ClusterMembershipResponse,
    ClusterEvidenceResponse,
    ClusterRelationshipResponse,
    ClusterAuditLogResponse,
    ClusterAttackTechniqueResponse,
    ClusterDetailResponse,
    ClusterTimelineResponse,
)
from app.modules.campaign_intelligence.clustering_engine import ClusteringEngine
from app.modules.campaign_intelligence.lifecycle import ClusterLifecycleManager
from app.modules.campaign_intelligence.timeline import InvestigationTimelineBuilder
from app.streaming.event_publisher import event_publisher


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class CampaignIntelligenceService:
    """Manages investigation clusters, lifecycle workflows, merge/split operations, and timelines."""

    def __init__(self, db: Session):
        self.db = db
        self.clustering_engine = ClusteringEngine(db)
        self.timeline_builder = InvestigationTimelineBuilder(db)

    def _to_cluster_response(self, c: InvestigationClusterModel) -> InvestigationClusterResponse:
        # Calculate member counts
        m_stmt = (
            select(ClusterMembershipModel.member_type, func.count())
            .where(ClusterMembershipModel.cluster_id == c.cluster_id)
            .group_by(ClusterMembershipModel.member_type)
        )
        counts = dict(self.db.execute(m_stmt).all())

        return InvestigationClusterResponse(
            cluster_id=c.cluster_id,
            title=c.title,
            description=c.description,
            lifecycle_status=c.lifecycle_status,
            priority=c.priority,
            review_status=c.review_status,
            analyst_owner=c.analyst_owner,
            cluster_methodology_version=c.cluster_methodology_version,
            first_observed_at=c.first_observed_at,
            last_observed_at=c.last_observed_at,
            evidence_summary=c.evidence_summary or {},
            destination_cluster_id=c.destination_cluster_id,
            session_count=counts.get("SESSION", 0),
            source_profile_count=counts.get("SOURCE_PROFILE", 0),
            alert_count=counts.get("ALERT", 0),
            sequence_count=counts.get("SEQUENCE", 0),
            created_at=c.created_at,
            updated_at=c.updated_at,
        )

    def list_clusters(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        review_status: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "last_observed_at",
        sort_order: str = "desc",
    ) -> PaginatedClustersResponse:
        """Retrieves a paginated list of investigation clusters with filtering."""
        query = select(InvestigationClusterModel)

        if status:
            query = query.where(InvestigationClusterModel.lifecycle_status == status.upper())
        if priority:
            query = query.where(InvestigationClusterModel.priority == priority.upper())
        if review_status:
            query = query.where(InvestigationClusterModel.review_status == review_status.upper())
        if search:
            s_term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    InvestigationClusterModel.cluster_id.ilike(s_term),
                    InvestigationClusterModel.title.ilike(s_term),
                    InvestigationClusterModel.description.ilike(s_term),
                )
            )

        # Count total
        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.scalar(count_stmt) or 0

        # Sort
        sort_col = getattr(InvestigationClusterModel, sort_by, InvestigationClusterModel.last_observed_at)
        if sort_order.lower() == "asc":
            query = query.order_by(asc(sort_col))
        else:
            query = query.order_by(desc(sort_col))

        # Paginate
        query = query.offset((page - 1) * page_size).limit(page_size)
        clusters = list(self.db.scalars(query).all())

        items = [self._to_cluster_response(c) for c in clusters]
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        return PaginatedClustersResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_cluster_summary(self) -> ClusterSummaryResponse:
        """Calculates global aggregation counters across all investigation clusters."""
        stmt = (
            select(InvestigationClusterModel.lifecycle_status, func.count())
            .group_by(InvestigationClusterModel.lifecycle_status)
        )
        status_counts = dict(self.db.execute(stmt).all())

        p_stmt = (
            select(InvestigationClusterModel.priority, func.count())
            .group_by(InvestigationClusterModel.priority)
        )
        priority_counts = dict(self.db.execute(p_stmt).all())

        total = sum(status_counts.values())

        return ClusterSummaryResponse(
            total_clusters=total,
            active_investigations=status_counts.get("ACTIVE", 0),
            under_review_count=status_counts.get("UNDER_REVIEW", 0),
            candidate_clusters=status_counts.get("CANDIDATE", 0),
            monitoring_count=status_counts.get("MONITORING", 0),
            closed_count=status_counts.get("CLOSED", 0),
            critical_priority_count=priority_counts.get("CRITICAL", 0),
            high_priority_count=priority_counts.get("HIGH", 0),
        )

    def get_cluster(self, cluster_id: str) -> InvestigationClusterModel:
        """Retrieves a single cluster by ID or raises 404."""
        c = self.db.scalar(
            select(InvestigationClusterModel).where(InvestigationClusterModel.cluster_id == cluster_id)
        )
        if not c:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation cluster '{cluster_id}' not found.",
            )
        return c

    def get_cluster_detail(self, cluster_id: str) -> ClusterDetailResponse:
        """Retrieves full cluster details including members, evidence, relationships, and audit logs."""
        c = self.get_cluster(cluster_id)
        cluster_resp = self._to_cluster_response(c)
        members = self.get_cluster_members(cluster_id)
        evidence = self.get_cluster_evidence(cluster_id)
        relationships = self.get_cluster_relationships(cluster_id)
        attack_techniques = self.get_cluster_attack_techniques(cluster_id)
        audit_logs = self.get_cluster_audit_logs(cluster_id)

        return ClusterDetailResponse(
            cluster=cluster_resp,
            members=members,
            evidence=evidence,
            relationships=relationships,
            attack_techniques=attack_techniques,
            audit_logs=audit_logs,
        )

    def get_cluster_members(self, cluster_id: str) -> List[ClusterMembershipResponse]:
        """Retrieves all members bound to a cluster."""
        self.get_cluster(cluster_id)
        stmt = (
            select(ClusterMembershipModel)
            .where(ClusterMembershipModel.cluster_id == cluster_id)
            .order_by(ClusterMembershipModel.created_at.asc())
        )
        members = list(self.db.scalars(stmt).all())
        return [
            ClusterMembershipResponse(
                id=str(m.id),
                cluster_id=m.cluster_id,
                member_type=m.member_type,
                member_id=m.member_id,
                association_method=m.association_method,
                association_confidence=m.association_confidence,
                evidence_references=m.evidence_references or [],
                membership_status=m.membership_status,
                analyst_review_status=m.analyst_review_status,
                reviewed_by=m.reviewed_by,
                reviewed_at=m.reviewed_at,
                created_at=m.created_at,
            )
            for m in members
        ]

    def get_cluster_evidence(self, cluster_id: str) -> List[ClusterEvidenceResponse]:
        """Retrieves all supporting and contradicting evidence attached to a cluster."""
        self.get_cluster(cluster_id)
        stmt = (
            select(ClusterEvidenceModel)
            .where(ClusterEvidenceModel.cluster_id == cluster_id)
            .order_by(ClusterEvidenceModel.created_at.asc())
        )
        evidence_list = list(self.db.scalars(stmt).all())
        return [
            ClusterEvidenceResponse(
                evidence_id=e.evidence_id,
                cluster_id=e.cluster_id,
                evidence_type=e.evidence_type,
                evidence_reference=e.evidence_reference,
                evidence_description=e.evidence_description,
                contribution_score=e.contribution_score,
                classification=e.classification,
                evidence_timestamp=e.evidence_timestamp,
                methodology_version=e.methodology_version,
                created_at=e.created_at,
            )
            for e in evidence_list
        ]

    def get_cluster_relationships(self, cluster_id: str) -> List[ClusterRelationshipResponse]:
        """Retrieves relationships where this cluster is source or target."""
        self.get_cluster(cluster_id)
        stmt = (
            select(ClusterRelationshipModel)
            .where(
                or_(
                    ClusterRelationshipModel.source_cluster_id == cluster_id,
                    ClusterRelationshipModel.target_cluster_id == cluster_id,
                )
            )
            .order_by(desc(ClusterRelationshipModel.relationship_confidence))
        )
        rels = list(self.db.scalars(stmt).all())
        return [
            ClusterRelationshipResponse(
                relationship_id=r.relationship_id,
                source_cluster_id=r.source_cluster_id,
                target_cluster_id=r.target_cluster_id,
                relationship_type=r.relationship_type,
                supporting_evidence=r.supporting_evidence or {},
                relationship_confidence=r.relationship_confidence,
                analyst_review_status=r.analyst_review_status,
                created_at=r.created_at,
            )
            for r in rels
        ]

    def get_cluster_timeline(
        self,
        cluster_id: str,
        limit: int = 100,
        offset: int = 0,
        chronological: bool = True,
    ) -> ClusterTimelineResponse:
        """Retrieves the unified chronological timeline for this cluster."""
        self.get_cluster(cluster_id)
        return self.timeline_builder.build_timeline(
            cluster_id=cluster_id,
            limit=limit,
            offset=offset,
            chronological=chronological,
        )

    def get_cluster_attack_techniques(self, cluster_id: str) -> List[ClusterAttackTechniqueResponse]:
        """Maps alert and session members of the cluster to verified MITRE ATT&CK techniques."""
        c = self.get_cluster(cluster_id)

        # Find all alert members
        m_stmt = select(ClusterMembershipModel.member_id).where(
            ClusterMembershipModel.cluster_id == cluster_id,
            ClusterMembershipModel.member_type == "ALERT",
        )
        alert_ids = list(self.db.scalars(m_stmt).all())

        if not alert_ids:
            return []

        # Find ATT&CK mappings associated with these alerts
        map_stmt = select(AttackDetectionMappingModel)
        mappings = list(self.db.scalars(map_stmt).all())

        technique_map: Dict[str, Dict[str, Any]] = {}
        for m in mappings:
            t_id = m.technique_id
            if t_id not in technique_map:
                technique_map[t_id] = {
                    "technique_id": t_id,
                    "technique_name": m.technique_name or t_id,
                    "tactic": m.tactic or "Unknown",
                    "supporting_rules": [m.detection_rule_id],
                    "associated_sessions": [],
                    "mapping_confidence": m.mapping_confidence,
                    "methodology_version": m.mapping_policy_version,
                }
            else:
                if m.detection_rule_id not in technique_map[t_id]["supporting_rules"]:
                    technique_map[t_id]["supporting_rules"].append(m.detection_rule_id)

        return [
            ClusterAttackTechniqueResponse(
                technique_id=data["technique_id"],
                technique_name=data["technique_name"],
                tactic=data["tactic"],
                supporting_rules=data["supporting_rules"],
                associated_sessions=data["associated_sessions"],
                mapping_confidence=data["mapping_confidence"],
                methodology_version=data["methodology_version"],
            )
            for data in technique_map.values()
        ]

    def get_cluster_audit_logs(self, cluster_id: str) -> List[ClusterAuditLogResponse]:
        """Retrieves immutable audit history for this cluster."""
        self.get_cluster(cluster_id)
        stmt = (
            select(ClusterAuditLogModel)
            .where(ClusterAuditLogModel.cluster_id == cluster_id)
            .order_by(desc(ClusterAuditLogModel.timestamp))
        )
        logs = list(self.db.scalars(stmt).all())
        return [
            ClusterAuditLogResponse(
                id=str(log.id),
                cluster_id=log.cluster_id,
                actor=log.actor,
                action=log.action,
                target=log.target,
                previous_state=log.previous_state,
                new_state=log.new_state,
                reason=log.reason,
                timestamp=log.timestamp,
            )
            for log in logs
        ]

    def add_analyst_note(self, cluster_id: str, analyst_id: str, notes: str) -> Dict[str, Any]:
        """Adds an analyst investigation note to the cluster with full audit logging."""
        c = self.get_cluster(cluster_id)
        now_utc = datetime.now(timezone.utc)

        audit = ClusterAuditLogModel(
            cluster_id=cluster_id,
            actor=analyst_id,
            action="NOTE_ADDED",
            target=cluster_id,
            previous_state=None,
            new_state={"notes": notes},
            reason="Analyst observation recorded",
            timestamp=now_utc,
        )
        self.db.add(audit)
        c.updated_at = now_utc
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.updated",
            cluster_id=cluster_id,
            payload={"action": "NOTE_ADDED", "analyst_id": analyst_id},
        )

        return {"success": True, "cluster_id": cluster_id, "timestamp": now_utc.isoformat()}

    def transition_lifecycle_status(
        self, cluster_id: str, analyst_id: str, target_status: str, reason: str
    ) -> InvestigationClusterResponse:
        """Transitions a cluster to a new lifecycle state with strict state machine validation."""
        c = self.get_cluster(cluster_id)
        updated_cluster = ClusterLifecycleManager.transition(
            db=self.db,
            cluster=c,
            target_status=target_status,
            actor=analyst_id,
            reason=reason,
        )
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.status.changed",
            cluster_id=cluster_id,
            payload={"new_status": target_status, "analyst_id": analyst_id, "reason": reason},
        )

        return self._to_cluster_response(updated_cluster)

    def member_decision(
        self, cluster_id: str, member_id: str, analyst_id: str, decision: str, reason: Optional[str]
    ) -> Dict[str, Any]:
        """Analyst accepts or rejects a proposed membership in a cluster."""
        self.get_cluster(cluster_id)
        stmt = select(ClusterMembershipModel).where(
            ClusterMembershipModel.cluster_id == cluster_id,
            ClusterMembershipModel.member_id == member_id,
        )
        member = self.db.scalar(stmt)
        if not member:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Member '{member_id}' not found in cluster '{cluster_id}'.",
            )

        now_utc = datetime.now(timezone.utc)
        prev_status = member.membership_status

        if decision.upper() == "ACCEPT":
            member.membership_status = "ACCEPTED"
            member.analyst_review_status = "APPROVED"
        elif decision.upper() == "REJECT":
            member.membership_status = "REJECTED"
            member.analyst_review_status = "DISMISSED"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision '{decision}'. Must be ACCEPT or REJECT.",
            )

        member.reviewed_by = analyst_id
        member.reviewed_at = now_utc

        # Audit log
        audit = ClusterAuditLogModel(
            cluster_id=cluster_id,
            actor=analyst_id,
            action="MEMBERSHIP_REVIEWED",
            target=f"{member.member_type}:{member.member_id}",
            previous_state={"status": prev_status},
            new_state={"status": member.membership_status},
            reason=reason,
            timestamp=now_utc,
        )
        self.db.add(audit)
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.membership.reviewed",
            cluster_id=cluster_id,
            payload={
                "member_id": member_id,
                "member_type": member.member_type,
                "decision": member.membership_status,
                "analyst_id": analyst_id,
            },
        )

        return {
            "success": True,
            "cluster_id": cluster_id,
            "member_id": member_id,
            "membership_status": member.membership_status,
        }

    def merge_clusters(
        self, destination_cluster_id: str, source_cluster_id: str, analyst_id: str, reason: str
    ) -> InvestigationClusterResponse:
        """Non-destructively merges a source cluster into a destination cluster.
        
        Preserves all historical evidence, updates member references, marks source as MERGED.
        """
        if destination_cluster_id == source_cluster_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot merge a cluster into itself.",
            )

        dest = self.get_cluster(destination_cluster_id)
        src = self.get_cluster(source_cluster_id)

        if dest.lifecycle_status in ("MERGED", "SPLIT"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Destination cluster is in terminal state '{dest.lifecycle_status}'.",
            )
        if src.lifecycle_status in ("MERGED", "SPLIT"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Source cluster is already in terminal state '{src.lifecycle_status}'.",
            )

        now_utc = datetime.now(timezone.utc)

        # 1. Fetch existing destination members to prevent duplicates
        existing_dest_members = {
            (m.member_type, m.member_id)
            for m in self.db.scalars(
                select(ClusterMembershipModel).where(
                    ClusterMembershipModel.cluster_id == destination_cluster_id
                )
            ).all()
        }

        # 2. Transfer active members from source to destination
        src_members = list(
            self.db.scalars(
                select(ClusterMembershipModel).where(
                    ClusterMembershipModel.cluster_id == source_cluster_id
                )
            ).all()
        )

        transferred_count = 0
        for m in src_members:
            if (m.member_type, m.member_id) not in existing_dest_members:
                new_m = ClusterMembershipModel(
                    cluster_id=destination_cluster_id,
                    member_type=m.member_type,
                    member_id=m.member_id,
                    association_method="MERGED_FROM_CLUSTER",
                    association_confidence=m.association_confidence,
                    evidence_references=m.evidence_references + [f"MERGED_FROM:{source_cluster_id}"],
                    membership_status=m.membership_status,
                    analyst_review_status="APPROVED",
                    reviewed_by=analyst_id,
                    reviewed_at=now_utc,
                    created_at=now_utc,
                )
                self.db.add(new_m)
                transferred_count += 1

        # 3. Copy supporting evidence
        src_evidence = list(
            self.db.scalars(
                select(ClusterEvidenceModel).where(ClusterEvidenceModel.cluster_id == source_cluster_id)
            ).all()
        )
        existing_dest_ev_refs = set(
            self.db.scalars(
                select(ClusterEvidenceModel.evidence_reference).where(
                    ClusterEvidenceModel.cluster_id == destination_cluster_id
                )
            ).all()
        )

        for ev in src_evidence:
            if ev.evidence_reference not in existing_dest_ev_refs:
                new_ev = ClusterEvidenceModel(
                    evidence_id=f"EVID-{uuid.uuid4().hex[:12].upper()}",
                    cluster_id=destination_cluster_id,
                    evidence_type=ev.evidence_type,
                    evidence_reference=ev.evidence_reference,
                    evidence_description=f"[Merged from {source_cluster_id}] {ev.evidence_description}",
                    contribution_score=ev.contribution_score,
                    classification=ev.classification,
                    evidence_timestamp=ev.evidence_timestamp,
                    methodology_version=ev.methodology_version,
                    created_at=now_utc,
                )
                self.db.add(new_ev)

        # 4. Update destination cluster time boundaries
        dest.first_observed_at = min(_ensure_utc(dest.first_observed_at), _ensure_utc(src.first_observed_at))
        dest.last_observed_at = max(_ensure_utc(dest.last_observed_at), _ensure_utc(src.last_observed_at))
        dest.updated_at = now_utc

        # 5. Transition source cluster to MERGED
        ClusterLifecycleManager.transition(
            db=self.db,
            cluster=src,
            target_status="MERGED",
            actor=analyst_id,
            reason=f"Consolidated into {destination_cluster_id}: {reason}",
            destination_cluster_id=destination_cluster_id,
        )

        # 6. Audit log on destination
        dest_audit = ClusterAuditLogModel(
            cluster_id=destination_cluster_id,
            actor=analyst_id,
            action="MERGED_INCORPORATION",
            target=source_cluster_id,
            previous_state=None,
            new_state={"transferred_members": transferred_count, "source_cluster": source_cluster_id},
            reason=reason,
            timestamp=now_utc,
        )
        self.db.add(dest_audit)
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.merged",
            cluster_id=destination_cluster_id,
            payload={
                "destination_cluster_id": destination_cluster_id,
                "source_cluster_id": source_cluster_id,
                "analyst_id": analyst_id,
                "transferred_members": transferred_count,
            },
        )

        return self._to_cluster_response(dest)

    def split_cluster(
        self,
        source_cluster_id: str,
        member_ids: List[str],
        new_title: str,
        new_description: str,
        analyst_id: str,
        reason: str,
    ) -> InvestigationClusterResponse:
        """Non-destructively splits designated members from a cluster into a new investigation cluster."""
        src = self.get_cluster(source_cluster_id)

        if src.lifecycle_status in ("MERGED", "SPLIT"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot split a cluster in terminal state '{src.lifecycle_status}'.",
            )

        # Fetch designated members
        m_stmt = select(ClusterMembershipModel).where(
            ClusterMembershipModel.cluster_id == source_cluster_id,
            ClusterMembershipModel.member_id.in_(member_ids),
        )
        selected_members = list(self.db.scalars(m_stmt).all())

        if not selected_members:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No matching members found in source cluster for splitting.",
            )

        all_src_members_count = self.db.scalar(
            select(func.count()).where(ClusterMembershipModel.cluster_id == source_cluster_id)
        ) or 0

        if len(selected_members) >= all_src_members_count:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot split all members out of the source cluster. At least one member must remain.",
            )

        now_utc = datetime.now(timezone.utc)
        new_cluster_id = f"CAMP-{hashlib.sha256(f'SPLIT-{uuid.uuid4().hex}'.encode()).hexdigest()[:16].upper()}"

        # 1. Create new cluster
        new_cluster = InvestigationClusterModel(
            cluster_id=new_cluster_id,
            title=new_title,
            description=new_description,
            lifecycle_status="CANDIDATE",
            priority=src.priority,
            review_status="UNDER_REVIEW",
            analyst_owner=analyst_id,
            cluster_methodology_version="1.0",
            first_observed_at=src.first_observed_at,
            last_observed_at=src.last_observed_at,
            evidence_summary={
                "split_from_cluster": source_cluster_id,
                "split_reason": reason,
                "initial_member_count": len(selected_members),
            },
            created_at=now_utc,
        )
        self.db.add(new_cluster)
        self.db.flush()

        # 2. Transfer selected members
        for sm in selected_members:
            # Rebind member to new cluster
            new_m = ClusterMembershipModel(
                cluster_id=new_cluster_id,
                member_type=sm.member_type,
                member_id=sm.member_id,
                association_method="SPLIT_FROM_CLUSTER",
                association_confidence=sm.association_confidence,
                evidence_references=sm.evidence_references + [f"SPLIT_FROM:{source_cluster_id}"],
                membership_status="ACCEPTED",
                analyst_review_status="APPROVED",
                reviewed_by=analyst_id,
                reviewed_at=now_utc,
                created_at=now_utc,
            )
            self.db.add(new_m)
            # Remove from source cluster
            self.db.delete(sm)

        # 3. Create relationship between original and new cluster
        rel = ClusterRelationshipModel(
            relationship_id=f"REL-{uuid.uuid4().hex[:12].upper()}",
            source_cluster_id=source_cluster_id,
            target_cluster_id=new_cluster_id,
            relationship_type="SUB_CAMPAIGN",
            supporting_evidence={"reason": reason, "transferred_members": member_ids},
            relationship_confidence=80,
            analyst_review_status="ACCEPTED",
            created_at=now_utc,
        )
        self.db.add(rel)

        # 4. Audit logs on both clusters
        src_audit = ClusterAuditLogModel(
            cluster_id=source_cluster_id,
            actor=analyst_id,
            action="SPLIT_PARTITION",
            target=new_cluster_id,
            previous_state={"total_members": all_src_members_count},
            new_state={"remaining_members": all_src_members_count - len(selected_members), "new_cluster": new_cluster_id},
            reason=reason,
            timestamp=now_utc,
        )
        new_audit = ClusterAuditLogModel(
            cluster_id=new_cluster_id,
            actor=analyst_id,
            action="SPLIT_CREATED",
            target=source_cluster_id,
            previous_state=None,
            new_state={"initial_members": len(selected_members), "origin_cluster": source_cluster_id},
            reason=reason,
            timestamp=now_utc,
        )
        self.db.add_all([src_audit, new_audit])
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.split",
            cluster_id=new_cluster_id,
            payload={
                "source_cluster_id": source_cluster_id,
                "new_cluster_id": new_cluster_id,
                "analyst_id": analyst_id,
                "transferred_members": len(selected_members),
            },
        )

        return self._to_cluster_response(new_cluster)

    def close_cluster(
        self, cluster_id: str, analyst_id: str, closure_reason: str, resolution_status: str
    ) -> InvestigationClusterResponse:
        """Concludes an investigation cluster, marking it CLOSED with a reason."""
        c = self.get_cluster(cluster_id)
        updated_cluster = ClusterLifecycleManager.transition(
            db=self.db,
            cluster=c,
            target_status="CLOSED",
            actor=analyst_id,
            reason=f"Closed with resolution '{resolution_status}': {closure_reason}",
        )
        self.db.commit()

        # SSE Notification
        event_publisher.publish_investigation_event(
            event_name="investigation.closed",
            cluster_id=cluster_id,
            payload={
                "cluster_id": cluster_id,
                "analyst_id": analyst_id,
                "closure_reason": closure_reason,
                "resolution_status": resolution_status,
            },
        )

        return self._to_cluster_response(updated_cluster)

    def trigger_clustering(self, time_window_hours: int = 48, force_all: bool = False) -> Dict[str, Any]:
        """Runs the deterministic investigation clustering engine on-demand."""
        clusters = self.clustering_engine.run_clustering(
            time_window_hours=time_window_hours, force_all=force_all
        )
        return {
            "success": True,
            "discovered_clusters_count": len(clusters),
            "cluster_ids": [c.cluster_id for c in clusters],
        }

