"""Deterministic, evidence-based investigation clustering engine (Task P24)."""

import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session

from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterEvidenceModel,
    ClusterRelationshipModel,
    ClusterAuditLogModel,
)
from app.db.models.sequence import BehavioralSequenceModel, BehavioralSequenceMemberModel
from app.db.models.source_profile import SourceProfileModel, SourceProfileFeatureModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.modules.campaign_intelligence.scoring import RelationshipScorer


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ClusteringEngine:
    """Discovers and groups related observed activities into persistent investigation clusters."""

    def __init__(self, db: Session):
        self.db = db

    def _generate_cluster_id(self, seed: str) -> str:
        h = hashlib.sha256(f"SnareSight-Cluster-{seed}".encode("utf-8")).hexdigest()
        return f"CAMP-{h[:16].upper()}"

    def run_clustering(self, time_window_hours: int = 48, force_all: bool = False) -> List[InvestigationClusterModel]:
        """Discovers candidate clusters across recent behavioral sequences and source profiles.
        
        Idempotent: Identifies existing clusters and refreshes evidence without duplicating entries.
        """
        now_utc = datetime.now(timezone.utc)
        since_time = now_utc - timedelta(hours=time_window_hours) if not force_all else datetime.min.replace(tzinfo=timezone.utc)

        # 1. Fetch recent behavioral sequences
        seq_stmt = (
            select(BehavioralSequenceModel)
            .where(BehavioralSequenceModel.last_observed_at >= since_time)
            .order_by(BehavioralSequenceModel.last_observed_at.desc())
        )
        sequences = list(self.db.scalars(seq_stmt).all())

        # 2. Fetch active source profiles
        prof_stmt = (
            select(SourceProfileModel)
            .where(SourceProfileModel.last_observed_at >= since_time)
            .order_by(SourceProfileModel.last_observed_at.desc())
        )
        profiles = list(self.db.scalars(prof_stmt).all())

        created_or_updated_clusters: List[InvestigationClusterModel] = []

        # Strategy A: Cluster around Behavioral Sequences
        for seq in sequences:
            cluster = self._process_sequence_cluster(seq)
            if cluster and cluster not in created_or_updated_clusters:
                created_or_updated_clusters.append(cluster)

        # Strategy B: Cross-Cluster Relationships Discovery
        self._discover_cluster_relationships(created_or_updated_clusters)

        self.db.commit()
        return created_or_updated_clusters

    def _process_sequence_cluster(self, seq: BehavioralSequenceModel) -> Optional[InvestigationClusterModel]:
        """Builds or updates an investigation cluster rooted in a behavioral sequence."""
        cluster_id = self._generate_cluster_id(seq.sequence_id)
        now_utc = datetime.now(timezone.utc)

        # Check existing cluster
        cluster = self.db.scalar(
            select(InvestigationClusterModel).where(InvestigationClusterModel.cluster_id == cluster_id)
        )

        # Gather related members (sessions from sequence)
        member_stmt = (
            select(BehavioralSequenceMemberModel)
            .where(BehavioralSequenceMemberModel.sequence_id == seq.sequence_id)
        )
        seq_members = list(self.db.scalars(member_stmt).all())
        session_ids = [m.member_record_id for m in seq_members if getattr(m, 'member_type', '') == 'SESSION']

        # Gather source profiles for primary source address
        source_profiles: List[SourceProfileModel] = []
        if seq.primary_source_address:
            sp = self.db.scalar(
                select(SourceProfileModel).where(SourceProfileModel.source_ip == seq.primary_source_address)
            )
            if sp:
                source_profiles.append(sp)

        # Gather alerts triggered
        alerts: List[AlertModel] = []
        if seq.primary_source_address:
            alert_stmt = select(AlertModel).where(AlertModel.source_address == seq.primary_source_address)
            alerts = list(self.db.scalars(alert_stmt).all())

        # Determine priority based on sequence and alerts
        priority = "MEDIUM"
        if any((getattr(a, "severity", "") or "").upper() == "CRITICAL" for a in alerts) or seq.sequence_relevance >= 80:
            priority = "CRITICAL"
        elif any((getattr(a, "severity", "") or "").upper() == "HIGH" for a in alerts) or seq.sequence_relevance >= 60:
            priority = "HIGH"
        elif seq.sequence_relevance < 40:
            priority = "LOW"

        # Evidence Summary calculation
        supporting_count = 0
        contradicting_count = 0

        title = f"Investigation Cluster: {seq.title}"
        description = (
            f"Evidence-supported investigation cluster grouping observed multi-session activity "
            f"around pattern '{seq.sequence_pattern}'. Correlates {len(session_ids)} session(s) "
            f"and {len(alerts)} alert(s)."
        )

        first_obs = _ensure_utc(seq.first_observed_at) or now_utc
        last_obs = _ensure_utc(seq.last_observed_at) or now_utc

        if not cluster:
            cluster = InvestigationClusterModel(
                cluster_id=cluster_id,
                title=title,
                description=description,
                lifecycle_status="CANDIDATE",
                priority=priority,
                review_status="UNREVIEWED",
                analyst_owner=None,
                cluster_methodology_version="1.0",
                first_observed_at=first_obs,
                last_observed_at=last_obs,
                evidence_summary={
                    "sequence_id": seq.sequence_id,
                    "pattern": seq.sequence_pattern,
                    "session_count": len(session_ids),
                    "alert_count": len(alerts),
                    "primary_decoy": seq.primary_decoy_id,
                },
                created_at=now_utc,
            )
            self.db.add(cluster)
            self.db.flush()

            # Audit log
            audit = ClusterAuditLogModel(
                cluster_id=cluster_id,
                actor="SYSTEM_CLUSTERING_ENGINE",
                action="CREATED",
                target=cluster_id,
                new_state={"lifecycle_status": "CANDIDATE", "priority": priority},
                reason=f"Discovered candidate investigation cluster from sequence {seq.sequence_id}",
                timestamp=now_utc,
            )
            self.db.add(audit)
        else:
            # Update boundaries and priority
            cluster.last_observed_at = max(_ensure_utc(cluster.last_observed_at), last_obs)
            cluster.priority = priority
            cluster.updated_at = now_utc

        # Maintain Memberships (Idempotently)
        existing_members = {
            (m.member_type, m.member_id): m
            for m in self.db.scalars(
                select(ClusterMembershipModel).where(ClusterMembershipModel.cluster_id == cluster_id)
            ).all()
        }

        # 1. Sequence member
        if ("SEQUENCE", seq.sequence_id) not in existing_members:
            m_seq = ClusterMembershipModel(
                cluster_id=cluster_id,
                member_type="SEQUENCE",
                member_id=seq.sequence_id,
                association_method="SEQUENCE_ROOT",
                association_confidence=95,
                evidence_references=[f"SEQ:{seq.sequence_id}"],
                membership_status="PROPOSED",
                analyst_review_status="PENDING",
                created_at=now_utc,
            )
            self.db.add(m_seq)

        # 2. Session members
        for sid in session_ids:
            if ("SESSION", sid) not in existing_members:
                m_sess = ClusterMembershipModel(
                    cluster_id=cluster_id,
                    member_type="SESSION",
                    member_id=sid,
                    association_method="BEHAVIORAL_SEQUENCE_OVERLAP",
                    association_confidence=85,
                    evidence_references=[f"SEQ:{seq.sequence_id}"],
                    membership_status="PROPOSED",
                    analyst_review_status="PENDING",
                    created_at=now_utc,
                )
                self.db.add(m_sess)

        # 3. Source Profile member
        for sp in source_profiles:
            if ("SOURCE_PROFILE", sp.profile_id) not in existing_members:
                m_prof = ClusterMembershipModel(
                    cluster_id=cluster_id,
                    member_type="SOURCE_PROFILE",
                    member_id=sp.profile_id,
                    association_method="SOURCE_CORRELATION",
                    association_confidence=80,
                    evidence_references=[f"SRC:{sp.source_ip}"],
                    membership_status="PROPOSED",
                    analyst_review_status="PENDING",
                    created_at=now_utc,
                )
                self.db.add(m_prof)

        # 4. Alert members
        for al in alerts:
            aid = str(al.alert_id)
            if ("ALERT", aid) not in existing_members:
                m_alt = ClusterMembershipModel(
                    cluster_id=cluster_id,
                    member_type="ALERT",
                    member_id=aid,
                    association_method="ALERT_EVIDENCE_LINKAGE",
                    association_confidence=80,
                    evidence_references=[f"ALT:{aid}"],
                    membership_status="PROPOSED",
                    analyst_review_status="PENDING",
                    created_at=now_utc,
                )
                self.db.add(m_alt)

        # Maintain Evidence Items (Idempotently)
        existing_ev_refs = set(
            self.db.scalars(
                select(ClusterEvidenceModel.evidence_reference).where(
                    ClusterEvidenceModel.cluster_id == cluster_id
                )
            ).all()
        )

        # Evidence: Behavioral Sequence
        seq_ref = f"SEQ:{seq.sequence_id}"
        if seq_ref not in existing_ev_refs:
            ev = ClusterEvidenceModel(
                evidence_id=f"EVID-{uuid.uuid4().hex[:12].upper()}",
                cluster_id=cluster_id,
                evidence_type="BEHAVIORAL_SEQUENCE_EVIDENCE",
                evidence_reference=seq_ref,
                evidence_description=f"Multi-session behavioral progression: {seq.description}",
                contribution_score=0.9,
                classification="SUPPORTING",
                evidence_timestamp=first_obs,
                methodology_version="1.0",
                created_at=now_utc,
            )
            self.db.add(ev)
            supporting_count += 1

        # Evidence: Primary Decoy Targeting
        if seq.primary_decoy_id:
            decoy_ref = f"DECOY:{seq.primary_decoy_id}"
            if decoy_ref not in existing_ev_refs:
                ev = ClusterEvidenceModel(
                    evidence_id=f"EVID-{uuid.uuid4().hex[:12].upper()}",
                    cluster_id=cluster_id,
                    evidence_type="SHARED_DECOY_TARGET",
                    evidence_reference=decoy_ref,
                    evidence_description=f"Grouped activity focused on honeypot decoy '{seq.primary_decoy_id}'",
                    contribution_score=0.7,
                    classification="SUPPORTING",
                    evidence_timestamp=first_obs,
                    methodology_version="1.0",
                    created_at=now_utc,
                )
                self.db.add(ev)
                supporting_count += 1

        self.db.flush()
        return cluster

    def _discover_cluster_relationships(self, clusters: List[InvestigationClusterModel]):
        """Discovers behavioral similarity and sequential relationships between active clusters."""
        if len(clusters) < 2:
            return

        now_utc = datetime.now(timezone.utc)

        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                c1 = clusters[i]
                c2 = clusters[j]

                # Compare decoy targets in evidence summary
                decoy1 = (c1.evidence_summary or {}).get("primary_decoy")
                decoy2 = (c2.evidence_summary or {}).get("primary_decoy")

                shared_decoys = 1 if decoy1 and decoy2 and decoy1 == decoy2 else 0

                # Compare temporal gap
                c1_last = _ensure_utc(c1.last_observed_at) or now_utc
                c2_first = _ensure_utc(c2.first_observed_at) or now_utc
                gap_hours = abs((c1_last - c2_first).total_seconds()) / 3600.0

                evaluation = RelationshipScorer.evaluate_relationship(
                    shared_sequences=0,
                    source_similarity=75.0 if shared_decoys > 0 else 0.0,
                    shared_decoys=shared_decoys,
                    shared_techniques=1 if shared_decoys > 0 else 0,
                    temporal_gap_hours=gap_hours,
                )

                if evaluation["is_above_threshold"]:
                    rel_id = f"REL-{hashlib.sha256(f'{c1.cluster_id}:{c2.cluster_id}'.encode()).hexdigest()[:12].upper()}"
                    existing_rel = self.db.scalar(
                        select(ClusterRelationshipModel).where(
                            ClusterRelationshipModel.relationship_id == rel_id
                        )
                    )
                    if not existing_rel:
                        rel = ClusterRelationshipModel(
                            relationship_id=rel_id,
                            source_cluster_id=c1.cluster_id,
                            target_cluster_id=c2.cluster_id,
                            relationship_type="BEHAVIORAL_SIMILARITY",
                            supporting_evidence=evaluation,
                            relationship_confidence=evaluation["score"],
                            analyst_review_status="PROPOSED",
                            created_at=now_utc,
                        )
                        self.db.add(rel)
