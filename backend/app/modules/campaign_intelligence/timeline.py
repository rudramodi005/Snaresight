"""Unified Chronological Investigation Timeline Builder (Task P24)."""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select, desc, asc
from sqlalchemy.orm import Session

from app.db.models.campaign import (
    InvestigationClusterModel,
    ClusterMembershipModel,
    ClusterEvidenceModel,
    ClusterAuditLogModel,
)
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.db.models.sequence import BehavioralSequenceModel
from app.db.models.source_profile import SourceProfileModel
from app.modules.campaign_intelligence.schemas import (
    ClusterTimelineItemResponse,
    ClusterTimelineResponse,
)


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class InvestigationTimelineBuilder:
    """Constructs a comprehensive, unified timeline across all correlated observations and analyst actions."""

    def __init__(self, db: Session):
        self.db = db

    def build_timeline(
        self,
        cluster_id: str,
        limit: int = 100,
        offset: int = 0,
        chronological: bool = True,
    ) -> ClusterTimelineResponse:
        """Assembles a chronological timeline from sessions, alerts, sequences, profiles, and audit events."""
        cluster = self.db.scalar(
            select(InvestigationClusterModel).where(InvestigationClusterModel.cluster_id == cluster_id)
        )
        if not cluster:
            return ClusterTimelineResponse(cluster_id=cluster_id, items=[], total_items=0)

        # 1. Fetch all members
        member_stmt = select(ClusterMembershipModel).where(ClusterMembershipModel.cluster_id == cluster_id)
        members = list(self.db.scalars(member_stmt).all())

        session_ids = [m.member_id for m in members if m.member_type == "SESSION"]
        alert_ids = [m.member_id for m in members if m.member_type == "ALERT"]
        sequence_ids = [m.member_id for m in members if m.member_type == "SEQUENCE"]
        profile_ids = [m.member_id for m in members if m.member_type == "SOURCE_PROFILE"]

        items: List[ClusterTimelineItemResponse] = []

        # 2. Add Sessions
        if session_ids:
            sess_stmt = select(ActivitySessionModel).where(ActivitySessionModel.session_id.in_(session_ids))
            for s in self.db.scalars(sess_stmt).all():
                ts = _ensure_utc(getattr(s, "first_observed_at", getattr(s, "start_time", None)))
                items.append(
                    ClusterTimelineItemResponse(
                        item_id=f"TL-SESS-{s.session_id}",
                        item_type="SESSION",
                        timestamp=ts,
                        title=f"Activity Session on {s.decoy_id}",
                        summary=f"Protocol {s.protocol} session with {s.event_count} events (Status: {s.session_status})",
                        reference_id=s.session_id,
                        source_identifier=s.source_address,
                        decoy_id=s.decoy_id,
                        details={
                            "protocol": s.protocol,
                            "event_count": s.event_count,
                            "highest_severity": s.highest_severity,
                        },
                    )
                )

        # 3. Add Alerts
        if alert_ids:
            # Need string or UUID conversion
            alert_stmt = select(AlertModel)
            for a in self.db.scalars(alert_stmt).all():
                if str(a.alert_id) in alert_ids:
                    ts = _ensure_utc(getattr(a, "created_at", getattr(a, "generated_at", None)))
                    items.append(
                        ClusterTimelineItemResponse(
                            item_id=f"TL-ALT-{a.alert_id}",
                            item_type="ALERT",
                            timestamp=ts,
                            title=f"Security Alert: {a.title}",
                            summary=f"Severity: {a.severity} (Confidence: {a.confidence}%) - {a.summary}",
                            reference_id=str(a.alert_id),
                            source_identifier=a.source_address,
                            decoy_id=a.decoy_id,
                            details={
                                "severity": a.severity,
                                "confidence": a.confidence,
                                "rule_id": a.detection_rule_id,
                            },
                        )
                    )

        # 4. Add Behavioral Sequences
        if sequence_ids:
            seq_stmt = select(BehavioralSequenceModel).where(BehavioralSequenceModel.sequence_id.in_(sequence_ids))
            for seq in self.db.scalars(seq_stmt).all():
                ts = _ensure_utc(seq.first_observed_at)
                items.append(
                    ClusterTimelineItemResponse(
                        item_id=f"TL-SEQ-{seq.sequence_id}",
                        item_type="SEQUENCE",
                        timestamp=ts,
                        title=f"Behavioral Attack Chain: {seq.title}",
                        summary=f"Pattern: {seq.sequence_pattern} across {seq.session_count} session(s)",
                        reference_id=seq.sequence_id,
                        source_identifier=seq.primary_source_address,
                        decoy_id=seq.primary_decoy_id,
                        details={
                            "pattern": seq.sequence_pattern,
                            "relevance": seq.sequence_relevance,
                        },
                    )
                )

        # 5. Add Source Profile Milestones
        if profile_ids:
            prof_stmt = select(SourceProfileModel).where(SourceProfileModel.profile_id.in_(profile_ids))
            for p in self.db.scalars(prof_stmt).all():
                ts = _ensure_utc(p.first_observed_at)
                items.append(
                    ClusterTimelineItemResponse(
                        item_id=f"TL-PROF-{p.profile_id}",
                        item_type="SOURCE_PROFILE_ACTIVITY",
                        timestamp=ts,
                        title=f"Observed Source Baseline: {p.source_ip}",
                        summary=f"Priority {p.profile_priority} profile first engaged with {p.total_sessions} session(s)",
                        reference_id=p.profile_id,
                        source_identifier=p.source_ip,
                        decoy_id=None,
                        details={
                            "priority": p.profile_priority,
                            "fingerprint": p.fingerprint,
                        },
                    )
                )

        # 6. Add Audit Log Actions (e.g. merge, split, note, status changes)
        audit_stmt = select(ClusterAuditLogModel).where(ClusterAuditLogModel.cluster_id == cluster_id)
        for log in self.db.scalars(audit_stmt).all():
            ts = _ensure_utc(log.timestamp)
            items.append(
                ClusterTimelineItemResponse(
                    item_id=f"TL-AUDIT-{log.id}",
                    item_type="ANALYST_ACTION",
                    timestamp=ts,
                    title=f"Analyst Action: {log.action}",
                    summary=f"Executed by {log.actor}. {log.reason or ''}",
                    reference_id=str(log.id),
                    source_identifier=None,
                    decoy_id=None,
                    details={
                        "actor": log.actor,
                        "action": log.action,
                        "reason": log.reason,
                    },
                )
            )

        # Sort items
        items.sort(key=lambda x: x.timestamp, reverse=not chronological)
        total_items = len(items)
        paginated_items = items[offset : offset + limit]

        return ClusterTimelineResponse(
            cluster_id=cluster_id,
            items=paginated_items,
            total_items=total_items,
        )

