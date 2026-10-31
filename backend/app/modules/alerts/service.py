"""Business logic service for SOC Alert Management, Triage, and Prioritization (Task P28)."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_, and_, func

from app.db.models.alert import AlertModel, AlertEvidenceModel, AlertAuditLogModel, AlertNoteModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.event import SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.sequence import BehavioralSequenceModel, BehavioralSequenceMemberModel
from app.db.models.campaign import InvestigationClusterModel, ClusterMembershipModel, ClusterAuditLogModel
from app.db.models.intelligence import AttackDetectionMappingModel, AttackTechniqueModel
from app.streaming.event_publisher import event_publisher

from app.modules.alerts.schemas import (
    AlertListItem,
    AlertQueueResponse,
    AlertSummaryResponse,
    AlertDetailResponse,
    AlertEvidenceItem,
    AlertRelationshipsResponse,
    AlertAuditLogItem,
    AlertNoteItem,
    AcknowledgeRequest,
    AssignRequest,
    InvestigateRequest,
    EscalateRequest,
    ResolveRequest,
    CloseRequest,
    AddNoteRequest,
    TriageDecisionRequest,
)
from app.modules.alerts.prioritization import default_prioritizer, PrioritizationResult


class AlertTriageService:
    """Manages the full auditable lifecycle, triage, prioritization, and correlation of security alerts."""

    ALLOWED_STATUSES = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"}
    ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    VALID_TRANSITIONS = {
        "NEW": {"ACKNOWLEDGED", "INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"},
        "ACKNOWLEDGED": {"INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"},
        "INVESTIGATING": {"ACKNOWLEDGED", "ESCALATED", "RESOLVED", "CLOSED"},
        "ESCALATED": {"INVESTIGATING", "RESOLVED", "CLOSED"},
        "RESOLVED": {"INVESTIGATING", "CLOSED"},
        "CLOSED": {"INVESTIGATING"},  # Reopen to investigate
    }

    def __init__(self, db: Session):
        self.db = db
        self.publisher = event_publisher

    def _find_alert_or_404(self, alert_id_str: str) -> AlertModel:
        """Locates an alert by UUID or string alert_id; raises HTTP 404 if missing."""
        try:
            val_uuid = uuid.UUID(str(alert_id_str).strip())
            alert = self.db.query(AlertModel).filter(
                (AlertModel.alert_id == val_uuid) | (AlertModel.id == val_uuid)
            ).first()
        except ValueError:
            alert = None

        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security alert '{alert_id_str}' was not found in the database.",
            )
        return alert

    def _calculate_alert_priority(self, alert: AlertModel, supporting_count: int = 1) -> PrioritizationResult:
        """Calculates transparent operational priority score and breakdown."""
        # Check if alert or its supporting events are part of sequences or clusters
        has_cluster = False
        cluster_mem = self.db.query(ClusterMembershipModel).filter(
            (ClusterMembershipModel.member_id == str(alert.alert_id)) |
            (ClusterMembershipModel.member_id == alert.source_address)
        ).first()
        if cluster_mem:
            has_cluster = True

        return default_prioritizer.calculate_priority(
            severity=alert.severity,
            confidence=alert.confidence,
            evidence_strength=alert.evidence_strength or "CORROBORATED",
            supporting_events_count=supporting_count,
            has_investigation_or_sequence=has_cluster,
            generated_at=alert.generated_at,
        )

    # --- 1. Alert Queue & Search ---

    def get_alerts_queue(
        self,
        severity: Optional[str] = None,
        status_filter: Optional[str] = None,
        category: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        unassigned_only: bool = False,
        search: Optional[str] = None,
        date_start: Optional[datetime] = None,
        date_end: Optional[datetime] = None,
        sort_by: str = "generated_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 25,
    ) -> AlertQueueResponse:
        """Retrieves server-side filtered, sorted, and paginated alerts."""
        query = self.db.query(AlertModel)

        # A. Status filter
        if status_filter:
            st = status_filter.strip().upper()
            if st in self.ALLOWED_STATUSES:
                query = query.filter(AlertModel.assessment_status == st)

        # B. Severity filter
        if severity:
            sev = severity.strip().upper()
            if sev in self.ALLOWED_SEVERITIES:
                query = query.filter(AlertModel.severity == sev)

        # C. Category filter (via detection rule)
        if category:
            cat_upper = category.strip().upper()
            query = query.join(DetectionRuleModel, AlertModel.detection_rule_id == DetectionRuleModel.rule_id).filter(
                DetectionRuleModel.category == cat_upper
            )

        # D. Analyst assignment filter
        if unassigned_only:
            query = query.filter(
                or_(AlertModel.assigned_analyst.is_(None), AlertModel.assigned_analyst == "")
            )
        elif assigned_analyst:
            query = query.filter(AlertModel.assigned_analyst == assigned_analyst.strip())

        # E. Date range filter
        if date_start:
            query = query.filter(AlertModel.generated_at >= date_start)
        if date_end:
            query = query.filter(AlertModel.generated_at <= date_end)

        # F. Free-text search
        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    AlertModel.title.ilike(term),
                    AlertModel.summary.ilike(term),
                    AlertModel.source_address.ilike(term),
                    AlertModel.detection_rule_id.ilike(term),
                    AlertModel.decoy_id.ilike(term),
                    AlertModel.target_service.ilike(term),
                )
            )

        total = query.count()

        # G. Sorting
        sort_field = getattr(AlertModel, sort_by, AlertModel.generated_at)
        if sort_order.lower() == "asc":
            query = query.order_by(asc(sort_field))
        else:
            query = query.order_by(desc(sort_field))

        # H. Pagination
        offset = max(0, (page - 1) * page_size)
        alerts = query.offset(offset).limit(page_size).all()

        items: List[AlertListItem] = []
        for a in alerts:
            # Count supporting evidence
            ev_count = self.db.query(AlertEvidenceModel).filter(
                AlertEvidenceModel.alert_id == a.alert_id
            ).count()

            # Ensure priority score is present
            if a.priority_score is None:
                p_res = self._calculate_alert_priority(a, max(1, ev_count))
                a.priority_score = p_res.priority_score
                a.priority_level = p_res.priority_level
                self.db.add(a)

            items.append(
                AlertListItem(
                    alert_id=str(a.alert_id),
                    title=a.title,
                    summary=a.summary,
                    severity=a.severity,
                    confidence=a.confidence,
                    priority_score=a.priority_score or 50.0,
                    priority_level=a.priority_level or "P3_MEDIUM",
                    assessment_status=a.assessment_status,
                    triage_decision=a.triage_decision,
                    evidence_strength=a.evidence_strength,
                    source_address=a.source_address,
                    decoy_id=a.decoy_id,
                    target_service=a.target_service,
                    detection_rule_id=a.detection_rule_id,
                    detection_rule_version=a.detection_rule_version,
                    first_observed_at=a.first_observed_at.isoformat() if a.first_observed_at else None,
                    last_observed_at=a.last_observed_at.isoformat() if a.last_observed_at else None,
                    generated_at=a.generated_at.isoformat() if a.generated_at else None,
                    assigned_analyst=a.assigned_analyst,
                    supporting_events_count=ev_count,
                )
            )

        self.db.commit()

        return AlertQueueResponse(
            total=total,
            limit=page_size,
            offset=offset,
            items=items,
        )

    # --- 2. Alert Summary & Metrics ---

    def get_alerts_summary(self) -> AlertSummaryResponse:
        """Aggregates real-time alert statistics, lifecycle distribution, and priority metrics."""
        now_utc = datetime.now(timezone.utc)
        all_alerts = self.db.query(AlertModel).all()

        status_counts = {st: 0 for st in self.ALLOWED_STATUSES}
        severity_counts = {sev: 0 for sev in self.ALLOWED_SEVERITIES}
        priority_counts = {"P1_CRITICAL": 0, "P2_HIGH": 0, "P3_MEDIUM": 0, "P4_LOW": 0}

        unassigned_count = 0
        requiring_attention = 0

        for a in all_alerts:
            # Status
            st = a.assessment_status.upper() if a.assessment_status else "NEW"
            if st in status_counts:
                status_counts[st] += 1
            else:
                status_counts["NEW"] += 1

            # Severity
            sev = a.severity.upper() if a.severity else "MEDIUM"
            if sev in severity_counts:
                severity_counts[sev] += 1

            # Priority
            plevel = a.priority_level or "P3_MEDIUM"
            if plevel in priority_counts:
                priority_counts[plevel] += 1

            # Unassigned (only active alerts)
            if not a.assigned_analyst and st not in ("RESOLVED", "CLOSED"):
                unassigned_count += 1

            # Requiring attention: active critical/high or escalated
            if st in ("NEW", "ESCALATED") or (st == "ACKNOWLEDGED" and sev in ("CRITICAL", "HIGH")):
                requiring_attention += 1

        return AlertSummaryResponse(
            total_matching=len(all_alerts),
            new_alerts=status_counts.get("NEW", 0),
            acknowledged_alerts=status_counts.get("ACKNOWLEDGED", 0),
            investigating_alerts=status_counts.get("INVESTIGATING", 0),
            escalated_alerts=status_counts.get("ESCALATED", 0),
            resolved_alerts=status_counts.get("RESOLVED", 0),
            closed_alerts=status_counts.get("CLOSED", 0),
            unassigned_alerts=unassigned_count,
            requiring_attention=requiring_attention,
            severity_breakdown=severity_counts,
            priority_breakdown=priority_counts,
            last_refreshed_at=now_utc.isoformat(),
        )

    # --- 3. Alert Detail ---

    def get_alert_detail(self, alert_id_str: str) -> AlertDetailResponse:
        """Retrieves full explainable alert detail, evidence count, notes, and audit history."""
        a = self._find_alert_or_404(alert_id_str)

        # Supporting evidence count
        ev_count = self.db.query(AlertEvidenceModel).filter(
            AlertEvidenceModel.alert_id == a.alert_id
        ).count()

        # Prioritization result
        prioritization = self._calculate_alert_priority(a, max(1, ev_count))

        # Update alert priority fields if changed
        if a.priority_score != prioritization.priority_score or a.priority_level != prioritization.priority_level:
            a.priority_score = prioritization.priority_score
            a.priority_level = prioritization.priority_level
            self.db.commit()

        # Detection rule metadata
        rule_meta = None
        rule = self.db.query(DetectionRuleModel).filter(
            DetectionRuleModel.rule_id == a.detection_rule_id
        ).first()
        if rule:
            rule_meta = {
                "rule_id": rule.rule_id,
                "rule_name": rule.rule_name,
                "rule_version": rule.rule_version,
                "category": rule.category,
                "description": rule.description,
                "enabled": rule.enabled,
                "severity": rule.severity,
            }

        # Recent notes
        notes = (
            self.db.query(AlertNoteModel)
            .filter(AlertNoteModel.alert_id == a.alert_id)
            .order_by(desc(AlertNoteModel.created_at))
            .limit(10)
            .all()
        )
        recent_notes = [
            AlertNoteItem(
                id=str(n.id),
                author_id=n.author_id,
                author_role=n.author_role,
                content=n.content,
                created_at=n.created_at.isoformat(),
            )
            for n in notes
        ]

        # Recent history
        history = (
            self.db.query(AlertAuditLogModel)
            .filter(AlertAuditLogModel.alert_id == a.alert_id)
            .order_by(desc(AlertAuditLogModel.created_at))
            .limit(15)
            .all()
        )
        recent_history = [
            AlertAuditLogItem(
                id=str(h.id),
                action_type=h.action_type,
                analyst_id=h.analyst_id,
                previous_status=h.previous_status,
                new_status=h.new_status,
                reason=h.reason,
                details=h.details or {},
                created_at=h.created_at.isoformat(),
            )
            for h in history
        ]

        return AlertDetailResponse(
            alert_id=str(a.alert_id),
            schema_version=a.schema_version,
            title=a.title,
            summary=a.summary,
            severity=a.severity,
            confidence=a.confidence,
            assessment_status=a.assessment_status,
            priority_score=a.priority_score or prioritization.priority_score,
            priority_level=a.priority_level or prioritization.priority_level,
            evidence_strength=a.evidence_strength,
            source_address=a.source_address,
            observed_source_id=a.observed_source_id,
            decoy_id=a.decoy_id,
            target_service=a.target_service,
            first_observed_at=a.first_observed_at.isoformat() if a.first_observed_at else None,
            last_observed_at=a.last_observed_at.isoformat() if a.last_observed_at else None,
            generated_at=a.generated_at.isoformat() if a.generated_at else None,
            updated_at=a.updated_at.isoformat() if a.updated_at else None,
            detection_explanation=a.detection_explanation,
            recommendations=a.recommendations or {},
            detection_rule_id=a.detection_rule_id,
            detection_rule_version=a.detection_rule_version,
            assigned_analyst=a.assigned_analyst,
            triage_decision=a.triage_decision,
            triage_justification=a.triage_justification,
            resolution_category=a.resolution_category,
            resolution_reason=a.resolution_reason,
            escalation_reason=a.escalation_reason,
            escalation_role=a.escalation_role,
            closure_reason=a.closure_reason,
            prioritization=prioritization,
            supporting_events_count=ev_count,
            rule_metadata=rule_meta,
            recent_notes=recent_notes,
            recent_history=recent_history,
        )

    # --- 4. Supporting Evidence ---

    def get_alert_evidence(self, alert_id_str: str) -> List[AlertEvidenceItem]:
        """Retrieves normalized supporting events linked to the alert, with Explorer URLs."""
        a = self._find_alert_or_404(alert_id_str)

        evidence_links = (
            self.db.query(AlertEvidenceModel)
            .filter(AlertEvidenceModel.alert_id == a.alert_id)
            .order_by(asc(AlertEvidenceModel.created_at))
            .all()
        )

        items: List[AlertEvidenceItem] = []
        for link in evidence_links:
            ev = self.db.query(SecurityEventModel).filter(
                SecurityEventModel.event_id == link.event_id
            ).first()
            if ev:
                items.append(
                    AlertEvidenceItem(
                        event_id=str(ev.event_id),
                        evidence_role=link.evidence_role,
                        evidence_summary=link.evidence_summary,
                        event_type=ev.event_type,
                        category=ev.event_category,
                        observed_at=ev.observed_at.isoformat() if ev.observed_at else None,
                        source_ip=ev.source_address,
                        destination_port=ev.target_port,
                        protocol=ev.source_protocol,
                        outcome=ev.outcome,
                        raw_event_id=str(ev.raw_event_id) if ev.raw_event_id else None,
                        investigation_url=f"/events?event_id={ev.event_id}",
                    )
                )
        return items

    # --- 5. Relationships & Context ---

    def get_alert_relationships(self, alert_id_str: str) -> AlertRelationshipsResponse:
        """Resolves cross-subsystem links: sessions, source profiles, sequences, clusters, MITRE."""
        a = self._find_alert_or_404(alert_id_str)

        # 1. Evidence events
        evidence_links = self.db.query(AlertEvidenceModel).filter(
            AlertEvidenceModel.alert_id == a.alert_id
        ).all()
        event_ids = [el.event_id for el in evidence_links]

        # 2. Related Session
        session_obj = None
        if event_ids:
            first_ev = self.db.query(SecurityEventModel).filter(
                SecurityEventModel.event_id == event_ids[0]
            ).first()
            if first_ev and first_ev.session_id:
                act_session = self.db.query(ActivitySessionModel).filter(
                    ActivitySessionModel.session_id == first_ev.session_id
                ).first()
                if act_session:
                    session_obj = {
                        "session_id": act_session.session_id,
                        "status": act_session.session_status,
                        "event_count": act_session.event_count,
                        "first_seen_at": act_session.first_observed_at.isoformat() if act_session.first_observed_at else None,
                        "last_seen_at": act_session.last_activity_at.isoformat() if act_session.last_activity_at else None,
                        "navigation_url": f"/sessions?session_id={act_session.session_id}",
                    }

        # 3. Source Profile
        profile_obj = None
        src_profile = self.db.query(SourceProfileModel).filter(
            SourceProfileModel.source_ip == a.source_address
        ).first()
        if src_profile:
            profile_obj = {
                "profile_id": src_profile.profile_id,
                "source_address": src_profile.source_ip,
                "profile_priority": src_profile.profile_priority,
                "total_sessions": src_profile.total_sessions,
                "total_events": src_profile.total_events,
                "navigation_url": f"/source-intelligence?profile_id={src_profile.profile_id}",
            }

        # 4. Behavioral Sequences
        sequences_list = []
        if event_ids:
            str_eids = [str(eid) for eid in event_ids]
            seq_members = self.db.query(BehavioralSequenceMemberModel).filter(
                BehavioralSequenceMemberModel.member_record_id.in_(str_eids)
            ).all()
            seq_ids = list({sm.sequence_id for sm in seq_members})
            for sid in seq_ids:
                seq = self.db.query(BehavioralSequenceModel).filter(
                    BehavioralSequenceModel.sequence_id == sid
                ).first()
                if seq:
                    sequences_list.append({
                        "sequence_id": seq.sequence_id,
                        "title": seq.title,
                        "lifecycle_status": seq.lifecycle_status,
                        "step_count": seq.step_count,
                        "navigation_url": f"/sequences?sequence_id={seq.sequence_id}",
                    })

        # 5. Investigation Clusters
        clusters_list = []
        cluster_mems = self.db.query(ClusterMembershipModel).filter(
            (ClusterMembershipModel.member_id == str(a.alert_id)) |
            (ClusterMembershipModel.member_id == a.source_address)
        ).all()
        cluster_ids = list({cm.cluster_id for cm in cluster_mems})
        for cid in cluster_ids:
            cl = self.db.query(InvestigationClusterModel).filter(
                InvestigationClusterModel.cluster_id == cid
            ).first()
            if cl:
                clusters_list.append({
                    "cluster_id": cl.cluster_id,
                    "title": cl.title,
                    "lifecycle_status": cl.lifecycle_status,
                    "priority": cl.priority,
                    "navigation_url": f"/investigations?cluster_id={cl.cluster_id}",
                })

        # 6. MITRE ATT&CK Techniques
        mitre_list = []
        mappings = self.db.query(AttackDetectionMappingModel).filter(
            AttackDetectionMappingModel.rule_id == a.detection_rule_id
        ).all()
        for m in mappings:
            tech = self.db.query(AttackTechniqueModel).filter(
                AttackTechniqueModel.technique_id == m.technique_id
            ).first()
            mitre_list.append({
                "technique_id": m.technique_id,
                "technique_name": tech.technique_name if tech else m.technique_id,
                "tactic": tech.tactic_name if tech else "Unknown",
                "confidence": getattr(m, "mapping_confidence", getattr(m, "confidence", 50)),
                "navigation_url": f"/mitre?technique_id={m.technique_id}",
            })

        return AlertRelationshipsResponse(
            alert_id=str(a.alert_id),
            session=session_obj,
            source_profile=profile_obj,
            behavioral_sequences=sequences_list,
            investigation_clusters=clusters_list,
            mitre_techniques=mitre_list,
        )

    # --- 6. Alert History & Notes ---

    def get_alert_history(self, alert_id_str: str) -> List[AlertAuditLogItem]:
        """Retrieves chronological audit trail of all analyst triage actions."""
        a = self._find_alert_or_404(alert_id_str)
        logs = (
            self.db.query(AlertAuditLogModel)
            .filter(AlertAuditLogModel.alert_id == a.alert_id)
            .order_by(desc(AlertAuditLogModel.created_at))
            .all()
        )
        return [
            AlertAuditLogItem(
                id=str(l.id),
                action_type=l.action_type,
                analyst_id=l.analyst_id,
                previous_status=l.previous_status,
                new_status=l.new_status,
                reason=l.reason,
                details=l.details or {},
                created_at=l.created_at.isoformat(),
            )
            for l in logs
        ]

    def get_alert_notes(self, alert_id_str: str) -> List[AlertNoteItem]:
        """Retrieves append-only analyst notes attached to the alert."""
        a = self._find_alert_or_404(alert_id_str)
        notes = (
            self.db.query(AlertNoteModel)
            .filter(AlertNoteModel.alert_id == a.alert_id)
            .order_by(asc(AlertNoteModel.created_at))
            .all()
        )
        return [
            AlertNoteItem(
                id=str(n.id),
                author_id=n.author_id,
                author_role=n.author_role,
                content=n.content,
                created_at=n.created_at.isoformat(),
            )
            for n in notes
        ]

    # --- 7. Triage Workflow Actions ---

    def _validate_status_transition(self, current_status: str, target_status: str) -> None:
        """Enforces the strict lifecycle transition matrix; raises 400 Bad Request on invalid transitions."""
        curr = (current_status or "NEW").upper()
        tgt = target_status.upper()
        allowed = self.VALID_TRANSITIONS.get(curr, set())
        if tgt not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid lifecycle transition from '{curr}' to '{tgt}'. Allowed transitions: {sorted(list(allowed))}",
            )

    def _append_audit_log(
        self,
        alert_id: uuid.UUID,
        action_type: str,
        analyst_id: str,
        previous_status: Optional[str] = None,
        new_status: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AlertAuditLogModel:
        """Appends an immutable audit log record to alert_audit_logs."""
        log = AlertAuditLogModel(
            id=uuid.uuid4(),
            alert_id=alert_id,
            action_type=action_type,
            analyst_id=analyst_id,
            previous_status=previous_status,
            new_status=new_status,
            reason=reason,
            details=details or {},
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(log)
        return log

    def acknowledge_alert(self, alert_id_str: str, req: AcknowledgeRequest) -> AlertDetailResponse:
        """Acknowledges an alert, transitioning its status to ACKNOWLEDGED."""
        a = self._find_alert_or_404(alert_id_str)
        prev_status = a.assessment_status
        self._validate_status_transition(prev_status, "ACKNOWLEDGED")

        now_utc = datetime.now(timezone.utc)
        a.assessment_status = "ACKNOWLEDGED"
        a.updated_at = now_utc

        # Automatically assign acknowledging analyst if unassigned
        if not a.assigned_analyst:
            a.assigned_analyst = req.analyst_id

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="ACKNOWLEDGE",
            analyst_id=req.analyst_id,
            previous_status=prev_status,
            new_status="ACKNOWLEDGED",
            reason=req.notes,
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_acknowledged",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_status": prev_status,
                "new_status": "ACKNOWLEDGED",
                "analyst_id": req.analyst_id,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def assign_alert(self, alert_id_str: str, req: AssignRequest) -> AlertDetailResponse:
        """Assigns or reassigns an alert to an authorized analyst."""
        a = self._find_alert_or_404(alert_id_str)
        prev_analyst = a.assigned_analyst

        now_utc = datetime.now(timezone.utc)
        a.assigned_analyst = req.analyst_id
        a.updated_at = now_utc

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="ASSIGN",
            analyst_id=req.assigned_by,
            previous_status=a.assessment_status,
            new_status=a.assessment_status,
            reason=req.notes,
            details={"previous_analyst": prev_analyst, "new_analyst": req.analyst_id},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_assigned",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_analyst": prev_analyst,
                "assigned_analyst": req.analyst_id,
                "assigned_by": req.assigned_by,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def start_investigation(self, alert_id_str: str, req: InvestigateRequest) -> AlertDetailResponse:
        """Starts formal investigation on an alert."""
        a = self._find_alert_or_404(alert_id_str)
        prev_status = a.assessment_status
        self._validate_status_transition(prev_status, "INVESTIGATING")

        now_utc = datetime.now(timezone.utc)
        a.assessment_status = "INVESTIGATING"
        a.updated_at = now_utc
        if not a.assigned_analyst:
            a.assigned_analyst = req.analyst_id

        # Associate with cluster if provided
        cluster_associated = None
        if req.investigation_cluster_id:
            cluster = self.db.query(InvestigationClusterModel).filter(
                InvestigationClusterModel.cluster_id == req.investigation_cluster_id.strip()
            ).first()
            if cluster:
                existing_mem = self.db.query(ClusterMembershipModel).filter(
                    ClusterMembershipModel.cluster_id == cluster.cluster_id,
                    ClusterMembershipModel.member_id == str(a.alert_id),
                ).first()
                if not existing_mem:
                    mem = ClusterMembershipModel(
                        id=uuid.uuid4(),
                        cluster_id=cluster.cluster_id,
                        member_type="ALERT",
                        member_id=str(a.alert_id),
                        added_by=req.analyst_id,
                        added_at=now_utc,
                    )
                    self.db.add(mem)
                    cluster_associated = cluster.cluster_id

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="START_INVESTIGATION",
            analyst_id=req.analyst_id,
            previous_status=prev_status,
            new_status="INVESTIGATING",
            reason=req.notes,
            details={"associated_cluster_id": cluster_associated} if cluster_associated else {},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_investigating",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_status": prev_status,
                "new_status": "INVESTIGATING",
                "analyst_id": req.analyst_id,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def escalate_alert(self, alert_id_str: str, req: EscalateRequest) -> AlertDetailResponse:
        """Escalates an alert to higher tier / incident response lead; requires reason."""
        if not req.reason.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Escalation requires a non-empty justification reason.",
            )

        a = self._find_alert_or_404(alert_id_str)
        prev_status = a.assessment_status
        self._validate_status_transition(prev_status, "ESCALATED")

        now_utc = datetime.now(timezone.utc)
        a.assessment_status = "ESCALATED"
        a.escalation_reason = req.reason.strip()
        a.escalation_role = req.escalation_role.strip()
        a.updated_at = now_utc

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="ESCALATE",
            analyst_id=req.analyst_id,
            previous_status=prev_status,
            new_status="ESCALATED",
            reason=req.reason.strip(),
            details={"escalation_role": req.escalation_role.strip()},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_escalated",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_status": prev_status,
                "new_status": "ESCALATED",
                "analyst_id": req.analyst_id,
                "escalation_role": req.escalation_role,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def resolve_alert(self, alert_id_str: str, req: ResolveRequest) -> AlertDetailResponse:
        """Resolves an alert with categorization and required explanation."""
        if not req.resolution_reason.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Resolution requires a non-empty explanation reason.",
            )

        a = self._find_alert_or_404(alert_id_str)
        prev_status = a.assessment_status
        self._validate_status_transition(prev_status, "RESOLVED")

        now_utc = datetime.now(timezone.utc)
        a.assessment_status = "RESOLVED"
        a.resolution_category = req.resolution_category.strip()
        a.resolution_reason = req.resolution_reason.strip()
        a.updated_at = now_utc

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="RESOLVE",
            analyst_id=req.analyst_id,
            previous_status=prev_status,
            new_status="RESOLVED",
            reason=req.resolution_reason.strip(),
            details={"resolution_category": req.resolution_category.strip()},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_resolved",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_status": prev_status,
                "new_status": "RESOLVED",
                "analyst_id": req.analyst_id,
                "resolution_category": req.resolution_category,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def close_alert(self, alert_id_str: str, req: CloseRequest) -> AlertDetailResponse:
        """Closes an alert with mandatory disposition closure reason."""
        if not req.closure_reason.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Closing an alert requires an auditable closure reason.",
            )

        a = self._find_alert_or_404(alert_id_str)
        prev_status = a.assessment_status
        self._validate_status_transition(prev_status, "CLOSED")

        now_utc = datetime.now(timezone.utc)
        a.assessment_status = "CLOSED"
        a.closure_reason = req.closure_reason.strip()
        a.updated_at = now_utc

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="CLOSE",
            analyst_id=req.analyst_id,
            previous_status=prev_status,
            new_status="CLOSED",
            reason=req.closure_reason.strip(),
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_closed",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_status": prev_status,
                "new_status": "CLOSED",
                "analyst_id": req.analyst_id,
            },
        )
        return self.get_alert_detail(alert_id_str)

    def add_note(self, alert_id_str: str, req: AddNoteRequest) -> AlertNoteItem:
        """Appends an immutable analyst note and records an audit entry."""
        if not req.content.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Note content cannot be empty.",
            )

        a = self._find_alert_or_404(alert_id_str)
        now_utc = datetime.now(timezone.utc)

        note = AlertNoteModel(
            id=uuid.uuid4(),
            alert_id=a.alert_id,
            author_id=req.author_id.strip(),
            author_role=req.author_role.strip() if req.author_role else "SOC_ANALYST",
            content=req.content.strip(),
            created_at=now_utc,
        )
        self.db.add(note)

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="ADD_NOTE",
            analyst_id=req.author_id.strip(),
            details={"note_id": str(note.id)},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_note_added",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "note_id": str(note.id),
                "author_id": req.author_id,
            },
        )

        return AlertNoteItem(
            id=str(note.id),
            author_id=note.author_id,
            author_role=note.author_role,
            content=note.content,
            created_at=note.created_at.isoformat(),
        )

    def record_triage_decision(self, alert_id_str: str, req: TriageDecisionRequest) -> AlertDetailResponse:
        """Records a structured triage decision assessment with mandatory justification."""
        if not req.justification.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Triage decision requires an evidence-backed justification.",
            )

        a = self._find_alert_or_404(alert_id_str)
        prev_decision = a.triage_decision

        now_utc = datetime.now(timezone.utc)
        a.triage_decision = req.decision
        a.triage_justification = req.justification.strip()
        a.updated_at = now_utc

        self._append_audit_log(
            alert_id=a.alert_id,
            action_type="TRIAGE_DECISION",
            analyst_id=req.analyst_id,
            previous_status=a.assessment_status,
            new_status=a.assessment_status,
            reason=req.justification.strip(),
            details={"previous_decision": prev_decision, "new_decision": req.decision},
        )
        self.db.commit()

        # Publish SSE
        self.publisher.publish_alert_lifecycle_event(
            event_name="alert_triage_decision",
            alert_id=str(a.alert_id),
            payload={
                "alert_id": str(a.alert_id),
                "previous_decision": prev_decision,
                "decision": req.decision,
                "analyst_id": req.analyst_id,
            },
        )
        return self.get_alert_detail(alert_id_str)
