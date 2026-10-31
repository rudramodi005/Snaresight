"""Business service layer for Security Events Explorer & Event Investigation (Task P27).

Provides high-performance, indexed database querying, multi-attribute filtering,
server-side pagination, safe credential redaction, cross-subsystem correlation mapping,
chronological session timelines, multi-event comparison, and analyst audit logging.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import select, func, desc, asc, or_, and_
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.db.models.honeypot import HoneypotModel
from app.db.models.event import RawEventModel, SecurityEventModel, EventAuditLogModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.sequence import BehavioralSequenceMemberModel
from app.db.models.campaign import InvestigationClusterModel, ClusterMembershipModel, ClusterAuditLogModel
from app.db.models.intelligence import AttackDetectionMappingModel, AttackTechniqueModel

from app.modules.security_events.schemas import (
    SecurityEventItem,
    PaginatedSecurityEventsResponse,
    SecurityEventSummaryResponse,
    EventDetailResponse,
    EventRelationshipItem,
    EventProcessingStage,
    EventAuditLogItem,
    EventTimelineEntry,
    EventTimelineResponse,
    EventComparisonField,
    EventComparisonResponse,
)


SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SENSITIVE_PATTERNS = {
    "password", "pass", "secret", "token", "key", "auth",
    "authorization", "credential", "pwd", "private", "access_token"
}


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime instance is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _scrub_sensitive_dict(data: Any) -> Any:
    """Recursively redacts sensitive credential patterns from JSON payloads."""
    if isinstance(data, dict):
        scrubbed = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(p in k_lower for p in SENSITIVE_PATTERNS):
                scrubbed[k] = "[REDACTED_CREDENTIAL]"
            else:
                scrubbed[k] = _scrub_sensitive_dict(v)
        return scrubbed
    elif isinstance(data, list):
        return [_scrub_sensitive_dict(item) for item in data]
    return data


class SecurityEventsService:
    """Application service for searching, investigating, and comparing security events."""

    def __init__(self, db: Session):
        self.db = db

    def list_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        category: Optional[str] = None,
        event_type: Optional[str] = None,
        sensor_id: Optional[str] = None,
        protocol: Optional[str] = None,
        source_address: Optional[str] = None,
        session_id: Optional[str] = None,
        detection_status: Optional[str] = None,
        outcome: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        sort_by: str = "observed_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 25,
    ) -> PaginatedSecurityEventsResponse:
        """Executes multi-attribute filtered query with server-side pagination and sorting."""
        query = self.db.query(SecurityEventModel)

        # 1. Time range filtering
        if start_time:
            query = query.filter(SecurityEventModel.observed_at >= _ensure_utc(start_time))
        if end_time:
            query = query.filter(SecurityEventModel.observed_at <= _ensure_utc(end_time))

        # 2. Attribute filters
        if category:
            query = query.filter(SecurityEventModel.event_category == category.upper())
        if event_type:
            query = query.filter(SecurityEventModel.event_type == event_type.upper())
        if sensor_id:
            query = query.filter(SecurityEventModel.decoy_id == sensor_id)
        if protocol:
            query = query.filter(SecurityEventModel.source_protocol == protocol.upper())
        if source_address:
            query = query.filter(SecurityEventModel.source_address == source_address.strip())
        if session_id:
            query = query.filter(SecurityEventModel.session_id == session_id.strip())
        if outcome:
            query = query.filter(SecurityEventModel.outcome == outcome.upper())

        # 3. Detection status and severity filters
        if detection_status or severity:
            # Join AlertEvidenceModel to check for associated alerts
            query = query.outerjoin(
                AlertEvidenceModel, SecurityEventModel.event_id == AlertEvidenceModel.event_id
            ).outerjoin(
                AlertModel, AlertEvidenceModel.alert_id == AlertModel.alert_id
            )
            if detection_status == "DETECTED":
                query = query.filter(AlertEvidenceModel.id.isnot(None))
            elif detection_status == "NORMAL":
                query = query.filter(AlertEvidenceModel.id.is_(None))

            if severity:
                query = query.filter(AlertModel.severity == severity.upper())

        # 4. Global text search
        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SecurityEventModel.source_address.ilike(term),
                    SecurityEventModel.event_type.ilike(term),
                    SecurityEventModel.event_category.ilike(term),
                    SecurityEventModel.decoy_id.ilike(term),
                    SecurityEventModel.action.ilike(term),
                    SecurityEventModel.session_id.ilike(term),
                )
            )

        total = query.distinct().count()

        # 5. Sorting
        sort_column = getattr(SecurityEventModel, sort_by, SecurityEventModel.observed_at)
        if sort_order.lower() == "asc":
            query = query.order_by(asc(sort_column))
        else:
            query = query.order_by(desc(sort_column))

        # 6. Pagination
        offset = max(0, (page - 1) * page_size)
        events = query.distinct().offset(offset).limit(page_size).all()
        total_pages = max(1, (total + page_size - 1) // page_size)

        items = [self._map_to_event_item(e) for e in events]

        return PaginatedSecurityEventsResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            items=items,
        )

    def _map_to_event_item(self, e: SecurityEventModel) -> SecurityEventItem:
        """Transforms a SecurityEventModel instance into a SecurityEventItem schema."""
        # Find alerts attached via AlertEvidenceModel
        evidence_links = self.db.query(AlertEvidenceModel).filter(
            AlertEvidenceModel.event_id == e.event_id
        ).all()
        alert_ids = [el.alert_id for el in evidence_links]

        highest_sev: Optional[str] = None
        has_alerts = len(alert_ids) > 0

        if has_alerts:
            alerts = self.db.query(AlertModel.severity).filter(
                AlertModel.alert_id.in_(alert_ids)
            ).all()
            if alerts:
                # Pick highest severity
                sorted_sevs = sorted(
                    [a[0].upper() for a in alerts if a[0]],
                    key=lambda s: SEVERITY_WEIGHTS.get(s, 0),
                    reverse=True,
                )
                if sorted_sevs:
                    highest_sev = sorted_sevs[0]

        # Review status from latest EventAuditLogModel
        latest_audit = self.db.query(EventAuditLogModel).filter(
            EventAuditLogModel.event_id == e.event_id
        ).order_by(desc(EventAuditLogModel.created_at)).first()

        review_status = latest_audit.review_status if latest_audit else "UNREVIEWED"

        # Check investigation cluster association
        cluster_id: Optional[str] = None
        cluster_code: Optional[str] = None
        membership = self.db.query(ClusterMembershipModel).filter(
            ClusterMembershipModel.member_type == "EVENT",
            ClusterMembershipModel.member_id == str(e.event_id),
        ).first()

        if membership:
            cluster = self.db.query(InvestigationClusterModel).filter(
                InvestigationClusterModel.cluster_id == membership.cluster_id
            ).first()
            if cluster:
                cluster_id = cluster.cluster_id
                cluster_code = cluster.cluster_id

        return SecurityEventItem(
            event_id=str(e.event_id),
            raw_event_id=str(e.raw_event_id),
            timestamp=e.observed_at.isoformat() if e.observed_at else datetime.now(timezone.utc).isoformat(),
            event_category=e.event_category,
            event_type=e.event_type,
            action=e.action,
            outcome=e.outcome,
            sensor_id=e.decoy_id,
            protocol=e.source_protocol,
            session_id=e.session_id,
            source_address=e.source_address,
            source_port=e.source_port,
            target_service=e.target_service,
            target_port=e.target_port,
            detection_status="DETECTED" if has_alerts else "NORMAL",
            has_alerts=has_alerts,
            alerts_count=len(alert_ids),
            highest_alert_severity=highest_sev,
            review_status=review_status,  # type: ignore
            investigation_cluster_id=cluster_id,
            investigation_code=cluster_code,
        )

    def get_event_detail(self, event_id: str) -> EventDetailResponse:
        """Retrieves full forensic details, safe payloads, relationships, and history."""
        e = self._find_event_or_404(event_id)
        overview = self._map_to_event_item(e)

        # 1. Scrubbed payload and metadata
        safe_metadata = _scrub_sensitive_dict(e.sanitized_metadata or {})
        safe_provenance = _scrub_sensitive_dict(e.provenance or {})

        # 2. Cross-subsystem relationships
        relationships = self.get_event_relationships(str(e.event_id))

        # 3. Processing history reconstruction
        history: List[EventProcessingStage] = []
        if e.raw_event:
            history.append(EventProcessingStage(
                stage="INGESTION",
                timestamp=e.raw_event.received_at.isoformat() if e.raw_event.received_at else e.received_at.isoformat(),
                status="COMPLETED",
                details={"event_source_id": e.raw_event.event_source_id, "schema_version": e.raw_event.schema_version},
            ))
            history.append(EventProcessingStage(
                stage="VALIDATION",
                timestamp=e.raw_event.received_at.isoformat() if e.raw_event.received_at else e.received_at.isoformat(),
                status=e.raw_event.validation_status,
                details={"status": e.raw_event.validation_status},
            ))

        history.append(EventProcessingStage(
            stage="NORMALIZATION",
            timestamp=e.normalized_at.isoformat() if e.normalized_at else e.received_at.isoformat(),
            status="COMPLETED",
            details={"schema_version": e.schema_version, "protocol": e.source_protocol},
        ))

        history.append(EventProcessingStage(
            stage="DEDUPLICATION",
            timestamp=e.created_at.isoformat() if e.created_at else e.received_at.isoformat(),
            status="PASSED",
            details={"deduplication_reference": e.deduplication_reference},
        ))

        # Check if alerts were generated
        evidence_links = self.db.query(AlertEvidenceModel).filter(
            AlertEvidenceModel.event_id == e.event_id
        ).all()
        for el in evidence_links:
            alert = self.db.query(AlertModel).filter(AlertModel.alert_id == el.alert_id).first()
            if alert:
                history.append(EventProcessingStage(
                    stage="DETECTION",
                    timestamp=alert.generated_at.isoformat(),
                    status="ALERT_TRIGGERED",
                    details={
                        "alert_id": str(alert.alert_id),
                        "rule_id": alert.detection_rule_id,
                        "severity": alert.severity,
                        "confidence": alert.confidence,
                    },
                ))

        # 4. Evidence provenance
        evidence_provenance = {
            "decoy_id": e.decoy_id,
            "sensor_name": e.honeypot.name if e.honeypot else e.decoy_id,
            "protocol": e.source_protocol,
            "deduplication_reference": e.deduplication_reference,
            "schema_version": e.schema_version,
            "source_provenance": safe_provenance,
            "observed_at": e.observed_at.isoformat() if e.observed_at else None,
            "received_at": e.received_at.isoformat() if e.received_at else None,
            "normalized_at": e.normalized_at.isoformat() if e.normalized_at else None,
        }

        # 5. Audit logs
        audit_records = self.db.query(EventAuditLogModel).filter(
            EventAuditLogModel.event_id == e.event_id
        ).order_by(desc(EventAuditLogModel.created_at)).all()

        audit_logs = [
            EventAuditLogItem(
                id=str(a.id),
                action_type=a.action_type,
                analyst_id=a.analyst_id,
                review_status=a.review_status,
                notes=a.notes,
                created_at=a.created_at.isoformat(),
                extra_data=a.extra_data or {},
            )
            for a in audit_records
        ]

        return EventDetailResponse(
            overview=overview,
            normalized_payload=safe_metadata,
            provenance=safe_provenance,
            relationships=relationships,
            processing_history=history,
            evidence_provenance=evidence_provenance,
            audit_logs=audit_logs,
        )

    def get_event_relationships(self, event_id: str) -> List[EventRelationshipItem]:
        """Resolves connected entities across sessions, profiles, alerts, sequences, and investigations."""
        e = self._find_event_or_404(event_id)
        relationships: List[EventRelationshipItem] = []

        # A. Raw Event
        relationships.append(EventRelationshipItem(
            entity_type="RAW_EVENT",
            entity_id=str(e.raw_event_id),
            relationship_type="ORIGINAL_CAPTURE",
            label=f"Raw Decoy Telemetry ({e.raw_event_id})",
            description="Immutable raw capture prior to normalization",
            navigation_url=None,
        ))

        # B. Session relationship
        session = self.db.query(ActivitySessionModel).filter(
            ActivitySessionModel.session_id == e.session_id
        ).first()
        if session:
            relationships.append(EventRelationshipItem(
                entity_type="SESSION",
                entity_id=session.session_id,
                relationship_type="SAME_SESSION",
                label=f"Activity Session {session.session_id}",
                description=f"Correlated session on {session.decoy_id} ({session.event_count} events)",
                severity=session.highest_severity,
                navigation_url=f"/sessions?session_id={session.session_id}",
            ))

        # C. Source Profile relationship
        if e.source_address:
            profile = self.db.query(SourceProfileModel).filter(
                SourceProfileModel.source_ip == e.source_address
            ).first()
            if profile:
                relationships.append(EventRelationshipItem(
                    entity_type="SOURCE_PROFILE",
                    entity_id=profile.profile_id,
                    relationship_type="OBSERVED_SOURCE",
                    label=f"Observed Source {profile.display_label or profile.source_ip}",
                    description=f"Persistent source profile with priority {profile.profile_priority}",
                    severity=profile.profile_priority,
                    navigation_url=f"/source-intelligence?profile_id={profile.profile_id}",
                ))

        # D. Security Alerts
        evidence_links = self.db.query(AlertEvidenceModel).filter(
            AlertEvidenceModel.event_id == e.event_id
        ).all()
        for el in evidence_links:
            alert = self.db.query(AlertModel).filter(AlertModel.alert_id == el.alert_id).first()
            if alert:
                relationships.append(EventRelationshipItem(
                    entity_type="ALERT",
                    entity_id=str(alert.alert_id),
                    relationship_type="TRIGGERING_EVIDENCE",
                    label=f"Alert: {alert.title}",
                    description=f"Rule {alert.detection_rule_id} triggered with confidence {alert.confidence}%",
                    severity=alert.severity,
                    confidence=alert.confidence,
                    navigation_url=f"/alerts?alert_id={alert.alert_id}",
                ))

                # E. Check MITRE ATT&CK Mapping for this alert
                mapping = self.db.query(AttackDetectionMappingModel).filter(
                    AttackDetectionMappingModel.rule_id == alert.detection_rule_id
                ).first()
                if mapping:
                    tech = self.db.query(AttackTechniqueModel).filter(
                        AttackTechniqueModel.technique_id == mapping.technique_id
                    ).first()
                    tech_name = tech.name if tech else mapping.technique_id
                    relationships.append(EventRelationshipItem(
                        entity_type="MITRE_TECHNIQUE",
                        entity_id=mapping.technique_id,
                        relationship_type="TACTIC_TECHNIQUE_MAPPING",
                        label=f"MITRE {mapping.technique_id}: {tech_name}",
                        description=f"Technique mapped with confidence {mapping.confidence}%",
                        confidence=mapping.confidence,
                        navigation_url=f"/mitre?technique_id={mapping.technique_id}",
                    ))

        # F. Behavioral Sequence membership
        seq_member = self.db.query(BehavioralSequenceMemberModel).filter(
            (BehavioralSequenceMemberModel.member_record_id == str(e.event_id)) |
            (BehavioralSequenceMemberModel.member_record_id == e.session_id)
        ).first()
        if seq_member:
            relationships.append(EventRelationshipItem(
                entity_type="BEHAVIORAL_SEQUENCE",
                entity_id=str(seq_member.sequence_id),
                relationship_type="ATTACK_STEP",
                label=f"Attack Sequence {seq_member.sequence_id}",
                description=f"Step #{seq_member.sequence_position}: {seq_member.relationship_reason}",
                navigation_url=f"/sequences?sequence_id={seq_member.sequence_id}",
            ))

        # G. Investigation Cluster membership
        cluster_mem = self.db.query(ClusterMembershipModel).filter(
            (ClusterMembershipModel.member_id == str(e.event_id)) |
            (ClusterMembershipModel.member_id == e.session_id)
        ).first()
        if cluster_mem:
            cluster = self.db.query(InvestigationClusterModel).filter(
                InvestigationClusterModel.cluster_id == cluster_mem.cluster_id
            ).first()
            if cluster:
                relationships.append(EventRelationshipItem(
                    entity_type="INVESTIGATION_CLUSTER",
                    entity_id=cluster.cluster_id,
                    relationship_type="INVESTIGATION_MEMBER",
                    label=f"Investigation [{cluster.cluster_id}] {cluster.title}",
                    description=f"Cluster status: {cluster.lifecycle_status} | Priority: {cluster.priority}",
                    severity=cluster.priority,
                    navigation_url=f"/investigations?cluster_id={cluster.cluster_id}",
                ))

        return relationships

    def get_event_timeline(self, event_id: str, window_minutes: int = 60) -> EventTimelineResponse:
        """Retrieves chronological timeline of related events within the session or temporal window."""
        e = self._find_event_or_404(event_id)

        # Check if session exists with multiple events
        session_events = self.db.query(SecurityEventModel).filter(
            SecurityEventModel.session_id == e.session_id
        ).order_by(asc(SecurityEventModel.observed_at)).all()

        if len(session_events) > 1:
            context_type = "SESSION_TIMELINE"
            selected_events = session_events
        else:
            # Fall back to temporal timeline on same sensor/source
            context_type = "TEMPORAL_TIMELINE"
            t_start = e.observed_at - timedelta(minutes=window_minutes)
            t_end = e.observed_at + timedelta(minutes=window_minutes)
            selected_events = self.db.query(SecurityEventModel).filter(
                (SecurityEventModel.decoy_id == e.decoy_id) |
                (SecurityEventModel.source_address == e.source_address),
                SecurityEventModel.observed_at >= t_start,
                SecurityEventModel.observed_at <= t_end,
            ).order_by(asc(SecurityEventModel.observed_at)).limit(50).all()

        timeline_entries: List[EventTimelineEntry] = []
        for ev in selected_events:
            # Check alert status
            evidence = self.db.query(AlertEvidenceModel).filter(
                AlertEvidenceModel.event_id == ev.event_id
            ).first()
            alert_sev: Optional[str] = None
            alert_title: Optional[str] = None
            has_alert = False

            if evidence:
                alert = self.db.query(AlertModel).filter(AlertModel.alert_id == evidence.alert_id).first()
                if alert:
                    has_alert = True
                    alert_sev = alert.severity
                    alert_title = alert.title

            timeline_entries.append(EventTimelineEntry(
                event_id=str(ev.event_id),
                timestamp=ev.observed_at.isoformat() if ev.observed_at else "",
                event_category=ev.event_category,
                event_type=ev.event_type,
                action=ev.action,
                outcome=ev.outcome,
                sensor_id=ev.decoy_id,
                source_address=ev.source_address,
                is_current_event=(ev.event_id == e.event_id),
                relationship_context="SAME_SESSION" if ev.session_id == e.session_id else "TEMPORAL_CONTEXT_ONLY",
                has_alert=has_alert,
                alert_severity=alert_sev,
                alert_title=alert_title,
            ))

        return EventTimelineResponse(
            event_id=str(e.event_id),
            session_id=e.session_id,
            context_type=context_type,
            total_events=len(timeline_entries),
            timeline=timeline_entries,
        )

    def get_events_summary(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> SecurityEventSummaryResponse:
        """Computes aggregated metric counts and breakdown distributions for the page header."""
        query = self.db.query(SecurityEventModel)
        if start_time:
            query = query.filter(SecurityEventModel.observed_at >= _ensure_utc(start_time))
        if end_time:
            query = query.filter(SecurityEventModel.observed_at <= _ensure_utc(end_time))

        total = query.count()

        # Detected events count
        detected = query.join(
            AlertEvidenceModel, SecurityEventModel.event_id == AlertEvidenceModel.event_id
        ).distinct().count()

        clean = max(0, total - detected)

        distinct_sources = self.db.query(func.count(func.distinct(SecurityEventModel.source_address))).scalar() or 0
        distinct_sensors = self.db.query(func.count(func.distinct(SecurityEventModel.decoy_id))).scalar() or 0

        # Breakdowns
        cat_counts = self.db.query(
            SecurityEventModel.event_category, func.count(SecurityEventModel.id)
        ).group_by(SecurityEventModel.event_category).all()
        categories_breakdown = {cat or "UNKNOWN": cnt for cat, cnt in cat_counts}

        sensor_counts = self.db.query(
            SecurityEventModel.decoy_id, func.count(SecurityEventModel.id)
        ).group_by(SecurityEventModel.decoy_id).all()
        sensors_breakdown = {sensor or "UNKNOWN": cnt for sensor, cnt in sensor_counts}

        outcome_counts = self.db.query(
            SecurityEventModel.outcome, func.count(SecurityEventModel.id)
        ).group_by(SecurityEventModel.outcome).all()
        outcomes_breakdown = {outcome or "UNKNOWN": cnt for outcome, cnt in outcome_counts}

        return SecurityEventSummaryResponse(
            total_events=total,
            detected_events=detected,
            clean_events=clean,
            distinct_sources=distinct_sources,
            distinct_sensors=distinct_sensors,
            categories_breakdown=categories_breakdown,
            sensors_breakdown=sensors_breakdown,
            outcomes_breakdown=outcomes_breakdown,
        )

    def compare_events(self, event_ids: List[str]) -> EventComparisonResponse:
        """Compares safe normalized fields across 2 to 5 events, highlighting matches and differences."""
        events: List[SecurityEventModel] = []
        for eid in event_ids:
            try:
                e = self._find_event_or_404(eid)
                events.append(e)
            except HTTPException:
                pass

        if len(events) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least 2 valid existing events are required for comparison.",
            )

        fields_to_compare = [
            ("Event Category", lambda e: e.event_category),
            ("Event Type", lambda e: e.event_type),
            ("Action", lambda e: e.action),
            ("Outcome", lambda e: e.outcome),
            ("Decoy Sensor", lambda e: e.decoy_id),
            ("Source Protocol", lambda e: e.source_protocol),
            ("Target Service", lambda e: e.target_service),
            ("Target Port", lambda e: e.target_port),
            ("Source Address", lambda e: e.source_address),
            ("Session ID", lambda e: e.session_id),
            ("Processing Status", lambda e: e.processing_status),
        ]

        comparison_fields: List[EventComparisonField] = []
        matches = 0
        diffs = 0

        for field_label, extractor in fields_to_compare:
            val_map = {str(e.event_id): extractor(e) for e in events}
            unique_vals = set(str(v) for v in val_map.values())
            is_match = (len(unique_vals) == 1)

            if is_match:
                matches += 1
            else:
                diffs += 1

            comparison_fields.append(EventComparisonField(
                field_name=field_label,
                is_match=is_match,
                values_by_event_id=val_map,
            ))

        return EventComparisonResponse(
            compared_event_ids=[str(e.event_id) for e in events],
            matching_fields_count=matches,
            differing_fields_count=diffs,
            fields=comparison_fields,
            caveat_notice="Similarities in observed network attributes do not prove common real-world human attribution or threat actor identity.",
        )

    def add_event_note(self, event_id: str, analyst_id: str, note: str) -> EventAuditLogItem:
        """Attaches an analyst note to a security event with immutable audit trail."""
        e = self._find_event_or_404(event_id)

        audit_entry = EventAuditLogModel(
            event_id=e.event_id,
            action_type="NOTE",
            analyst_id=analyst_id,
            review_status="UNDER_REVIEW",
            notes=note,
            extra_data={"attached_at": datetime.now(timezone.utc).isoformat()},
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(audit_entry)

        return EventAuditLogItem(
            id=str(audit_entry.id),
            action_type=audit_entry.action_type,
            analyst_id=audit_entry.analyst_id,
            review_status=audit_entry.review_status,
            notes=audit_entry.notes,
            created_at=audit_entry.created_at.isoformat(),
            extra_data=audit_entry.extra_data or {},
        )

    def update_event_review(
        self, event_id: str, analyst_id: str, review_status: str, note: Optional[str] = None
    ) -> EventAuditLogItem:
        """Updates event investigation review status with mandatory audit logging."""
        e = self._find_event_or_404(event_id)

        audit_entry = EventAuditLogModel(
            event_id=e.event_id,
            action_type="REVIEW_STATUS_CHANGE",
            analyst_id=analyst_id,
            review_status=review_status.upper(),
            notes=note,
            extra_data={"previous_status": "UNREVIEWED", "new_status": review_status.upper()},
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(audit_entry)

        return EventAuditLogItem(
            id=str(audit_entry.id),
            action_type=audit_entry.action_type,
            analyst_id=audit_entry.analyst_id,
            review_status=audit_entry.review_status,
            notes=audit_entry.notes,
            created_at=audit_entry.created_at.isoformat(),
            extra_data=audit_entry.extra_data or {},
        )

    def associate_with_investigation(
        self, event_id: str, cluster_id: str, analyst_id: str, reason: str
    ) -> Dict[str, Any]:
        """Associates an event with an investigation cluster, updating cluster memberships and audit logs."""
        e = self._find_event_or_404(event_id)

        cluster = self.db.query(InvestigationClusterModel).filter(
            InvestigationClusterModel.cluster_id == cluster_id
        ).first()

        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation cluster '{cluster_id}' not found",
            )

        # Check existing membership
        existing = self.db.query(ClusterMembershipModel).filter(
            ClusterMembershipModel.cluster_id == cluster.cluster_id,
            ClusterMembershipModel.member_type == "EVENT",
            ClusterMembershipModel.member_id == str(e.event_id),
        ).first()

        if not existing:
            membership = ClusterMembershipModel(
                cluster_id=cluster.cluster_id,
                member_type="EVENT",
                member_id=str(e.event_id),
                association_method="MANUAL_ANALYST_SELECTION",
                association_confidence=80,
            )
            self.db.add(membership)

            # Cluster audit log
            c_audit = ClusterAuditLogModel(
                cluster_id=cluster.cluster_id,
                actor=analyst_id,
                action="MEMBER_ADDED",
                target=str(e.event_id),
                reason=reason,
                new_state={"member_type": "EVENT", "member_id": str(e.event_id)},
            )
            self.db.add(c_audit)

        # Event audit log
        e_audit = EventAuditLogModel(
            event_id=e.event_id,
            action_type="INVESTIGATION_ASSOCIATION",
            analyst_id=analyst_id,
            review_status="UNDER_REVIEW",
            notes=f"Associated with investigation [{cluster.cluster_id}] {cluster.title}: {reason}",
            extra_data={"cluster_id": cluster.cluster_id},
        )
        self.db.add(e_audit)
        self.db.commit()

        return {
            "status": "SUCCESS",
            "message": f"Event {e.event_id} associated with investigation cluster {cluster.cluster_id}",
            "cluster_id": cluster.cluster_id,
            "cluster_code": cluster.cluster_id,
        }

    def _find_event_or_404(self, event_id: str) -> SecurityEventModel:
        """Finds event by UUID or string event_id, raising 404 HTTPException if absent."""
        event = None
        try:
            val_uuid = uuid.UUID(event_id)
            event = self.db.query(SecurityEventModel).filter(
                (SecurityEventModel.event_id == val_uuid) |
                (SecurityEventModel.id == val_uuid)
            ).first()
        except ValueError:
            pass

        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Security event '{event_id}' not found",
            )
        return event
