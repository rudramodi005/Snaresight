"""Investigation Timeline Builder (Task P21).

Constructs unified, chronological event, detection, and ATT&CK mapping sequences
for a correlated activity session.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionEventModel, ActivitySessionModel
from app.db.models.event import SecurityEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.correlation.exceptions import SessionNotFoundError
from app.correlation.schemas import (
    SessionStatus,
    SessionTimelineResponse,
    TimelineEntryResponse,
    TimelineEntryType,
)


class InvestigationTimelineBuilder:
    """Aggregates and sorts events, detections, and ATT&CK mappings into an investigation timeline."""

    @classmethod
    def build_timeline(
        cls,
        db: Session,
        session_id: str,
        limit: int = 200,
    ) -> SessionTimelineResponse:
        """Constructs a deterministic, chronological timeline for the given activity session ID."""
        session = (
            db.query(ActivitySessionModel)
            .filter(ActivitySessionModel.session_id == session_id)
            .first()
        )
        if not session:
            raise SessionNotFoundError(f"Activity session '{session_id}' not found", session_id=session_id)

        entries: List[TimelineEntryResponse] = []

        # 1. Fetch all associated events
        session_events = (
            db.query(ActivitySessionEventModel)
            .filter(ActivitySessionEventModel.session_id == session_id)
            .all()
        )
        event_ids = [se.event_id for se in session_events]

        # Fetch underlying SecurityEvent records for rich metadata
        sec_events = (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.event_id.in_(event_ids))
            .all()
        ) if event_ids else []
        sec_events_by_id = {se.event_id: se for se in sec_events}

        for se_assoc in session_events:
            sec_ev = sec_events_by_id.get(se_assoc.event_id)
            entry_type, title, desc = cls._classify_event_entry(se_assoc, sec_ev)

            meta = sec_ev.sanitized_metadata if sec_ev else {}
            entries.append(
                TimelineEntryResponse(
                    entry_id=f"tl-evt-{se_assoc.id}",
                    session_id=session_id,
                    source_record_id=str(se_assoc.event_id),
                    timestamp=se_assoc.observed_at.isoformat(),
                    ingestion_timestamp=se_assoc.ingested_at.isoformat(),
                    entry_type=entry_type,
                    title=title,
                    description=desc,
                    component=session.honeypot_type,
                    category=se_assoc.event_category,
                    severity=None,
                    is_detection=False,
                    is_late_arrival=se_assoc.is_late_arrival,
                    metadata=meta,
                )
            )

        # 2. Fetch associated Detections / Alerts via AlertEvidenceModel junction
        alerts: List[AlertModel] = []
        if event_ids:
            alert_ids = [
                row[0]
                for row in db.query(AlertEvidenceModel.alert_id)
                .filter(AlertEvidenceModel.event_id.in_(event_ids))
                .distinct()
                .all()
            ]
            if alert_ids:
                alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(alert_ids)).all()

        for alert in alerts:
            entries.append(
                TimelineEntryResponse(
                    entry_id=f"tl-det-{alert.alert_id}",
                    session_id=session_id,
                    source_record_id=str(alert.alert_id),
                    timestamp=alert.first_observed_at.isoformat(),
                    ingestion_timestamp=alert.generated_at.isoformat(),
                    entry_type=TimelineEntryType.DETECTION_GENERATED,
                    title=f"Detection: {alert.title}",
                    description=alert.summary,
                    component="DETECTION_ENGINE",
                    category="DETECTION",
                    severity=alert.severity,
                    is_detection=True,
                    is_late_arrival=False,
                    related_detection_id=str(alert.alert_id),
                    metadata={
                        "rule_id": alert.detection_rule_id,
                        "rule_version": alert.detection_rule_version,
                        "confidence": alert.confidence,
                        "evidence_strength": alert.evidence_strength,
                    },
                )
            )

            # 3. Fetch associated ATT&CK mappings for this alert
            mappings = (
                db.query(AttackDetectionMappingModel)
                .filter(AttackDetectionMappingModel.alert_id == alert.alert_id)
                .all()
            )
            for m in mappings:
                tech_display = m.subtechnique_id or m.technique_id
                entries.append(
                    TimelineEntryResponse(
                        entry_id=f"tl-map-{m.mapping_id}",
                        session_id=session_id,
                        source_record_id=str(m.mapping_id),
                        timestamp=m.assessed_at.isoformat(),
                        ingestion_timestamp=m.created_at.isoformat(),
                        entry_type=TimelineEntryType.ATTACK_MAPPING_GENERATED,
                        title=f"ATT&CK Technique: {tech_display}",
                        description=m.mapping_rationale,
                        component="MITRE_MAPPING_ENGINE",
                        category="INTELLIGENCE",
                        severity=None,
                        is_detection=True,
                        is_late_arrival=False,
                        related_detection_id=str(alert.alert_id),
                        related_technique_id=m.technique_id,
                        related_mapping_id=str(m.mapping_id),
                        mapping_status=m.review_status,
                        metadata={
                            "technique_id": m.technique_id,
                            "subtechnique_id": m.subtechnique_id,
                            "mapping_category": m.mapping_category,
                            "mapping_confidence": m.mapping_confidence,
                            "review_status": m.review_status,
                        },
                    )
                )

        # 4. Deterministic Chronological Sorting
        # Primary: occurrence timestamp; Secondary: detection priority (events precede detections)
        entries.sort(key=lambda x: (x.timestamp, 1 if x.is_detection else 0, x.entry_id))

        # Apply limit
        trimmed_entries = entries[:limit]

        return SessionTimelineResponse(
            session_id=session_id,
            decoy_id=session.decoy_id,
            source_address=session.source_address,
            total_entries=len(entries),
            first_observed_at=session.first_observed_at.isoformat(),
            last_activity_at=session.last_activity_at.isoformat(),
            session_status=SessionStatus(session.session_status),
            entries=trimmed_entries,
        )

    @classmethod
    def _classify_event_entry(
        cls,
        assoc: ActivitySessionEventModel,
        sec_ev: Optional[SecurityEventModel],
    ) -> tuple[TimelineEntryType, str, str]:
        """Classifies entry type, title, and safe description for an event."""
        cat = (assoc.event_category or "").lower()
        outcome = (assoc.outcome or "").upper()
        meta = sec_ev.sanitized_metadata if sec_ev else {}
        path = meta.get("http_path", "")

        # Traversal check
        if any(tok in str(path) for tok in ("../", "..%2f", "%2e%2e/", "..\\")):
            return (
                TimelineEntryType.DIRECTORY_TRAVERSAL,
                "Directory Traversal Probe",
                f"Observed traversal indicator in requested path '{path}'",
            )

        # Auth outcomes
        if cat == "authentication":
            if outcome == "FAILURE":
                return (
                    TimelineEntryType.AUTHENTICATION_FAILURE,
                    "Authentication Failure",
                    f"Credential submission failed for visitor session on {assoc.event_type}",
                )
            elif outcome == "SUCCESS":
                return (
                    TimelineEntryType.DECOY_AUTHENTICATION_ACCEPTED,
                    "Decoy Authentication Accepted",
                    "Simulated credential acceptance recorded on decoy trap",
                )

        # Disconnect check
        if assoc.action in ("DISCONNECT", "LOGOUT", "TERMINATE"):
            return (
                TimelineEntryType.CONNECTION_CLOSED,
                "Connection Terminated",
                f"Visitor session connection closed via {assoc.action}",
            )

        # Generic Request
        return (
            TimelineEntryType.HTTP_REQUEST,
            f"HTTP Request: {meta.get('http_method', 'GET')} {path or '/'}",
            f"Observed {meta.get('http_method', 'GET')} request with status {meta.get('status_code', 200)}",
        )
