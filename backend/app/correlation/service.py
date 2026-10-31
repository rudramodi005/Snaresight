"""Application Service Facade for SnareSight Session Correlation (Task P21)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import (
    ActivitySessionEventModel,
    ActivitySessionModel,
)
from app.db.models.event import SecurityEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.correlation.exceptions import SessionNotFoundError
from app.correlation.schemas import (
    ActivitySessionResponse,
    ActivitySessionSummary,
    CorrelationMethod,
    PaginatedSessionsResponse,
    SessionEventResponse,
    SessionStatisticsResponse,
    SessionStatus,
    SessionTimelineResponse,
)
from app.correlation.timeline import InvestigationTimelineBuilder


class CorrelationService:
    """Provides high-level query, timeline assembly, and statistical operations for activity sessions."""

    @classmethod
    def list_sessions(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        decoy_id: Optional[str] = None,
        honeypot_type: Optional[str] = None,
        source_address: Optional[str] = None,
        status: Optional[str] = None,
        min_events: Optional[int] = None,
        has_detections: Optional[bool] = None,
    ) -> PaginatedSessionsResponse:
        """Returns paginated activity sessions matching filtering criteria."""
        query = db.query(ActivitySessionModel)

        if decoy_id:
            query = query.filter(ActivitySessionModel.decoy_id == decoy_id)
        if honeypot_type:
            query = query.filter(ActivitySessionModel.honeypot_type == honeypot_type)
        if source_address:
            query = query.filter(ActivitySessionModel.source_address == source_address)
        if status:
            query = query.filter(ActivitySessionModel.session_status == status)
        if min_events is not None:
            query = query.filter(ActivitySessionModel.event_count >= min_events)
        if has_detections is True:
            query = query.filter(ActivitySessionModel.detection_count > 0)
        elif has_detections is False:
            query = query.filter(ActivitySessionModel.detection_count == 0)

        total = query.count()
        offset = (page - 1) * page_size
        items = (
            query.order_by(ActivitySessionModel.last_activity_at.desc())
            .offset(offset)
            .limit(page_size)
            .all()
        )

        summaries = [cls._to_summary(m) for m in items]

        return PaginatedSessionsResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=summaries,
        )

    @classmethod
    def get_session(cls, db: Session, session_id: str) -> ActivitySessionResponse:
        """Retrieves detailed activity session record or raises SessionNotFoundError."""
        session = (
            db.query(ActivitySessionModel)
            .filter(ActivitySessionModel.session_id == session_id)
            .first()
        )
        if not session:
            raise SessionNotFoundError(f"Activity session '{session_id}' not found", session_id=session_id)

        duration = (session.last_activity_at - session.first_observed_at).total_seconds()

        return ActivitySessionResponse(
            session_id=session.session_id,
            decoy_id=session.decoy_id,
            honeypot_type=session.honeypot_type,
            explicit_session_id=session.explicit_session_id,
            connection_id=session.connection_id,
            correlation_method=CorrelationMethod(session.correlation_method),
            correlation_key=session.correlation_key,
            source_address=session.source_address,
            source_port=session.source_port,
            target_service=session.target_service,
            protocol=session.protocol,
            first_observed_at=session.first_observed_at.isoformat(),
            last_activity_at=session.last_activity_at.isoformat(),
            ended_at=session.ended_at.isoformat() if session.ended_at else None,
            first_ingested_at=session.first_ingested_at.isoformat(),
            last_ingested_at=session.last_ingested_at.isoformat(),
            session_status=SessionStatus(session.session_status),
            event_count=session.event_count,
            detection_count=session.detection_count,
            highest_severity=session.highest_severity,
            duration_seconds=duration,
            correlation_policy_version=session.correlation_policy_version,
            metadata_summary=session.metadata_summary,
            created_at=session.created_at.isoformat(),
            updated_at=session.updated_at.isoformat() if session.updated_at else None,
        )

    @classmethod
    def get_timeline(cls, db: Session, session_id: str, limit: int = 200) -> SessionTimelineResponse:
        """Builds chronological investigation timeline for a session."""
        return InvestigationTimelineBuilder.build_timeline(db=db, session_id=session_id, limit=limit)

    @classmethod
    def get_session_events(cls, db: Session, session_id: str) -> List[SessionEventResponse]:
        """Returns all normalized security events attached to an activity session."""
        session = (
            db.query(ActivitySessionModel)
            .filter(ActivitySessionModel.session_id == session_id)
            .first()
        )
        if not session:
            raise SessionNotFoundError(f"Activity session '{session_id}' not found", session_id=session_id)

        assocs = (
            db.query(ActivitySessionEventModel)
            .filter(ActivitySessionEventModel.session_id == session_id)
            .order_by(ActivitySessionEventModel.observed_at.asc())
            .all()
        )
        event_ids = [a.event_id for a in assocs]

        sec_events = (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.event_id.in_(event_ids))
            .all()
        ) if event_ids else []
        sec_by_id = {se.event_id: se for se in sec_events}

        results: List[SessionEventResponse] = []
        for a in assocs:
            sec_ev = sec_by_id.get(a.event_id)
            meta = sec_ev.sanitized_metadata if sec_ev else {}
            results.append(
                SessionEventResponse(
                    event_id=str(a.event_id),
                    raw_event_id=str(a.raw_event_id) if a.raw_event_id else None,
                    event_type=a.event_type,
                    event_category=a.event_category,
                    action=a.action,
                    outcome=a.outcome,
                    source_address=session.source_address,
                    target_service=session.target_service,
                    observed_at=a.observed_at.isoformat(),
                    ingested_at=a.ingested_at.isoformat(),
                    association_method=a.association_method,
                    correlation_confidence=a.correlation_confidence,
                    is_late_arrival=a.is_late_arrival,
                    sanitized_metadata=meta,
                )
            )

        return results

    @classmethod
    def get_session_detections(cls, db: Session, session_id: str) -> List[Dict[str, Any]]:
        """Returns security alerts associated with an activity session."""
        session = (
            db.query(ActivitySessionModel)
            .filter(ActivitySessionModel.session_id == session_id)
            .first()
        )
        if not session:
            raise SessionNotFoundError(f"Activity session '{session_id}' not found", session_id=session_id)

        # Query via event associations
        ev_ids = [
            row[0]
            for row in db.query(ActivitySessionEventModel.event_id)
            .filter(ActivitySessionEventModel.session_id == session_id)
            .all()
        ]
        alerts: List[AlertModel] = []
        if ev_ids:
            al_ids = [
                row[0]
                for row in db.query(AlertEvidenceModel.alert_id)
                .filter(AlertEvidenceModel.event_id.in_(ev_ids))
                .distinct()
                .all()
            ]
            if al_ids:
                alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(al_ids)).all()

        return [
            {
                "alert_id": str(al.alert_id),
                "title": al.title,
                "summary": al.summary,
                "severity": al.severity,
                "confidence": al.confidence,
                "detection_rule_id": al.detection_rule_id,
                "first_observed_at": al.first_observed_at.isoformat(),
                "generated_at": al.generated_at.isoformat(),
            }
            for al in alerts
        ]

    @classmethod
    def get_session_mitre_mappings(cls, db: Session, session_id: str) -> List[Dict[str, Any]]:
        """Returns ATT&CK technique mappings associated with the session's alerts."""
        alerts = cls.get_session_detections(db=db, session_id=session_id)
        alert_uuids = [uuid.UUID(a["alert_id"]) for a in alerts]

        if not alert_uuids:
            return []

        mappings = (
            db.query(AttackDetectionMappingModel)
            .filter(AttackDetectionMappingModel.alert_id.in_(alert_uuids))
            .all()
        )

        return [
            {
                "mapping_id": str(m.mapping_id),
                "alert_id": str(m.alert_id),
                "rule_id": m.rule_id,
                "technique_id": m.technique_id,
                "subtechnique_id": m.subtechnique_id,
                "mapping_category": m.mapping_category,
                "mapping_confidence": m.mapping_confidence,
                "mapping_confidence_level": m.mapping_confidence_level,
                "review_status": m.review_status,
                "assessed_at": m.assessed_at.isoformat(),
            }
            for m in mappings
        ]

    @classmethod
    def get_statistics(cls, db: Session) -> SessionStatisticsResponse:
        """Computes aggregate operational metrics for all correlated sessions."""
        total = db.query(ActivitySessionModel).count()
        active = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_status == "ACTIVE").count()
        idle = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_status == "IDLE").count()
        closed = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_status == "CLOSED").count()
        timed_out = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_status == "TIMED_OUT").count()

        with_det = db.query(ActivitySessionModel).filter(ActivitySessionModel.detection_count > 0).count()
        total_evts = db.query(func.coalesce(func.sum(ActivitySessionModel.event_count), 0)).scalar() or 0
        avg_evts = round(float(total_evts) / total, 2) if total > 0 else 0.0

        # By honeypot
        hp_counts = (
            db.query(ActivitySessionModel.decoy_id, func.count(ActivitySessionModel.id))
            .group_by(ActivitySessionModel.decoy_id)
            .all()
        )
        by_hp = {h: c for h, c in hp_counts}

        # By protocol
        proto_counts = (
            db.query(ActivitySessionModel.protocol, func.count(ActivitySessionModel.id))
            .group_by(ActivitySessionModel.protocol)
            .all()
        )
        by_proto = {p: c for p, c in proto_counts}

        # By correlation method
        method_counts = (
            db.query(ActivitySessionModel.correlation_method, func.count(ActivitySessionModel.id))
            .group_by(ActivitySessionModel.correlation_method)
            .all()
        )
        by_method = {m: c for m, c in method_counts}

        return SessionStatisticsResponse(
            total_sessions=total,
            active_sessions=active,
            idle_sessions=idle,
            closed_sessions=closed,
            timed_out_sessions=timed_out,
            sessions_with_detections=with_det,
            total_events_correlated=total_evts,
            average_events_per_session=avg_evts,
            by_honeypot=by_hp,
            by_protocol=by_proto,
            by_correlation_method=by_method,
        )

    @classmethod
    def _to_summary(cls, m: ActivitySessionModel) -> ActivitySessionSummary:
        duration = (m.last_activity_at - m.first_observed_at).total_seconds()
        return ActivitySessionSummary(
            session_id=m.session_id,
            decoy_id=m.decoy_id,
            honeypot_type=m.honeypot_type,
            source_address=m.source_address,
            source_port=m.source_port,
            target_service=m.target_service,
            protocol=m.protocol,
            correlation_method=CorrelationMethod(m.correlation_method),
            first_observed_at=m.first_observed_at.isoformat(),
            last_activity_at=m.last_activity_at.isoformat(),
            ended_at=m.ended_at.isoformat() if m.ended_at else None,
            session_status=SessionStatus(m.session_status),
            event_count=m.event_count,
            detection_count=m.detection_count,
            highest_severity=m.highest_severity,
            duration_seconds=duration,
        )
