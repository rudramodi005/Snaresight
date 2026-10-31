"""Service Layer for Behavioral Sequence Analysis & SOC Investigations (Task P22)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel, ActivitySessionEventModel
from app.db.models.event import SecurityEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.modules.correlation.sequence_models import (
    BehavioralSequenceModel,
    BehavioralSequenceMemberModel,
    BehavioralSequenceRelationshipModel,
    SequenceAssessmentHistoryModel,
    SequenceEvidenceModel,
)
from app.modules.correlation.sequence_schemas import (
    BehavioralSequenceDetailResponse,
    BehavioralSequenceResponse,
    PaginatedSequencesResponse,
    SequenceAssessmentRequest,
    SequenceEvidenceResponse,
    SequenceHistoryResponse,
    SequenceLifecycleStatus,
    SequenceMemberResponse,
    SequenceMemberType,
    SequencePatternType,
    SequenceRelationshipResponse,
    SequenceStatisticsResponse,
    SequenceStatusUpdateRequest,
    SequenceTimelineEntryResponse,
    SequenceTimelineResponse,
)


class SequenceService:
    """Service facade providing query, timeline, assessment, and analytics operations for behavioral sequences."""

    @classmethod
    def list_sequences(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
        pattern: Optional[str] = None,
        source_address: Optional[str] = None,
        decoy_id: Optional[str] = None,
        min_sessions: Optional[int] = None,
        min_confidence: Optional[int] = None,
        min_relevance: Optional[int] = None,
    ) -> PaginatedSequencesResponse:
        """Retrieves paginated, filtered behavioral sequence candidates."""
        query = db.query(BehavioralSequenceModel)

        if status:
            query = query.filter(BehavioralSequenceModel.lifecycle_status == status.upper())
        if pattern:
            query = query.filter(BehavioralSequenceModel.sequence_pattern == pattern)
        if source_address:
            query = query.filter(BehavioralSequenceModel.primary_source_address == source_address)
        if decoy_id:
            query = query.filter(BehavioralSequenceModel.primary_decoy_id == decoy_id)
        if min_sessions is not None:
            query = query.filter(BehavioralSequenceModel.session_count >= min_sessions)
        if min_confidence is not None:
            query = query.filter(BehavioralSequenceModel.correlation_confidence >= min_confidence)
        if min_relevance is not None:
            query = query.filter(BehavioralSequenceModel.sequence_relevance >= min_relevance)

        total = query.count()
        offset = (page - 1) * page_size
        records = (
            query.order_by(BehavioralSequenceModel.last_observed_at.desc())
            .offset(offset)
            .limit(page_size)
            .all()
        )

        items = [cls._to_sequence_response(r) for r in records]
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        return PaginatedSequencesResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            items=items,
        )

    @classmethod
    def get_sequence(cls, db: Session, sequence_id: str) -> BehavioralSequenceDetailResponse:
        """Retrieves complete behavioral sequence detail with members, relationships, and evidence."""
        seq = db.query(BehavioralSequenceModel).filter_by(sequence_id=sequence_id).first()
        if not seq:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sequence '{sequence_id}' not found")

        members = (
            db.query(BehavioralSequenceMemberModel)
            .filter_by(sequence_id=sequence_id)
            .order_by(BehavioralSequenceMemberModel.sequence_position.asc())
            .all()
        )
        relationships = db.query(BehavioralSequenceRelationshipModel).filter_by(sequence_id=sequence_id).all()
        evidence_items = db.query(SequenceEvidenceModel).filter_by(sequence_id=sequence_id).all()
        history_records = (
            db.query(SequenceAssessmentHistoryModel)
            .filter_by(sequence_id=sequence_id)
            .order_by(SequenceAssessmentHistoryModel.timestamp.desc())
            .all()
        )

        base_dict = cls._to_sequence_response(seq).model_dump()
        base_dict["members"] = [cls._to_member_response(m) for m in members]
        base_dict["relationships"] = [cls._to_rel_response(r) for r in relationships]
        base_dict["evidence_items"] = [cls._to_evidence_response(e) for e in evidence_items]
        base_dict["history_records"] = [cls._to_history_response(h) for h in history_records]

        return BehavioralSequenceDetailResponse(**base_dict)

    @classmethod
    def get_sequence_timeline(
        cls,
        db: Session,
        sequence_id: str,
        limit: int = 300,
    ) -> SequenceTimelineResponse:
        """Constructs unified multi-session chronological timeline."""
        seq = db.query(BehavioralSequenceModel).filter_by(sequence_id=sequence_id).first()
        if not seq:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sequence '{sequence_id}' not found")

        members = (
            db.query(BehavioralSequenceMemberModel)
            .filter_by(sequence_id=sequence_id)
            .all()
        )
        entries: List[SequenceTimelineEntryResponse] = []

        # Fetch underlying sessions, detections, and mappings
        session_ids = [m.member_record_id for m in members if m.member_type == SequenceMemberType.SESSION.value]
        detection_ids = [m.member_record_id for m in members if m.member_type == SequenceMemberType.DETECTION.value]
        mapping_ids = [m.member_record_id for m in members if m.member_type == SequenceMemberType.ATTACK_MAPPING.value]

        sessions = {
            s.session_id: s
            for s in db.query(ActivitySessionModel).filter(ActivitySessionModel.session_id.in_(session_ids)).all()
        } if session_ids else {}

        detection_uuids = []
        for d in detection_ids:
            try:
                detection_uuids.append(uuid.UUID(d))
            except Exception:
                pass

        detections = {
            str(a.alert_id): a
            for a in db.query(AlertModel).filter(AlertModel.alert_id.in_(detection_uuids)).all()
        } if detection_uuids else {}

        mapping_uuids = []
        for m in mapping_ids:
            try:
                mapping_uuids.append(uuid.UUID(m))
            except Exception:
                pass

        mappings = {
            str(m.mapping_id): m
            for m in db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_id.in_(mapping_uuids)).all()
        } if mapping_uuids else {}

        for m in members:
            if m.member_type == SequenceMemberType.SESSION.value:
                sess = sessions.get(m.member_record_id)
                entries.append(
                    SequenceTimelineEntryResponse(
                        entry_id=f"stl-sess-{m.member_record_id}",
                        sequence_id=sequence_id,
                        member_type=SequenceMemberType.SESSION,
                        member_record_id=m.member_record_id,
                        timestamp=m.observed_at.isoformat(),
                        title=f"Session Started: {sess.decoy_id if sess else 'Decoy'}",
                        description=m.relationship_reason,
                        category="SESSION_BOUNDARY",
                        severity=sess.highest_severity if sess else None,
                        session_id=m.member_record_id,
                        decoy_id=sess.decoy_id if sess else None,
                        details={
                            "event_count": sess.event_count if sess else 0,
                            "target_service": sess.target_service if sess else None,
                            "source_address": sess.source_address if sess else None,
                        },
                    )
                )
            elif m.member_type == SequenceMemberType.DETECTION.value:
                det = detections.get(m.member_record_id)
                entries.append(
                    SequenceTimelineEntryResponse(
                        entry_id=f"stl-det-{m.member_record_id}",
                        sequence_id=sequence_id,
                        member_type=SequenceMemberType.DETECTION,
                        member_record_id=m.member_record_id,
                        timestamp=m.observed_at.isoformat(),
                        title=f"Detection: {det.title if det else 'Security Finding'}",
                        description=det.summary if det else m.relationship_reason,
                        category="DETECTION",
                        severity=det.severity if det else "MEDIUM",
                        decoy_id=det.decoy_id if det else None,
                        details={
                            "rule_id": det.detection_rule_id if det else None,
                            "confidence": det.confidence if det else None,
                        },
                    )
                )
            elif m.member_type == SequenceMemberType.ATTACK_MAPPING.value:
                map_obj = mappings.get(m.member_record_id)
                tech_id = map_obj.technique_id if map_obj else "T1000"
                entries.append(
                    SequenceTimelineEntryResponse(
                        entry_id=f"stl-map-{m.member_record_id}",
                        sequence_id=sequence_id,
                        member_type=SequenceMemberType.ATTACK_MAPPING,
                        member_record_id=m.member_record_id,
                        timestamp=m.observed_at.isoformat(),
                        title=f"ATT&CK Technique: {tech_id}",
                        description=map_obj.mapping_rationale if map_obj else m.relationship_reason,
                        category="INTELLIGENCE",
                        severity=None,
                        technique_id=tech_id,
                        details={
                            "review_status": map_obj.review_status if map_obj else "PENDING",
                            "confidence": map_obj.mapping_confidence if map_obj else None,
                        },
                    )
                )

        # Deterministic Sorting: Primary by timestamp asc, secondary by member_type rank
        rank_map = {
            SequenceMemberType.SESSION: 0,
            SequenceMemberType.DETECTION: 1,
            SequenceMemberType.ATTACK_MAPPING: 2,
        }
        entries.sort(key=lambda x: (x.timestamp, rank_map.get(x.member_type, 3), x.entry_id))

        return SequenceTimelineResponse(
            sequence_id=sequence_id,
            title=seq.title,
            total_entries=len(entries),
            first_observed_at=seq.first_observed_at.isoformat(),
            last_observed_at=seq.last_observed_at.isoformat(),
            entries=entries[:limit],
        )

    @classmethod
    def get_sequence_evidence(cls, db: Session, sequence_id: str) -> List[SequenceEvidenceResponse]:
        """Returns field-level evidence traces justifying sequence relationships."""
        seq = db.query(BehavioralSequenceModel).filter_by(sequence_id=sequence_id).first()
        if not seq:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sequence '{sequence_id}' not found")
        items = db.query(SequenceEvidenceModel).filter_by(sequence_id=sequence_id).all()
        return [cls._to_evidence_response(i) for i in items]

    @classmethod
    def get_sequence_sessions(cls, db: Session, sequence_id: str) -> List[Dict[str, Any]]:
        """Returns referenced ActivitySession records."""
        members = (
            db.query(BehavioralSequenceMemberModel)
            .filter_by(sequence_id=sequence_id, member_type=SequenceMemberType.SESSION.value)
            .all()
        )
        session_ids = [m.member_record_id for m in members]
        if not session_ids:
            return []

        sessions = (
            db.query(ActivitySessionModel)
            .filter(ActivitySessionModel.session_id.in_(session_ids))
            .all()
        )
        return [
            {
                "session_id": s.session_id,
                "decoy_id": s.decoy_id,
                "honeypot_type": s.honeypot_type,
                "source_address": s.source_address,
                "target_service": s.target_service,
                "first_observed_at": s.first_observed_at.isoformat(),
                "last_activity_at": s.last_activity_at.isoformat(),
                "session_status": s.session_status,
                "event_count": s.event_count,
                "detection_count": s.detection_count,
                "highest_severity": s.highest_severity,
            }
            for s in sessions
        ]

    @classmethod
    def get_sequence_detections(cls, db: Session, sequence_id: str) -> List[Dict[str, Any]]:
        """Returns referenced Alert detection findings."""
        members = (
            db.query(BehavioralSequenceMemberModel)
            .filter_by(sequence_id=sequence_id, member_type=SequenceMemberType.DETECTION.value)
            .all()
        )
        alert_ids = [m.member_record_id for m in members]
        if not alert_ids:
            return []

        alert_uuids = []
        for a_id in alert_ids:
            try:
                alert_uuids.append(uuid.UUID(a_id))
            except Exception:
                pass

        alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(alert_uuids)).all() if alert_uuids else []
        return [
            {
                "alert_id": str(a.alert_id),
                "title": a.title,
                "summary": a.summary,
                "severity": a.severity,
                "confidence": a.confidence,
                "detection_rule_id": a.detection_rule_id,
                "decoy_id": a.decoy_id,
                "first_observed_at": a.first_observed_at.isoformat(),
            }
            for a in alerts
        ]

    @classmethod
    def get_sequence_mitre(cls, db: Session, sequence_id: str) -> List[Dict[str, Any]]:
        """Returns referenced ATT&CK technique mappings."""
        members = (
            db.query(BehavioralSequenceMemberModel)
            .filter_by(sequence_id=sequence_id, member_type=SequenceMemberType.ATTACK_MAPPING.value)
            .all()
        )
        map_ids = [m.member_record_id for m in members]
        if not map_ids:
            return []

        map_uuids = []
        for m_id in map_ids:
            try:
                map_uuids.append(uuid.UUID(m_id))
            except Exception:
                pass

        mappings = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_id.in_(map_uuids)).all() if map_uuids else []
        return [
            {
                "mapping_id": str(m.mapping_id),
                "alert_id": str(m.alert_id) if m.alert_id else None,
                "technique_id": m.technique_id,
                "subtechnique_id": m.subtechnique_id,
                "mapping_category": m.mapping_category,
                "mapping_confidence": m.mapping_confidence,
                "review_status": m.review_status,
                "mapping_rationale": m.mapping_rationale,
            }
            for m in mappings
        ]

    @classmethod
    def record_assessment(
        cls,
        db: Session,
        sequence_id: str,
        req: SequenceAssessmentRequest,
        analyst_id: str = "analyst",
    ) -> BehavioralSequenceResponse:
        """Records an authorized analyst investigation assessment."""
        seq = db.query(BehavioralSequenceModel).filter_by(sequence_id=sequence_id).first()
        if not seq:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sequence '{sequence_id}' not found")

        action_map = {
            "CONFIRM": ("CONFIRMED_PROGRESSION", SequenceLifecycleStatus.REVIEWED.value),
            "DISMISS": ("DISMISSED_COINCIDENCE", SequenceLifecycleStatus.DISMISSED.value),
            "INCONCLUSIVE": ("INCONCLUSIVE", SequenceLifecycleStatus.UNDER_REVIEW.value),
        }
        review_stat, target_life = action_map.get(req.assessment_action.upper(), ("INCONCLUSIVE", SequenceLifecycleStatus.UNDER_REVIEW.value))

        if req.new_status:
            target_life = req.new_status.value

        prev_status = seq.lifecycle_status
        seq.analyst_review_status = review_stat
        seq.lifecycle_status = target_life
        now_utc = datetime.now(timezone.utc)
        seq.updated_at = now_utc

        # Log History Record
        hist = SequenceAssessmentHistoryModel(
            sequence_id=sequence_id,
            assessed_by=analyst_id,
            previous_status=prev_status,
            new_status=target_life,
            assessment_action=f"ANALYST_{req.assessment_action.upper()}",
            assessment_notes=req.review_notes,
            policy_version=seq.correlation_policy_version,
            timestamp=now_utc,
        )
        db.add(hist)
        db.commit()

        return cls._to_sequence_response(seq)

    @classmethod
    def update_status(
        cls,
        db: Session,
        sequence_id: str,
        req: SequenceStatusUpdateRequest,
        actor_id: str = "analyst",
    ) -> BehavioralSequenceResponse:
        """Transitions sequence lifecycle status."""
        seq = db.query(BehavioralSequenceModel).filter_by(sequence_id=sequence_id).first()
        if not seq:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sequence '{sequence_id}' not found")

        prev_status = seq.lifecycle_status
        seq.lifecycle_status = req.new_status.value
        now_utc = datetime.now(timezone.utc)
        seq.updated_at = now_utc

        hist = SequenceAssessmentHistoryModel(
            sequence_id=sequence_id,
            assessed_by=actor_id,
            previous_status=prev_status,
            new_status=req.new_status.value,
            assessment_action="STATUS_CHANGED",
            assessment_notes=req.reason,
            policy_version=seq.correlation_policy_version,
            timestamp=now_utc,
        )
        db.add(hist)
        db.commit()

        return cls._to_sequence_response(seq)

    @classmethod
    def get_statistics(cls, db: Session) -> SequenceStatisticsResponse:
        """Computes aggregate operational and discovery statistics."""
        total = db.query(BehavioralSequenceModel).count()
        new_cnt = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="NEW").count()
        obs_cnt = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="OBSERVING").count()
        under_rev = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="UNDER_REVIEW").count()
        reviewed = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="REVIEWED").count()
        dismissed = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="DISMISSED").count()
        closed = db.query(BehavioralSequenceModel).filter_by(lifecycle_status="CLOSED").count()

        total_sessions = db.query(func.coalesce(func.sum(BehavioralSequenceModel.session_count), 0)).scalar() or 0
        avg_sess = round(float(total_sessions) / total, 2) if total > 0 else 0.0

        # Pattern counts
        pat_rows = (
            db.query(BehavioralSequenceModel.sequence_pattern, func.count(BehavioralSequenceModel.id))
            .group_by(BehavioralSequenceModel.sequence_pattern)
            .all()
        )
        by_pat = {r[0]: r[1] for r in pat_rows}

        # Severity counts
        sev_rows = (
            db.query(BehavioralSequenceModel.aggregate_severity, func.count(BehavioralSequenceModel.id))
            .group_by(BehavioralSequenceModel.aggregate_severity)
            .all()
        )
        by_sev = {r[0] or "INFO": r[1] for r in sev_rows}

        # Review status counts
        rev_rows = (
            db.query(BehavioralSequenceModel.analyst_review_status, func.count(BehavioralSequenceModel.id))
            .group_by(BehavioralSequenceModel.analyst_review_status)
            .all()
        )
        by_rev = {r[0]: r[1] for r in rev_rows}

        return SequenceStatisticsResponse(
            total_sequences=total,
            new_sequences=new_cnt,
            observing_sequences=obs_cnt,
            under_review_sequences=under_rev,
            reviewed_sequences=reviewed,
            dismissed_sequences=dismissed,
            closed_sequences=closed,
            average_sessions_per_sequence=avg_sess,
            by_pattern=by_pat,
            by_severity=by_sev,
            by_review_status=by_rev,
        )

    # -------------------------------------------------------------------------
    # Serialization Helpers
    # -------------------------------------------------------------------------

    @classmethod
    def _to_sequence_response(cls, model: BehavioralSequenceModel) -> BehavioralSequenceResponse:
        return BehavioralSequenceResponse(
            sequence_id=model.sequence_id,
            title=model.title,
            sequence_pattern=SequencePatternType(model.sequence_pattern),
            description=model.description,
            lifecycle_status=SequenceLifecycleStatus(model.lifecycle_status),
            first_observed_at=model.first_observed_at.isoformat(),
            last_observed_at=model.last_observed_at.isoformat(),
            session_count=model.session_count,
            event_count=model.event_count,
            detection_count=model.detection_count,
            correlation_confidence=model.correlation_confidence,
            sequence_relevance=model.sequence_relevance,
            aggregate_severity=model.aggregate_severity,
            analyst_review_status=model.analyst_review_status,
            primary_source_address=model.primary_source_address,
            primary_decoy_id=model.primary_decoy_id,
            correlation_policy_version=model.correlation_policy_version,
            metadata_summary=model.metadata_summary or {},
            created_at=model.created_at.isoformat(),
            updated_at=model.updated_at.isoformat() if model.updated_at else None,
        )

    @classmethod
    def _to_member_response(cls, m: BehavioralSequenceMemberModel) -> SequenceMemberResponse:
        return SequenceMemberResponse(
            id=str(m.id),
            sequence_id=m.sequence_id,
            member_type=SequenceMemberType(m.member_type),
            member_record_id=m.member_record_id,
            sequence_position=m.sequence_position,
            observed_at=m.observed_at.isoformat(),
            relationship_reason=m.relationship_reason,
            correlation_method=m.correlation_method,
            created_at=m.created_at.isoformat(),
        )

    @classmethod
    def _to_rel_response(cls, r: BehavioralSequenceRelationshipModel) -> SequenceRelationshipResponse:
        return SequenceRelationshipResponse(
            id=str(r.id),
            sequence_id=r.sequence_id,
            source_member_id=str(r.source_member_id),
            target_member_id=str(r.target_member_id),
            relationship_type=r.relationship_type,
            explanation=r.explanation,
            confidence_score=r.confidence_score,
            evidence_payload=r.evidence_payload or {},
            created_at=r.created_at.isoformat(),
        )

    @classmethod
    def _to_evidence_response(cls, e: SequenceEvidenceModel) -> SequenceEvidenceResponse:
        return SequenceEvidenceResponse(
            id=str(e.id),
            sequence_id=e.sequence_id,
            evidence_record_type=e.evidence_record_type,
            evidence_record_id=e.evidence_record_id,
            field_name=e.field_name,
            field_value=e.field_value,
            evidence_provenance=e.evidence_provenance or {},
            observed_at=e.observed_at.isoformat(),
            created_at=e.created_at.isoformat(),
        )

    @classmethod
    def _to_history_response(cls, h: SequenceAssessmentHistoryModel) -> SequenceHistoryResponse:
        return SequenceHistoryResponse(
            id=str(h.id),
            sequence_id=h.sequence_id,
            assessed_by=h.assessed_by,
            previous_status=h.previous_status,
            new_status=h.new_status,
            assessment_action=h.assessment_action,
            assessment_notes=h.assessment_notes,
            policy_version=h.policy_version,
            timestamp=h.timestamp.isoformat(),
        )
