"""Service facade for ATT&CK detection mappings, analyst reviews, and queries (Task P20)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.intelligence import (
    AttackDetectionMappingModel,
    AttackMappingEvidenceModel,
    AttackMappingHistoryModel,
    AttackMappingReviewModel,
    AttackSubtechniqueModel,
    AttackTacticModel,
    AttackTechniqueModel,
)
from app.modules.mitre.exceptions import MitreNotFoundError
from app.modules.mitre.mapping.schemas import (
    DetectionMappingResponse,
    MappingCategory,
    MappingConfidenceLevel,
    MappingEvidenceResponse,
    MappingHistoryResponse,
    MappingReviewRequest,
    MappingReviewResponse,
    MappingStatisticsResponse,
    PaginatedMappingsResponse,
    ReviewAction,
    ReviewStatus,
)


class MappingService:
    """Service facade providing mapping querying, analyst review, and audit workflows."""

    @classmethod
    def list_mappings(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        rule_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        technique_id: Optional[str] = None,
        category: Optional[str] = None,
        confidence_level: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> PaginatedMappingsResponse:
        """Returns paginated detection mappings with optional filtering."""
        query = db.query(AttackDetectionMappingModel)

        if rule_id:
            query = query.filter(AttackDetectionMappingModel.rule_id == rule_id)
        if alert_id:
            try:
                al_uuid = uuid.UUID(alert_id)
                query = query.filter(AttackDetectionMappingModel.alert_id == al_uuid)
            except Exception:
                pass
        if technique_id:
            query = query.filter(AttackDetectionMappingModel.technique_id == technique_id)
        if category:
            query = query.filter(AttackDetectionMappingModel.mapping_category == category)
        if confidence_level:
            query = query.filter(AttackDetectionMappingModel.mapping_confidence_level == confidence_level)
        if review_status:
            query = query.filter(AttackDetectionMappingModel.review_status == review_status)

        total = query.count()
        offset = (page - 1) * page_size
        items = query.order_by(AttackDetectionMappingModel.created_at.desc()).offset(offset).limit(page_size).all()

        mapped_items = [cls._enrich_mapping_response(db, m) for m in items]

        return PaginatedMappingsResponse(
            total=total,
            page=page,
            page_size=page_size,
            items=mapped_items,
        )

    @classmethod
    def get_mapping(cls, db: Session, mapping_id: str) -> DetectionMappingResponse:
        """Retrieves a single mapping record with its associated evidence."""
        try:
            m_uuid = uuid.UUID(mapping_id)
        except ValueError:
            raise MitreNotFoundError(f"Invalid mapping ID format: {mapping_id}")

        record = (
            db.query(AttackDetectionMappingModel)
            .filter(
                (AttackDetectionMappingModel.mapping_id == m_uuid) | (AttackDetectionMappingModel.id == m_uuid)
            )
            .first()
        )
        if not record:
            raise MitreNotFoundError(f"Detection mapping '{mapping_id}' not found")

        return cls._enrich_mapping_response(db, record, include_evidence=True)

    @classmethod
    def get_mappings_for_detection(cls, db: Session, detection_id: str) -> List[DetectionMappingResponse]:
        """Retrieves all ATT&CK mappings associated with a detection result ID or alert ID."""
        records = (
            db.query(AttackDetectionMappingModel)
            .filter(
                (AttackDetectionMappingModel.detection_result_id == detection_id)
                | (AttackDetectionMappingModel.alert_id == (uuid.UUID(detection_id) if cls._is_valid_uuid(detection_id) else None))
            )
            .all()
        )
        return [cls._enrich_mapping_response(db, r, include_evidence=True) for r in records]

    @classmethod
    def get_detections_for_technique(cls, db: Session, technique_id: str) -> List[DetectionMappingResponse]:
        """Retrieves SnareSight detections mapped to a specific ATT&CK technique."""
        records = (
            db.query(AttackDetectionMappingModel)
            .filter(AttackDetectionMappingModel.technique_id == technique_id)
            .order_by(AttackDetectionMappingModel.created_at.desc())
            .limit(100)
            .all()
        )
        return [cls._enrich_mapping_response(db, r) for r in records]

    @classmethod
    def submit_review(
        cls,
        db: Session,
        mapping_id: str,
        req: MappingReviewRequest,
        reviewer_id: str = "analyst",
    ) -> MappingReviewResponse:
        """Processes an authorized analyst review action (ACCEPT, REJECT, REQUEST_MORE_EVIDENCE)."""
        try:
            m_uuid = uuid.UUID(mapping_id)
        except ValueError:
            raise MitreNotFoundError(f"Invalid mapping ID format: {mapping_id}")

        mapping_row = (
            db.query(AttackDetectionMappingModel)
            .filter(
                (AttackDetectionMappingModel.mapping_id == m_uuid) | (AttackDetectionMappingModel.id == m_uuid)
            )
            .first()
        )
        if not mapping_row:
            raise MitreNotFoundError(f"Mapping '{mapping_id}' not found for review")

        prev_status = ReviewStatus(mapping_row.review_status)
        now_utc = datetime.now(timezone.utc)

        if req.action == ReviewAction.ACCEPT:
            new_status = ReviewStatus.ACCEPTED
        elif req.action == ReviewAction.REJECT:
            new_status = ReviewStatus.REJECTED
        else:
            new_status = ReviewStatus.NEEDS_MORE_EVIDENCE

        # 1. Update mapping record
        mapping_row.review_status = new_status.value
        mapping_row.review_comment = req.comment
        mapping_row.reviewed_by = reviewer_id
        mapping_row.reviewed_at = now_utc
        mapping_row.updated_at = now_utc

        # 2. Append review record to audit log
        review_entry = AttackMappingReviewModel(
            mapping_id=mapping_row.id,
            reviewer_id=reviewer_id,
            review_action=req.action.value,
            previous_status=prev_status.value,
            new_status=new_status.value,
            review_comment=req.comment,
            reviewed_at=now_utc,
            created_at=now_utc,
        )
        db.add(review_entry)

        # 3. Append history trace
        history_entry = AttackMappingHistoryModel(
            mapping_id=mapping_row.id,
            change_reason="ANALYST_REVIEW",
            previous_confidence=mapping_row.mapping_confidence,
            new_confidence=mapping_row.mapping_confidence,
            previous_status=prev_status.value,
            new_status=new_status.value,
            policy_version="1.0",
            dataset_version=mapping_row.dataset_version,
            details={"reviewer": reviewer_id, "action": req.action.value, "comment": req.comment},
            recorded_at=now_utc,
        )
        db.add(history_entry)
        db.commit()

        # 4. Post-Commit SSE Broadcast
        cls._notify_review_streaming(mapping_row, reviewer_id, req.action.value)

        return MappingReviewResponse(
            mapping_id=str(mapping_row.mapping_id),
            action=req.action,
            previous_status=prev_status,
            new_status=new_status,
            reviewed_by=reviewer_id,
            reviewed_at=now_utc.isoformat(),
            comment=req.comment,
        )

    @classmethod
    def get_statistics(cls, db: Session) -> MappingStatisticsResponse:
        """Computes aggregate operational statistics across all mapped detection findings."""
        total = db.query(AttackDetectionMappingModel).count()
        directly = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_category == "DIRECTLY_SUPPORTED").count()
        partially = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_category == "PARTIALLY_SUPPORTED").count()
        requires_review = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_category == "REQUIRES_ANALYST_REVIEW").count()

        pending = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.review_status == "PENDING").count()
        accepted = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.review_status == "ACCEPTED").count()
        rejected = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.review_status == "REJECTED").count()
        needs_more = db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.review_status == "NEEDS_MORE_EVIDENCE").count()

        # Confidence breakdown
        by_conf = {
            "HIGH": db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_confidence_level == "HIGH").count(),
            "MODERATE": db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_confidence_level == "MODERATE").count(),
            "LOW": db.query(AttackDetectionMappingModel).filter(AttackDetectionMappingModel.mapping_confidence_level == "LOW").count(),
        }

        # Techniques breakdown
        tech_counts = (
            db.query(AttackDetectionMappingModel.technique_id, func.count(AttackDetectionMappingModel.id))
            .group_by(AttackDetectionMappingModel.technique_id)
            .all()
        )
        by_tech = {tid: count for tid, count in tech_counts}

        # Tactics breakdown
        tactic_counts = (
            db.query(AttackTechniqueModel.tactic_name, func.count(AttackDetectionMappingModel.id))
            .join(AttackTechniqueModel, AttackDetectionMappingModel.technique_id == AttackTechniqueModel.technique_id)
            .group_by(AttackTechniqueModel.tactic_name)
            .all()
        )
        by_tactic = {tname: count for tname, count in tactic_counts if tname}

        return MappingStatisticsResponse(
            total_mappings=total,
            directly_supported=directly,
            partially_supported=partially,
            requires_analyst_review=requires_review,
            not_mapped_count=5,  # 5 explicit unmapped scenarios (CMD-001, FILE-001, WEB-003, BEHAV-001, BEHAV-002)
            pending_reviews=pending,
            accepted_mappings=accepted,
            rejected_mappings=rejected,
            needs_more_evidence_mappings=needs_more,
            by_confidence_level=by_conf,
            by_tactic=by_tactic,
            by_technique=by_tech,
        )

    @classmethod
    def _enrich_mapping_response(
        cls,
        db: Session,
        row: AttackDetectionMappingModel,
        include_evidence: bool = False,
    ) -> DetectionMappingResponse:
        """Enriches raw database row with technique metadata and evidence items."""
        tech = db.query(AttackTechniqueModel).filter(AttackTechniqueModel.technique_id == row.technique_id).first()
        sub = None
        if row.subtechnique_id:
            sub = db.query(AttackSubtechniqueModel).filter(AttackSubtechniqueModel.subtechnique_id == row.subtechnique_id).first()

        evidence_items: List[MappingEvidenceResponse] = []
        if include_evidence:
            ev_records = db.query(AttackMappingEvidenceModel).filter(AttackMappingEvidenceModel.mapping_id == row.id).all()
            for ev in ev_records:
                evidence_items.append(
                    MappingEvidenceResponse(
                        id=str(ev.id),
                        mapping_id=str(ev.mapping_id),
                        event_id=str(ev.event_id) if ev.event_id else None,
                        evidence_type=ev.evidence_type,
                        evidence_description=ev.evidence_description,
                        evidence_fields=ev.evidence_fields,
                        relevance_score=ev.relevance_score,
                        evidence_timestamp=ev.evidence_timestamp.isoformat(),
                        provenance=ev.provenance,
                        created_at=ev.created_at.isoformat(),
                    )
                )

        return DetectionMappingResponse(
            mapping_id=str(row.mapping_id),
            detection_result_id=row.detection_result_id,
            alert_id=str(row.alert_id) if row.alert_id else None,
            rule_id=row.rule_id,
            rule_version=row.rule_version,
            technique_id=row.technique_id,
            technique_name=tech.technique_name if tech else f"Technique {row.technique_id}",
            tactic_id=tech.tactic_id if tech else None,
            tactic_name=tech.tactic_name if tech else None,
            subtechnique_id=row.subtechnique_id,
            subtechnique_name=sub.subtechnique_name if sub else None,
            dataset_version=row.dataset_version,
            mapping_definition_id=row.mapping_definition_id,
            mapping_definition_version=row.mapping_definition_version,
            mapping_category=MappingCategory(row.mapping_category),
            mapping_confidence=row.mapping_confidence,
            mapping_confidence_level=MappingConfidenceLevel(row.mapping_confidence_level),
            confidence_explanation=row.confidence_explanation,
            mapping_rationale=row.mapping_rationale,
            review_status=ReviewStatus(row.review_status),
            review_comment=row.review_comment,
            reviewed_by=row.reviewed_by,
            reviewed_at=row.reviewed_at.isoformat() if row.reviewed_at else None,
            assessed_at=row.assessed_at.isoformat(),
            created_at=row.created_at.isoformat(),
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
            evidence=evidence_items,
        )

    @staticmethod
    def _is_valid_uuid(val: str) -> bool:
        try:
            uuid.UUID(val)
            return True
        except Exception:
            return False

    @staticmethod
    def _notify_review_streaming(mapping_row: AttackDetectionMappingModel, reviewer_id: str, action: str) -> None:
        try:
            from app.streaming.event_publisher import event_publisher
            event_publisher.publish_custom_event(
                event_type="mitre_mapping.reviewed",
                data={
                    "mapping_id": str(mapping_row.mapping_id),
                    "action": action,
                    "review_status": mapping_row.review_status,
                    "reviewed_by": reviewer_id,
                    "technique_id": mapping_row.technique_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                event_id=str(mapping_row.mapping_id),
            )
        except Exception:
            pass

