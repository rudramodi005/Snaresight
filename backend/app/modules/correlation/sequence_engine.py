"""Behavioral Sequence Discovery Engine (Task P22).

Identifies related suspicious multi-session activity, matches behavioral patterns,
and transactionally constructs explainable attack-chain candidates.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.correlation import ActivitySessionModel, ActivitySessionEventModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.modules.correlation.sequence_evidence import SequenceEvidenceBuilder
from app.modules.correlation.sequence_models import (
    BehavioralSequenceModel,
    BehavioralSequenceMemberModel,
    BehavioralSequenceRelationshipModel,
    SequenceAssessmentHistoryModel,
    SequenceEvidenceModel,
)
from app.modules.correlation.sequence_policy import (
    CrossSessionCorrelationPolicy,
    default_sequence_policy,
)
from app.modules.correlation.sequence_schemas import (
    SequenceLifecycleStatus,
    SequenceMemberType,
    SequencePatternType,
    SequenceRelationshipType,
)
from app.modules.correlation.sequence_scoring import SequenceScorer


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class SequenceEngine:
    """Core processor coordinating multi-session candidate discovery, pattern evaluation, and sequence construction."""

    def __init__(self, policy: Optional[CrossSessionCorrelationPolicy] = None):
        self.policy = policy or default_sequence_policy

    def evaluate_session(self, db: Session, session_id: str) -> Optional[BehavioralSequenceModel]:
        """Evaluates an ActivitySession for inclusion in a new or existing behavioral sequence.
        
        Guarantees:
        - Deterministic & Idempotent: Re-evaluating returns the existing sequence association.
        - Bounded execution: Queries only recent sessions within configured time window.
        - Non-destructive: Leaves original session and event records unmodified.
        """
        session = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_id == session_id).first()
        if not session:
            return None

        # 1. Idempotency Check: Has this session already been assigned to an active sequence?
        existing_member = (
            db.query(BehavioralSequenceMemberModel)
            .filter(
                BehavioralSequenceMemberModel.member_type == SequenceMemberType.SESSION.value,
                BehavioralSequenceMemberModel.member_record_id == session_id,
            )
            .first()
        )
        if existing_member:
            return (
                db.query(BehavioralSequenceModel)
                .filter(BehavioralSequenceModel.sequence_id == existing_member.sequence_id)
                .first()
            )

        sess_obs = _ensure_utc(session.first_observed_at)

        # 2. Bounded Candidate Query: Find candidate sessions within temporal correlation window
        # Constraint: Must share observed source address OR decoy ID OR have detections
        min_time = sess_obs - timedelta(seconds=self.policy.max_correlation_window_seconds)
        max_time = sess_obs + timedelta(seconds=self.policy.max_correlation_window_seconds)

        candidates = (
            db.query(ActivitySessionModel)
            .filter(
                ActivitySessionModel.session_id != session_id,
                ActivitySessionModel.first_observed_at >= min_time,
                ActivitySessionModel.first_observed_at <= max_time,
            )
            .order_by(ActivitySessionModel.first_observed_at.asc())
            .all()
        )

        # Filter candidates based on correlation signals (Level 1 to 3)
        relevant_candidates: List[ActivitySessionModel] = []
        has_shared_source_context = False

        for cand in candidates:
            cand_obs = _ensure_utc(cand.first_observed_at)
            is_valid_window, _ = self.policy.is_within_temporal_window(sess_obs, cand_obs)
            if not is_valid_window:
                continue

            # Level 2 Check: Shared Source Address
            if session.source_address and session.source_address != "0.0.0.0" and session.source_address == cand.source_address:
                relevant_candidates.append(cand)
                has_shared_source_context = True
            # Related Decoy Target Check (if both have detections)
            elif session.decoy_id == cand.decoy_id and (session.detection_count > 0 or cand.detection_count > 0):
                relevant_candidates.append(cand)

        if not relevant_candidates:
            # Level 5: Insufficient cross-session evidence
            return None

        # 3. Gather Detections and ATT&CK Mappings across candidate cluster
        all_sessions = relevant_candidates + [session]
        all_session_ids = [s.session_id for s in all_sessions]

        # Retrieve events
        all_event_ids = [
            row[0]
            for row in db.query(ActivitySessionEventModel.event_id)
            .filter(ActivitySessionEventModel.session_id.in_(all_session_ids))
            .all()
        ]

        # Retrieve alerts
        alerts: List[AlertModel] = []
        if all_event_ids:
            alert_ids = [
                row[0]
                for row in db.query(AlertEvidenceModel.alert_id)
                .filter(AlertEvidenceModel.event_id.in_(all_event_ids))
                .distinct()
                .all()
            ]
            if alert_ids:
                alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(alert_ids)).all()

        # Retrieve mappings
        mappings: List[AttackDetectionMappingModel] = []
        if alerts:
            alert_uuids = [a.alert_id for a in alerts]
            mappings = (
                db.query(AttackDetectionMappingModel)
                .filter(AttackDetectionMappingModel.alert_id.in_(alert_uuids))
                .all()
            )

        # Format dict representations for policy matching
        session_dicts = [
            {
                "session_id": s.session_id,
                "decoy_id": s.decoy_id,
                "honeypot_type": s.honeypot_type,
                "source_address": s.source_address,
                "target_service": s.target_service,
                "protocol": s.protocol,
                "first_observed_at": _ensure_utc(s.first_observed_at),
                "last_activity_at": _ensure_utc(s.last_activity_at),
                "event_count": s.event_count,
                "detection_count": s.detection_count,
                "metadata_summary": s.metadata_summary or {},
            }
            for s in all_sessions
        ]
        detection_dicts = [
            {
                "alert_id": str(a.alert_id),
                "detection_rule_id": a.detection_rule_id,
                "severity": a.severity,
                "first_observed_at": _ensure_utc(a.first_observed_at),
            }
            for a in alerts
        ]
        mapping_dicts = [
            {
                "mapping_id": str(m.mapping_id),
                "technique_id": m.technique_id,
                "subtechnique_id": m.subtechnique_id,
                "review_status": m.review_status,
            }
            for m in mappings
        ]

        # 4. Evaluate Behavioral Pattern
        match = self.policy.match_behavioral_pattern(
            sessions=session_dicts,
            detections=detection_dicts,
            mappings=mapping_dicts,
        )
        if not match:
            # Insufficient behavioral pattern match
            return None

        pattern_type, seq_title, pattern_rationale = match

        # 5. Check if any relevant candidate is already part of an open sequence
        target_seq: Optional[BehavioralSequenceModel] = None
        cand_session_ids = [c.session_id for c in relevant_candidates]

        existing_cand_member = (
            db.query(BehavioralSequenceMemberModel)
            .filter(
                BehavioralSequenceMemberModel.member_type == SequenceMemberType.SESSION.value,
                BehavioralSequenceMemberModel.member_record_id.in_(cand_session_ids),
            )
            .first()
        )
        if existing_cand_member:
            candidate_seq = (
                db.query(BehavioralSequenceModel)
                .filter(
                    BehavioralSequenceModel.sequence_id == existing_cand_member.sequence_id,
                    BehavioralSequenceModel.lifecycle_status.in_([
                        SequenceLifecycleStatus.NEW.value,
                        SequenceLifecycleStatus.OBSERVING.value,
                    ]),
                )
                .first()
            )
            if candidate_seq:
                target_seq = candidate_seq

        # 6. Compute Scores
        conf, rel, agg_sev, score_explanation = SequenceScorer.compute_scores(
            sessions=session_dicts,
            detections=detection_dicts,
            mappings=mapping_dicts,
            pattern=pattern_type,
            has_shared_trusted_id=False,
            has_shared_source_context=has_shared_source_context,
        )

        now_utc = datetime.now(timezone.utc)

        if target_seq:
            # 7A. Update Existing Sequence
            seq_model = self._attach_to_existing_sequence(
                db=db,
                sequence=target_seq,
                new_session=session,
                pattern_type=pattern_type,
                pattern_rationale=pattern_rationale,
                confidence=conf,
                relevance=rel,
                aggregate_severity=agg_sev,
                score_explanation=score_explanation,
                alerts=alerts,
                mappings=mappings,
                now_utc=now_utc,
            )
        else:
            # 7B. Create New Behavioral Sequence
            seq_model = self._create_new_sequence(
                db=db,
                sessions=all_sessions,
                pattern_type=pattern_type,
                title=seq_title,
                rationale=pattern_rationale,
                confidence=conf,
                relevance=rel,
                aggregate_severity=agg_sev,
                score_explanation=score_explanation,
                alerts=alerts,
                mappings=mappings,
                now_utc=now_utc,
            )

        db.commit()
        return seq_model

    def _create_new_sequence(
        self,
        db: Session,
        sessions: List[ActivitySessionModel],
        pattern_type: SequencePatternType,
        title: str,
        rationale: str,
        confidence: int,
        relevance: int,
        aggregate_severity: str,
        score_explanation: Dict[str, Any],
        alerts: List[AlertModel],
        mappings: List[AttackDetectionMappingModel],
        now_utc: datetime,
    ) -> BehavioralSequenceModel:
        """Instantiates a new BehavioralSequence and builds member, relationship, and evidence graphs."""
        new_seq_id = f"seq-{now_utc.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

        sorted_sessions = sorted(sessions, key=lambda s: _ensure_utc(s.first_observed_at))
        t_first = _ensure_utc(sorted_sessions[0].first_observed_at)
        t_last = max(_ensure_utc(s.last_activity_at) for s in sorted_sessions)

        primary_ip = sorted_sessions[0].source_address
        primary_decoy = sorted_sessions[0].decoy_id
        tot_events = sum(s.event_count for s in sorted_sessions)

        seq = BehavioralSequenceModel(
            sequence_id=new_seq_id,
            title=title,
            sequence_pattern=pattern_type.value,
            description=f"Automated behavioral candidate grouping across {len(sessions)} sessions. {rationale}.",
            lifecycle_status=SequenceLifecycleStatus.NEW.value,
            first_observed_at=t_first,
            last_observed_at=t_last,
            session_count=len(sessions),
            event_count=tot_events,
            detection_count=len(alerts),
            correlation_confidence=confidence,
            sequence_relevance=relevance,
            aggregate_severity=aggregate_severity,
            analyst_review_status="UNREVIEWED",
            primary_source_address=primary_ip,
            primary_decoy_id=primary_decoy,
            correlation_policy_version=self.policy.policy_version,
            metadata_summary={
                "pattern_rationale": rationale,
                "score_explanation": score_explanation,
                "disclaimer": "Behavioral sequence candidate requiring analyst validation. Does not establish human identity or compromise.",
            },
            created_at=now_utc,
        )
        db.add(seq)
        db.flush()

        # Add Members and build chronological edges
        prev_member: Optional[BehavioralSequenceMemberModel] = None
        for pos, s in enumerate(sorted_sessions):
            reason = f"Session #{pos+1} on {s.decoy_id} ({s.target_service}) with {s.event_count} events"
            member = SequenceEvidenceBuilder.create_session_member(
                sequence_id=new_seq_id,
                session=s,
                position=pos,
                reason=reason,
                correlation_method="BEHAVIORAL_PATTERN",
            )
            db.add(member)
            db.flush()

            # Relationship to previous session: OBSERVED_BEFORE
            if prev_member:
                rel = SequenceEvidenceBuilder.create_relationship(
                    sequence_id=new_seq_id,
                    source_member_id=prev_member.id,
                    target_member_id=member.id,
                    rel_type=SequenceRelationshipType.OBSERVED_BEFORE,
                    explanation=f"Session {prev_member.member_record_id} preceded session {member.member_record_id}",
                    confidence=confidence,
                )
                db.add(rel)

                if s.source_address == sorted_sessions[pos-1].source_address:
                    rel_ctx = SequenceEvidenceBuilder.create_relationship(
                        sequence_id=new_seq_id,
                        source_member_id=prev_member.id,
                        target_member_id=member.id,
                        rel_type=SequenceRelationshipType.SHARED_SOURCE_CONTEXT,
                        explanation=f"Shared source IP address {s.source_address} across sessions",
                        confidence=confidence,
                    )
                    db.add(rel_ctx)

            prev_member = member

            # Field Evidence Trace
            ev = SequenceEvidenceBuilder.create_field_evidence(
                sequence_id=new_seq_id,
                record_type="SESSION",
                record_id=s.session_id,
                field_name="source_address",
                field_value=s.source_address or "unknown",
                observed_at=s.first_observed_at,
                provenance={"decoy_id": s.decoy_id, "service": s.target_service},
            )
            db.add(ev)

        # Add Detections as Members
        det_pos = len(sorted_sessions)
        for a in alerts:
            det_member = SequenceEvidenceBuilder.create_detection_member(
                sequence_id=new_seq_id,
                alert=a,
                position=det_pos,
                reason=f"Detection rule {a.detection_rule_id} triggered with severity {a.severity}",
            )
            db.add(det_member)
            det_pos += 1

            ev_det = SequenceEvidenceBuilder.create_field_evidence(
                sequence_id=new_seq_id,
                record_type="DETECTION",
                record_id=str(a.alert_id),
                field_name="detection_rule_id",
                field_value=a.detection_rule_id,
                observed_at=a.first_observed_at,
                provenance={"rule_version": a.detection_rule_version, "confidence": a.confidence},
            )
            db.add(ev_det)

        # Add ATT&CK Mappings as Members
        for m in mappings:
            map_member = SequenceEvidenceBuilder.create_mapping_member(
                sequence_id=new_seq_id,
                mapping=m,
                position=det_pos,
                reason=f"ATT&CK Technique {m.technique_id} mapped to alert {m.alert_id}",
            )
            db.add(map_member)
            det_pos += 1

        # Audit History Record
        hist = SequenceAssessmentHistoryModel(
            sequence_id=new_seq_id,
            assessed_by="system",
            previous_status=None,
            new_status=SequenceLifecycleStatus.NEW.value,
            assessment_action="SEQUENCE_DISCOVERED",
            assessment_notes=f"Sequence candidate generated matching pattern {pattern_type.value}.",
            policy_version=self.policy.policy_version,
            timestamp=now_utc,
        )
        db.add(hist)

        return seq

    def _attach_to_existing_sequence(
        self,
        db: Session,
        sequence: BehavioralSequenceModel,
        new_session: ActivitySessionModel,
        pattern_type: SequencePatternType,
        pattern_rationale: str,
        confidence: int,
        relevance: int,
        aggregate_severity: str,
        score_explanation: Dict[str, Any],
        alerts: List[AlertModel],
        mappings: List[AttackDetectionMappingModel],
        now_utc: datetime,
    ) -> BehavioralSequenceModel:
        """Attaches an additional session to an active sequence and recalculates aggregates."""
        sess_first = _ensure_utc(new_session.first_observed_at)
        sess_last = _ensure_utc(new_session.last_activity_at)

        # Update sequence temporal window
        if sess_first < _ensure_utc(sequence.first_observed_at):
            sequence.first_observed_at = sess_first
        if sess_last > _ensure_utc(sequence.last_observed_at):
            sequence.last_observed_at = sess_last

        sequence.session_count += 1
        sequence.event_count += new_session.event_count
        sequence.detection_count = len(alerts)
        sequence.correlation_confidence = confidence
        sequence.sequence_relevance = relevance
        sequence.aggregate_severity = aggregate_severity
        sequence.lifecycle_status = SequenceLifecycleStatus.OBSERVING.value
        sequence.updated_at = now_utc

        # Add new session member
        cur_pos = db.query(func.coalesce(func.max(BehavioralSequenceMemberModel.sequence_position), 0)).filter_by(sequence_id=sequence.sequence_id).scalar() or 0
        new_pos = cur_pos + 1

        member = SequenceEvidenceBuilder.create_session_member(
            sequence_id=sequence.sequence_id,
            session=new_session,
            position=new_pos,
            reason=f"Attached additional session on {new_session.decoy_id} ({new_session.target_service})",
            correlation_method="BEHAVIORAL_PATTERN",
        )
        db.add(member)

        # Field Evidence Trace
        ev = SequenceEvidenceBuilder.create_field_evidence(
            sequence_id=sequence.sequence_id,
            record_type="SESSION",
            record_id=new_session.session_id,
            field_name="source_address",
            field_value=new_session.source_address or "unknown",
            observed_at=new_session.first_observed_at,
            provenance={"decoy_id": new_session.decoy_id, "service": new_session.target_service},
        )
        db.add(ev)

        # Audit History Record
        hist = SequenceAssessmentHistoryModel(
            sequence_id=sequence.sequence_id,
            assessed_by="system",
            previous_status=sequence.lifecycle_status,
            new_status=SequenceLifecycleStatus.OBSERVING.value,
            assessment_action="SESSION_ATTACHED",
            assessment_notes=f"Attached session {new_session.session_id} to existing sequence.",
            policy_version=self.policy.policy_version,
            timestamp=now_utc,
        )
        db.add(hist)

        return sequence


# Default engine instance
default_sequence_engine = SequenceEngine()

