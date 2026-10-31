"""Service layer for Observed Source Profiles and Behavioral Intelligence."""

import uuid
from datetime import datetime, timezone
from typing import Any, Tuple
from sqlalchemy import select, func, desc, asc, or_
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.db.models.source_profile import (
    SourceProfileModel,
    SourceProfileSessionModel,
    SourceProfileFeatureModel,
    SourceProfileHistoryModel,
    SourceProfileRecurrenceModel,
)
from app.db.models.correlation import ActivitySessionModel
from app.db.models.event import SecurityEventModel
from app.db.models.alert import AlertModel
from app.modules.source_intelligence.schemas import (
    SourceProfileResponse,
    SourceProfileListResponse,
    FeatureMetricsResponse,
    ProfileBehaviorResponse,
    ProfileTrendsResponse,
    TrendPoint,
    SimilarProfileResponse,
    RecurrenceResponse,
    HistoryResponse,
    UpdateAssociationRequest,
)
from app.modules.source_intelligence.aggregator import SourceProfileAggregator
from app.modules.source_intelligence.similarity import compare_source_profiles


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SourceIntelligenceService:
    """Provides high-level business capabilities for investigating observed source profiles."""

    def __init__(self, db: Session):
        self.db = db
        self.aggregator = SourceProfileAggregator(db)

    def _to_profile_response(self, p: SourceProfileModel) -> SourceProfileResponse:
        return SourceProfileResponse(
            profile_id=p.profile_id,
            display_label=p.display_label,
            source_ip=p.source_ip,
            ip_family=p.ip_family,
            fingerprint=p.fingerprint,
            first_observed_at=p.first_observed_at,
            last_observed_at=p.last_observed_at,
            total_sessions=p.total_sessions,
            total_events=p.total_events,
            total_alerts=p.total_alerts,
            distinct_categories=p.distinct_categories,
            distinct_honeypots=p.distinct_honeypots,
            protocol_distribution=p.protocol_distribution or {},
            behavioral_summary=p.behavioral_summary or {},
            profile_priority=p.profile_priority,
            profile_status=p.profile_status,
            is_shared_infrastructure=p.is_shared_infrastructure,
            analyst_notes_count=p.analyst_notes_count,
            version=p.version,
            last_aggregated_at=p.last_aggregated_at,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )

    def _to_feature_response(self, f: SourceProfileFeatureModel) -> FeatureMetricsResponse:
        return FeatureMetricsResponse(
            window_type=f.window_type,
            window_start=f.window_start,
            window_end=f.window_end,
            interaction_tempo=f.interaction_tempo,
            burstiness_ratio=f.burstiness_ratio,
            concurrency_level=f.concurrency_level,
            auth_attempt_count=f.auth_attempt_count,
            auth_failure_count=f.auth_failure_count,
            distinct_usernames_count=f.distinct_usernames_count,
            path_traversal_probes=f.path_traversal_probes,
            distinct_paths_probed=f.distinct_paths_probed,
            distinct_honeypots_targeted=f.distinct_honeypots_targeted,
            tactic_distribution=f.tactic_distribution or {},
            technique_distribution=f.technique_distribution or {},
            severity_breakdown=f.severity_breakdown or {},
            calculated_at=f.calculated_at,
        )

    def list_profiles(
        self,
        search: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        sort_by: str = "last_observed_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> SourceProfileListResponse:
        """Lists observed source profiles with search and filtering."""
        query = select(SourceProfileModel)

        if search:
            search_term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    SourceProfileModel.profile_id.ilike(search_term),
                    SourceProfileModel.source_ip.ilike(search_term),
                    SourceProfileModel.display_label.ilike(search_term),
                )
            )

        if priority:
            query = query.where(SourceProfileModel.profile_priority == priority.upper())

        if status:
            query = query.where(SourceProfileModel.profile_status == status.upper())

        # Total count
        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.scalar(count_stmt) or 0

        # Sort order
        sort_col = getattr(SourceProfileModel, sort_by, SourceProfileModel.last_observed_at)
        if sort_order.lower() == "asc":
            query = query.order_by(asc(sort_col))
        else:
            query = query.order_by(desc(sort_col))

        # Pagination
        query = query.offset((page - 1) * page_size).limit(page_size)
        profiles = list(self.db.scalars(query).all())

        items = [self._to_profile_response(p) for p in profiles]
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        return SourceProfileListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_profile(self, profile_id: str) -> SourceProfileModel:
        """Retrieves a single Observed Source Profile by profile_id or raises 404."""
        p = self.db.scalar(
            select(SourceProfileModel).where(SourceProfileModel.profile_id == profile_id)
        )
        if not p:
            raise HTTPException(status_code=404, detail=f"Observed source profile '{profile_id}' not found.")
        return p

    def get_profile_sessions(self, profile_id: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieves correlated activity sessions associated with this source profile."""
        p = self.get_profile(profile_id)
        stmt = (
            select(ActivitySessionModel, SourceProfileSessionModel)
            .join(
                SourceProfileSessionModel,
                ActivitySessionModel.session_id == SourceProfileSessionModel.session_id,
            )
            .where(SourceProfileSessionModel.profile_id == p.profile_id)
            .order_by(desc(ActivitySessionModel.first_observed_at))
            .offset(offset)
            .limit(limit)
        )
        results = self.db.execute(stmt).all()
        sessions_data = []
        for sess, junction in results:
            sessions_data.append({
                "session_id": sess.session_id,
                "decoy_id": sess.decoy_id,
                "protocol": sess.protocol,
                "start_time": sess.first_observed_at.isoformat() if sess.first_observed_at else None,
                "end_time": (sess.ended_at or sess.last_activity_at).isoformat() if (sess.ended_at or sess.last_activity_at) else None,
                "event_count": sess.event_count,
                "session_status": sess.session_status,
                "highest_severity": sess.highest_severity,
                "association_type": junction.association_type,
                "confidence_score": junction.confidence_score,
                "associated_at": junction.associated_at.isoformat() if junction.associated_at else None,
            })
        return sessions_data

    def get_profile_events(self, profile_id: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieves raw or normalized security events observed from this source IP."""
        p = self.get_profile(profile_id)
        stmt = (
            select(SecurityEventModel)
            .where(
                (SecurityEventModel.source_address == p.source_ip)
                | (SecurityEventModel.source_address == p.source_ip.lower())
            )
            .order_by(desc(SecurityEventModel.observed_at))
            .offset(offset)
            .limit(limit)
        )
        events = list(self.db.scalars(stmt).all())
        return [
            {
                "event_id": str(e.event_id),
                "timestamp": e.observed_at.isoformat() if e.observed_at else None,
                "decoy_id": e.decoy_id,
                "event_category": e.event_category,
                "event_type": e.event_type,
                "protocol": e.source_protocol,
                "source_ip": e.source_address,
                "source_port": e.source_port,
                "outcome": e.outcome,
                "event_details": e.sanitized_metadata or {},
            }
            for e in events
        ]

    def get_profile_alerts(self, profile_id: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieves detection alerts generated against this source profile."""
        p = self.get_profile(profile_id)
        stmt = (
            select(AlertModel)
            .where(
                (AlertModel.source_address == p.source_ip)
                | (AlertModel.source_address == p.source_ip.lower())
            )
            .order_by(desc(AlertModel.created_at))
            .offset(offset)
            .limit(limit)
        )
        alerts = list(self.db.scalars(stmt).all())
        return [
            {
                "alert_id": str(a.alert_id),
                "title": a.title,
                "severity": a.severity,
                "confidence_score": a.confidence,
                "status": a.assessment_status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ]

    def get_profile_behavior(self, profile_id: str) -> ProfileBehaviorResponse:
        """Retrieves detailed behavioral metrics, feature baselines, recurrences, and history."""
        p = self.get_profile(profile_id)

        feat_stmt = select(SourceProfileFeatureModel).where(
            SourceProfileFeatureModel.profile_id == p.profile_id
        )
        features = {f.window_type: f for f in self.db.scalars(feat_stmt).all()}

        all_time_f = features.get("ALL_TIME")
        b_24h_f = features.get("24H") or all_time_f

        now_utc = datetime.now(timezone.utc)
        if not all_time_f:
            empty_feature_resp = FeatureMetricsResponse(
                window_type="ALL_TIME",
                interaction_tempo=0.0,
                burstiness_ratio=0.0,
                concurrency_level=1,
                auth_attempt_count=0,
                auth_failure_count=0,
                distinct_usernames_count=0,
                path_traversal_probes=0,
                distinct_paths_probed=0,
                distinct_honeypots_targeted=0,
                calculated_at=now_utc,
            )
            baseline_resp = empty_feature_resp
            all_time_resp = empty_feature_resp
        else:
            baseline_resp = self._to_feature_response(b_24h_f)
            all_time_resp = self._to_feature_response(all_time_f)

        # Recurrences
        rec_stmt = (
            select(SourceProfileRecurrenceModel)
            .where(SourceProfileRecurrenceModel.profile_id == p.profile_id)
            .order_by(desc(SourceProfileRecurrenceModel.reactivation_at))
        )
        recurrences = [
            RecurrenceResponse(
                id=str(r.id),
                profile_id=r.profile_id,
                dormant_interval_seconds=r.dormant_interval_seconds,
                dormant_interval_display=r.dormant_interval_display,
                reactivation_at=r.reactivation_at,
                reactivation_session_id=r.reactivation_session_id,
                pattern_similarity=r.pattern_similarity,
                summary=r.summary,
                created_at=r.created_at,
            )
            for r in self.db.scalars(rec_stmt).all()
        ]

        # History
        hist_stmt = (
            select(SourceProfileHistoryModel)
            .where(SourceProfileHistoryModel.profile_id == p.profile_id)
            .order_by(desc(SourceProfileHistoryModel.created_at))
        )
        history = [
            HistoryResponse(
                id=str(h.id),
                profile_id=h.profile_id,
                action=h.action,
                analyst_id=h.analyst_id,
                previous_value=h.previous_value,
                new_value=h.new_value,
                notes=h.notes,
                created_at=h.created_at,
            )
            for h in self.db.scalars(hist_stmt).all()
        ]

        rationale = (p.behavioral_summary or {}).get(
            "priority_rationale", "Standard behavioral priority baseline"
        )

        return ProfileBehaviorResponse(
            profile_id=p.profile_id,
            display_label=p.display_label,
            source_ip=p.source_ip,
            profile_priority=p.profile_priority,
            priority_rationale=rationale,
            baseline_features=baseline_resp,
            all_time_features=all_time_resp,
            recurrences=recurrences,
            history=history,
        )

    def get_profile_trends(self, profile_id: str) -> ProfileTrendsResponse:
        """Retrieves multi-window trends and activity timeline buckets."""
        p = self.get_profile(profile_id)

        feat_stmt = select(SourceProfileFeatureModel).where(
            SourceProfileFeatureModel.profile_id == p.profile_id
        )
        features = {f.window_type: self._to_feature_response(f) for f in self.db.scalars(feat_stmt).all()}

        sess_stmt = (
            select(ActivitySessionModel)
            .join(
                SourceProfileSessionModel,
                ActivitySessionModel.session_id == SourceProfileSessionModel.session_id,
            )
            .where(SourceProfileSessionModel.profile_id == p.profile_id)
            .order_by(asc(ActivitySessionModel.first_observed_at))
        )
        sessions = list(self.db.scalars(sess_stmt).all())

        timeline_points: list[TrendPoint] = []
        for s in sessions:
            t_str = s.first_observed_at.strftime("%Y-%m-%d %H:%M") if s.first_observed_at else "unknown"
            timeline_points.append(
                TrendPoint(
                    timestamp=t_str,
                    session_count=1,
                    event_count=s.event_count,
                    alert_count=1 if (s.detection_count or 0) > 0 else 0,
                    top_protocol=s.protocol or "UNKNOWN",
                )
            )

        return ProfileTrendsResponse(
            profile_id=p.profile_id,
            activity_timeline=timeline_points,
            windows=features,
        )

    def get_similar_profiles(
        self, profile_id: str, limit: int = 5, min_similarity: float = 30.0
    ) -> list[SimilarProfileResponse]:
        """Finds Observed Source Profiles with similar behavioral distributions."""
        source_p = self.get_profile(profile_id)

        source_feat_m = self.db.scalar(
            select(SourceProfileFeatureModel).where(
                SourceProfileFeatureModel.profile_id == source_p.profile_id,
                SourceProfileFeatureModel.window_type == "ALL_TIME",
            )
        )
        source_feat = {
            "technique_distribution": source_feat_m.technique_distribution if source_feat_m else {},
            "interaction_tempo": source_feat_m.interaction_tempo if source_feat_m else 0.0,
            "auth_failure_count": source_feat_m.auth_failure_count if source_feat_m else 0,
        }

        candidate_stmt = select(SourceProfileModel).where(
            SourceProfileModel.profile_id != source_p.profile_id
        )
        candidates = list(self.db.scalars(candidate_stmt).all())

        similarities: list[SimilarProfileResponse] = []
        for cand in candidates:
            cand_feat_m = self.db.scalar(
                select(SourceProfileFeatureModel).where(
                    SourceProfileFeatureModel.profile_id == cand.profile_id,
                    SourceProfileFeatureModel.window_type == "ALL_TIME",
                )
            )
            cand_feat = {
                "technique_distribution": cand_feat_m.technique_distribution if cand_feat_m else {},
                "interaction_tempo": cand_feat_m.interaction_tempo if cand_feat_m else 0.0,
                "auth_failure_count": cand_feat_m.auth_failure_count if cand_feat_m else 0,
            }

            sim_resp = compare_source_profiles(
                source_p=source_p,
                source_feat=source_feat,
                target_p=cand,
                target_feat=cand_feat,
            )
            if sim_resp.similarity_score >= min_similarity:
                similarities.append(sim_resp)

        similarities.sort(key=lambda s: s.similarity_score, reverse=True)
        return similarities[:limit]

    def add_analyst_note(self, profile_id: str, analyst_id: str, notes: str) -> dict[str, Any]:
        """Records an analyst note and increments the profile's note count."""
        p = self.get_profile(profile_id)
        now_utc = datetime.now(timezone.utc)

        hist = SourceProfileHistoryModel(
            id=uuid.uuid4(),
            profile_id=p.profile_id,
            action="ANALYST_NOTE",
            analyst_id=analyst_id,
            previous_value=None,
            new_value={"notes": notes},
            notes=notes,
            created_at=now_utc,
        )
        self.db.add(hist)

        p.analyst_notes_count += 1
        p.updated_at = now_utc
        self.db.commit()

        return {
            "success": True,
            "profile_id": p.profile_id,
            "analyst_notes_count": p.analyst_notes_count,
            "created_at": now_utc.isoformat(),
        }

    def update_association(
        self, profile_id: str, request: UpdateAssociationRequest
    ) -> SourceProfileResponse:
        """Updates profile association flags (e.g. shared infrastructure), status, or priority with audit trail."""
        p = self.get_profile(profile_id)
        now_utc = datetime.now(timezone.utc)

        prev_val = {
            "is_shared_infrastructure": p.is_shared_infrastructure,
            "profile_status": p.profile_status,
            "profile_priority": p.profile_priority,
        }
        new_val = dict(prev_val)

        if request.is_shared_infrastructure is not None:
            p.is_shared_infrastructure = request.is_shared_infrastructure
            new_val["is_shared_infrastructure"] = request.is_shared_infrastructure

        if request.status is not None:
            clean_status = request.status.upper()
            if clean_status in ("ACTIVE", "DORMANT", "ARCHIVED"):
                p.profile_status = clean_status
                new_val["profile_status"] = clean_status

        if request.priority is not None:
            clean_prio = request.priority.upper()
            if clean_prio in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INSUFFICIENT_DATA"):
                p.profile_priority = clean_prio
                new_val["profile_priority"] = clean_prio

        p.version += 1
        p.updated_at = now_utc

        hist = SourceProfileHistoryModel(
            id=uuid.uuid4(),
            profile_id=p.profile_id,
            action="ASSOCIATION_REVIEW",
            analyst_id=request.analyst_id,
            previous_value=prev_val,
            new_value=new_val,
            notes=request.notes,
            created_at=now_utc,
        )
        self.db.add(hist)
        self.db.commit()

        return self._to_profile_response(p)

    def trigger_aggregation(
        self, profile_id: str | None = None, force_all: bool = False
    ) -> dict[str, Any]:
        """Manually runs profile aggregation on-demand."""
        if profile_id:
            p = self.get_profile(profile_id)
            updated_p = self.aggregator.aggregate_for_source_ip(p.source_ip)
            self.db.commit()
            return {
                "success": True,
                "aggregated_profiles_count": 1 if updated_p else 0,
                "profile_id": profile_id,
            }
        else:
            profiles = self.aggregator.aggregate_all_sources()
            return {
                "success": True,
                "aggregated_profiles_count": len(profiles),
            }
