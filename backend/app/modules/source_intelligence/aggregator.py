"""Incremental and idempotent source profile aggregation engine."""

from datetime import datetime, timezone, timedelta
from typing import Sequence
from sqlalchemy import select, delete
from sqlalchemy.orm import Session
from app.db.models.event import SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel
from app.db.models.source_profile import (
    SourceProfileModel,
    SourceProfileSessionModel,
    SourceProfileFeatureModel,
    SourceProfileRecurrenceModel,
)
from app.modules.source_intelligence.fingerprint import (
    canonicalize_ip,
    generate_source_fingerprint,
    generate_profile_id,
    format_source_display_label,
)
from app.modules.source_intelligence.feature_extractor import extract_features_from_records
from app.modules.source_intelligence.prioritization import evaluate_profile_priority
from app.modules.source_intelligence.recurrence import detect_profile_recurrences


WINDOW_TIMEDELTAS = {
    "1H": timedelta(hours=1),
    "24H": timedelta(days=1),
    "7D": timedelta(days=7),
    "30D": timedelta(days=30),
}


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_event_timestamp(ev: SecurityEventModel) -> datetime | None:
    return getattr(ev, "observed_at", getattr(ev, "timestamp", None))


def _get_session_start(s: ActivitySessionModel) -> datetime | None:
    return getattr(s, "first_observed_at", getattr(s, "start_time", None))


def _get_session_end(s: ActivitySessionModel) -> datetime | None:
    return (
        getattr(s, "ended_at", None)
        or getattr(s, "last_activity_at", None)
        or getattr(s, "end_time", None)
        or _get_session_start(s)
    )


class SourceProfileAggregator:
    """Engine responsible for building and updating Observed Source Profiles from raw honeypot activity."""

    def __init__(self, db: Session):
        self.db = db

    def aggregate_for_source_ip(self, raw_source_ip: str) -> SourceProfileModel | None:
        """Aggregates all sessions, events, and alerts for a single source IP idempotently."""
        canonical_ip, ip_family, is_private = canonicalize_ip(raw_source_ip)
        profile_id = generate_profile_id(canonical_ip)
        fingerprint = generate_source_fingerprint(canonical_ip)
        display_label = format_source_display_label(canonical_ip)

        # 1. Fetch all sessions for this source IP
        session_stmt = (
            select(ActivitySessionModel)
            .where(
                (ActivitySessionModel.source_address == canonical_ip)
                | (ActivitySessionModel.source_address == raw_source_ip)
            )
            .order_by(ActivitySessionModel.first_observed_at.asc())
        )
        sessions = list(self.db.scalars(session_stmt).all())

        # 2. Fetch all security events for this source IP
        event_stmt = (
            select(SecurityEventModel)
            .where(
                (SecurityEventModel.source_address == canonical_ip)
                | (SecurityEventModel.source_address == raw_source_ip)
            )
            .order_by(SecurityEventModel.observed_at.asc())
        )
        events = list(self.db.scalars(event_stmt).all())

        if not sessions and not events:
            return None

        # 3. Fetch alerts (matching source_address)
        alert_stmt = select(AlertModel).where(
            (AlertModel.source_address == canonical_ip)
            | (AlertModel.source_address == raw_source_ip)
        )
        alerts = list(self.db.scalars(alert_stmt).all())

        now_utc = datetime.now(timezone.utc)

        # Calculate time boundaries
        all_timestamps = []
        for e in events:
            t = _get_event_timestamp(e)
            if t:
                all_timestamps.append(_ensure_utc(t))
        for s in sessions:
            st = _get_session_start(s)
            se = _get_session_end(s)
            if st:
                all_timestamps.append(_ensure_utc(st))
            if se:
                all_timestamps.append(_ensure_utc(se))

        first_observed_at = min(all_timestamps) if all_timestamps else now_utc
        last_observed_at = max(all_timestamps) if all_timestamps else now_utc

        # Distinct counts and distributions
        distinct_categories_set = {e.event_category for e in events if e.event_category}
        distinct_honeypots_set = {
            s.decoy_id for s in sessions if s.decoy_id
        } | {
            getattr(e, "decoy_id", None) or getattr(e, "honeypot_id", None)
            for e in events
            if (getattr(e, "decoy_id", None) or getattr(e, "honeypot_id", None))
        }

        protocol_dist: dict[str, int] = {}
        for s in sessions:
            proto = (s.protocol or "UNKNOWN").upper()
            protocol_dist[proto] = protocol_dist.get(proto, 0) + 1
        for e in events:
            proto = (getattr(e, "source_protocol", None) or getattr(e, "protocol", "") or "").upper()
            if proto:
                protocol_dist[proto] = protocol_dist.get(proto, 0) + 1

        # Calculate features across time windows
        all_time_features = extract_features_from_records(
            events=events,
            sessions=sessions,
            alerts=alerts,
            window_type="ALL_TIME",
            window_start=first_observed_at,
            window_end=last_observed_at,
        )

        window_features_map: dict[str, dict] = {"ALL_TIME": all_time_features}
        for w_name, delta in WINDOW_TIMEDELTAS.items():
            w_start = now_utc - delta
            w_events = [e for e in events if _get_event_timestamp(e) and _ensure_utc(_get_event_timestamp(e)) >= w_start]
            w_sessions = [s for s in sessions if _get_session_start(s) and _ensure_utc(_get_session_start(s)) >= w_start]
            w_alerts = [a for a in alerts if a.created_at and _ensure_utc(a.created_at) >= w_start]
            window_features_map[w_name] = extract_features_from_records(
                events=w_events,
                sessions=w_sessions,
                alerts=w_alerts,
                window_type=w_name,
                window_start=w_start,
                window_end=now_utc,
            )

        # Profile Priority & Status Evaluation
        priority, rationale = evaluate_profile_priority(
            total_events=len(events),
            total_sessions=len(sessions),
            total_alerts=len(alerts),
            distinct_honeypots=len(distinct_honeypots_set),
            features=all_time_features,
        )

        # Determine status: ACTIVE if seen within 7 days, else DORMANT
        is_recent = (now_utc - last_observed_at).total_seconds() < (7 * 86400)
        status = "ACTIVE" if is_recent else "DORMANT"

        behavioral_summary = {
            "honeypots": sorted(list(distinct_honeypots_set)),
            "categories": sorted(list(distinct_categories_set)),
            "priority_rationale": rationale,
            "is_private_ip": is_private,
            "auth_summary": {
                "attempts": all_time_features["auth_attempt_count"],
                "failures": all_time_features["auth_failure_count"],
                "distinct_usernames": all_time_features["distinct_usernames_count"],
            },
            "traversal_summary": {
                "probes": all_time_features["path_traversal_probes"],
                "distinct_paths": all_time_features["distinct_paths_probed"],
            },
        }

        # Check existing profile
        profile = self.db.scalar(
            select(SourceProfileModel).where(SourceProfileModel.profile_id == profile_id)
        )

        if not profile:
            profile = SourceProfileModel(
                profile_id=profile_id,
                display_label=display_label,
                source_ip=canonical_ip,
                ip_family=ip_family,
                fingerprint=fingerprint,
                first_observed_at=first_observed_at,
                last_observed_at=last_observed_at,
                total_sessions=len(sessions),
                total_events=len(events),
                total_alerts=len(alerts),
                distinct_categories=len(distinct_categories_set),
                distinct_honeypots=len(distinct_honeypots_set),
                protocol_distribution=protocol_dist,
                behavioral_summary=behavioral_summary,
                profile_priority=priority,
                profile_status=status,
                is_shared_infrastructure=False,
                analyst_notes_count=0,
                version=1,
                last_aggregated_at=now_utc,
                created_at=now_utc,
            )
            self.db.add(profile)
            self.db.flush()
        else:
            if profile.profile_status != "ARCHIVED":
                profile.profile_status = status
            profile.display_label = display_label
            profile.first_observed_at = first_observed_at
            profile.last_observed_at = last_observed_at
            profile.total_sessions = len(sessions)
            profile.total_events = len(events)
            profile.total_alerts = len(alerts)
            profile.distinct_categories = len(distinct_categories_set)
            profile.distinct_honeypots = len(distinct_honeypots_set)
            profile.protocol_distribution = protocol_dist
            profile.behavioral_summary = behavioral_summary
            profile.profile_priority = priority
            profile.version += 1
            profile.last_aggregated_at = now_utc
            profile.updated_at = now_utc

        # 4. Upsert Window Features
        for w_name, f_data in window_features_map.items():
            existing_feat = self.db.scalar(
                select(SourceProfileFeatureModel).where(
                    SourceProfileFeatureModel.profile_id == profile_id,
                    SourceProfileFeatureModel.window_type == w_name,
                )
            )
            if not existing_feat:
                new_feat = SourceProfileFeatureModel(
                    profile_id=profile_id,
                    window_type=w_name,
                    window_start=f_data["window_start"],
                    window_end=f_data["window_end"],
                    interaction_tempo=f_data["interaction_tempo"],
                    burstiness_ratio=f_data["burstiness_ratio"],
                    concurrency_level=f_data["concurrency_level"],
                    auth_attempt_count=f_data["auth_attempt_count"],
                    auth_failure_count=f_data["auth_failure_count"],
                    distinct_usernames_count=f_data["distinct_usernames_count"],
                    path_traversal_probes=f_data["path_traversal_probes"],
                    distinct_paths_probed=f_data["distinct_paths_probed"],
                    distinct_honeypots_targeted=f_data["distinct_honeypots_targeted"],
                    tactic_distribution=f_data["tactic_distribution"],
                    technique_distribution=f_data["technique_distribution"],
                    severity_breakdown=f_data["severity_breakdown"],
                    calculated_at=now_utc,
                )
                self.db.add(new_feat)
            else:
                existing_feat.window_start = f_data["window_start"]
                existing_feat.window_end = f_data["window_end"]
                existing_feat.interaction_tempo = f_data["interaction_tempo"]
                existing_feat.burstiness_ratio = f_data["burstiness_ratio"]
                existing_feat.concurrency_level = f_data["concurrency_level"]
                existing_feat.auth_attempt_count = f_data["auth_attempt_count"]
                existing_feat.auth_failure_count = f_data["auth_failure_count"]
                existing_feat.distinct_usernames_count = f_data["distinct_usernames_count"]
                existing_feat.path_traversal_probes = f_data["path_traversal_probes"]
                existing_feat.distinct_paths_probed = f_data["distinct_paths_probed"]
                existing_feat.distinct_honeypots_targeted = f_data["distinct_honeypots_targeted"]
                existing_feat.tactic_distribution = f_data["tactic_distribution"]
                existing_feat.technique_distribution = f_data["technique_distribution"]
                existing_feat.severity_breakdown = f_data["severity_breakdown"]
                existing_feat.calculated_at = now_utc

        # 5. Maintain Session Junctions Idempotently
        existing_junctions = {
            j.session_id: j
            for j in self.db.scalars(
                select(SourceProfileSessionModel).where(
                    SourceProfileSessionModel.profile_id == profile_id
                )
            ).all()
        }
        for s in sessions:
            if s.session_id not in existing_junctions:
                j = SourceProfileSessionModel(
                    profile_id=profile_id,
                    session_id=s.session_id,
                    associated_at=now_utc,
                    confidence_score=100,
                    association_type="DIRECT_IP",
                    is_active=True,
                )
                self.db.add(j)

        # 6. Recurrence Detection
        new_recurrences = detect_profile_recurrences(profile_id, sessions)
        existing_rec_sessions = set(
            self.db.scalars(
                select(SourceProfileRecurrenceModel.reactivation_session_id).where(
                    SourceProfileRecurrenceModel.profile_id == profile_id
                )
            ).all()
        )
        for rec in new_recurrences:
            if rec.reactivation_session_id not in existing_rec_sessions:
                self.db.add(rec)

        self.db.flush()
        return profile

    def aggregate_all_sources(self) -> list[SourceProfileModel]:
        """Discovers all distinct source IPs from security events and sessions and aggregates them."""
        event_ips = set(
            self.db.scalars(
                select(SecurityEventModel.source_address).where(SecurityEventModel.source_address.isnot(None))
            ).all()
        )
        session_ips = set(
            self.db.scalars(
                select(ActivitySessionModel.source_address).where(
                    ActivitySessionModel.source_address.isnot(None)
                )
            ).all()
        )

        all_ips = {ip for ip in (event_ips | session_ips) if ip and ip.strip()}
        profiles = []
        for ip in all_ips:
            p = self.aggregate_for_source_ip(ip)
            if p:
                profiles.append(p)

        self.db.commit()
        return profiles
