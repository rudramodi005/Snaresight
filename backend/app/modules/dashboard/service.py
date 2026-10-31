"""Dashboard aggregation service for SnareSight SOC Overview (Task P25).

Executes efficient, indexed database aggregations for real-time security operations,
time-window trending, category distributions, sensor telemetry freshness,
system operational health, global multi-entity search, and notifications.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, func, desc, asc, or_
from sqlalchemy.orm import Session

from app.db.models.honeypot import HoneypotModel
from app.db.models.event import SecurityEventModel, RawEventModel
from app.db.models.alert import AlertModel
from app.db.models.rule import DetectionRuleModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.session import SessionModel
from app.db.models.source_profile import SourceProfileModel
from app.db.models.campaign import InvestigationClusterModel
from app.monitoring.service import health_service
from app.streaming.stream_manager import stream_manager
from app.streaming.event_publisher import event_publisher

from app.modules.dashboard.schemas import (
    DashboardOverviewResponse,
    OverviewMetrics,
    MetricValue,
    TrendBucket,
    SeverityCount,
    CategoryCount,
    RecentAlertItem,
    RecentInvestigationItem,
    SensorOverviewItem,
    PipelineHealthSummary,
    GlobalSearchResponse,
    SearchResultItem,
    NotificationListResponse,
    InAppNotification,
)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime instance is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DashboardService:
    """Central analytics and aggregation service for the SnareSight SOC dashboard."""

    def __init__(self, db: Session):
        self.db = db

    def get_overview(self, time_range: str = "24h") -> DashboardOverviewResponse:
        """Assembles unified SOC dashboard overview payload for requested time window."""
        now = datetime.now(timezone.utc)
        window_start, prev_window_start, bucket_delta, bucket_count, time_format = self._resolve_time_window(time_range, now)

        # 1. Metric Cards
        metrics = self._aggregate_metrics(window_start, prev_window_start, now)

        # 2. Activity Trend
        activity_trend = self._aggregate_activity_trend(window_start, now, bucket_delta, bucket_count, time_format)

        # 3. Severity Distribution
        severity_dist = self._aggregate_severity_distribution(window_start)

        # 4. Top Detection Categories
        top_categories = self._aggregate_top_categories(window_start)

        # 5. Recent Alerts
        recent_alerts = self._get_recent_alerts(limit=8)

        # 6. Recent Investigations
        recent_investigations = self._get_recent_investigations(limit=5)

        # 7. Sensor Operational Status
        sensors = self._get_sensor_overview(now)

        # 8. Pipeline Health Summary
        pipeline_health = self._get_pipeline_health_summary(now)

        return DashboardOverviewResponse(
            time_range=time_range,
            window_start=window_start.isoformat(),
            window_end=now.isoformat(),
            generated_at=now.isoformat(),
            metrics=metrics,
            activity_trend=activity_trend,
            severity_distribution=severity_dist,
            top_categories=top_categories,
            recent_alerts=recent_alerts,
            recent_investigations=recent_investigations,
            sensors=sensors,
            pipeline_health=pipeline_health,
        )

    def _resolve_time_window(
        self, time_range: str, now: datetime
    ) -> Tuple[datetime, datetime, timedelta, int, str]:
        """Resolves start times, step sizes, and bucket formats for requested window."""
        range_lower = time_range.lower()
        if range_lower == "1h":
            delta = timedelta(hours=1)
            bucket_delta = timedelta(minutes=5)
            bucket_count = 12
            time_format = "%H:%M"
        elif range_lower == "7d":
            delta = timedelta(days=7)
            bucket_delta = timedelta(hours=6)
            bucket_count = 28
            time_format = "%b %d %H:%M"
        elif range_lower == "30d":
            delta = timedelta(days=30)
            bucket_delta = timedelta(days=1)
            bucket_count = 30
            time_format = "%b %d"
        else:  # default "24h"
            delta = timedelta(hours=24)
            bucket_delta = timedelta(hours=1)
            bucket_count = 24
            time_format = "%H:00"

        window_start = now - delta
        prev_window_start = window_start - delta
        return window_start, prev_window_start, bucket_delta, bucket_count, time_format

    def _aggregate_metrics(
        self, window_start: datetime, prev_window_start: datetime, now: datetime
    ) -> OverviewMetrics:
        """Computes top metric card counters with honest trend comparison."""
        # A. Total Events (Current vs Previous)
        curr_events = self.db.query(func.count(SecurityEventModel.id)).filter(
            SecurityEventModel.observed_at >= window_start,
            SecurityEventModel.observed_at <= now,
        ).scalar() or 0
        prev_events = self.db.query(func.count(SecurityEventModel.id)).filter(
            SecurityEventModel.observed_at >= prev_window_start,
            SecurityEventModel.observed_at < window_start,
        ).scalar() or 0

        # B. Total Alerts
        curr_alerts = self.db.query(func.count(AlertModel.id)).filter(
            AlertModel.generated_at >= window_start,
            AlertModel.generated_at <= now,
        ).scalar() or 0
        prev_alerts = self.db.query(func.count(AlertModel.id)).filter(
            AlertModel.generated_at >= prev_window_start,
            AlertModel.generated_at < window_start,
        ).scalar() or 0

        # C. Critical Alerts
        critical_alerts = self.db.query(func.count(AlertModel.id)).filter(
            AlertModel.severity == "CRITICAL",
            AlertModel.generated_at >= window_start,
        ).scalar() or 0

        # D. High Severity Alerts
        high_alerts = self.db.query(func.count(AlertModel.id)).filter(
            AlertModel.severity == "HIGH",
            AlertModel.generated_at >= window_start,
        ).scalar() or 0

        # E. Observed Sessions
        sessions_count = self.db.query(func.count(ActivitySessionModel.id)).scalar()
        if not sessions_count:
            sessions_count = self.db.query(func.count(SessionModel.id)).scalar() or 0

        # F. Active Investigations
        active_investigations = self.db.query(func.count(InvestigationClusterModel.id)).filter(
            InvestigationClusterModel.lifecycle_status.in_(["ACTIVE", "UNDER_REVIEW"])
        ).scalar() or 0

        # G. Observed Source Profiles
        source_profiles_count = self.db.query(func.count(SourceProfileModel.id)).scalar() or 0

        # H. Connected Sensors
        sensors = self.db.query(HoneypotModel).all()
        connected_sensors = sum(1 for s in sensors if s.status.upper() in ["ACTIVE", "ONLINE"])

        def calc_trend(curr: int, prev: int) -> Tuple[Optional[float], Optional[str]]:
            if prev <= 0:
                return None, None
            pct = round(((curr - prev) / prev) * 100.0, 1)
            direction = "UP" if pct > 0 else ("DOWN" if pct < 0 else "FLAT")
            return pct, direction

        ev_pct, ev_dir = calc_trend(curr_events, prev_events)
        al_pct, al_dir = calc_trend(curr_alerts, prev_alerts)

        return OverviewMetrics(
            total_events=MetricValue(
                label="Total Observed Events",
                value=curr_events,
                description="Normalized telemetry events captured across honeypots",
                previous_value=prev_events if prev_events > 0 else None,
                change_percentage=ev_pct,
                trend_direction=ev_dir,
            ),
            total_alerts=MetricValue(
                label="Total Security Alerts",
                value=curr_alerts,
                description="Detections generated by threat rules in time window",
                previous_value=prev_alerts if prev_alerts > 0 else None,
                change_percentage=al_pct,
                trend_direction=al_dir,
            ),
            critical_alerts=MetricValue(
                label="Critical Alerts",
                value=critical_alerts,
                description="High-confidence critical severity detections requiring immediate triage",
            ),
            high_severity_alerts=MetricValue(
                label="High-Severity Alerts",
                value=high_alerts,
                description="Significant threat alerts requiring analyst review",
            ),
            observed_sessions=MetricValue(
                label="Correlated Sessions",
                value=sessions_count,
                description="Multi-event attacker interaction timelines",
            ),
            active_investigations=MetricValue(
                label="Active Investigations",
                value=active_investigations,
                description="Campaign clusters currently active or under review",
            ),
            observed_source_profiles=MetricValue(
                label="Observed Source Profiles",
                value=source_profiles_count,
                description="Persistent behavioral profiles tracking inbound sources",
            ),
            connected_sensors=MetricValue(
                label="Connected Decoy Sensors",
                value=connected_sensors,
                description="Active honeypots and collector endpoints",
            ),
        )

    def _aggregate_activity_trend(
        self,
        window_start: datetime,
        now: datetime,
        bucket_delta: timedelta,
        bucket_count: int,
        time_format: str,
    ) -> List[TrendBucket]:
        """Constructs chronological activity trend buckets for events and alerts."""
        buckets: List[TrendBucket] = []
        bucket_starts: List[datetime] = []

        # Pre-populate bucket timestamps
        for i in range(bucket_count):
            b_start = window_start + (i * bucket_delta)
            bucket_starts.append(b_start)
            label = b_start.strftime(time_format)
            buckets.append(TrendBucket(
                timestamp=b_start.isoformat(),
                bucket_label=label,
                events_count=0,
                alerts_count=0,
            ))

        # Query events within window
        event_times = self.db.query(SecurityEventModel.observed_at).filter(
            SecurityEventModel.observed_at >= window_start,
            SecurityEventModel.observed_at <= now,
        ).all()

        for (obs_time,) in event_times:
            if obs_time:
                obs_utc = _ensure_utc(obs_time)
                # Find bucket index
                idx = int((obs_utc - window_start) / bucket_delta)
                if 0 <= idx < bucket_count:
                    buckets[idx].events_count += 1

        # Query alerts within window
        alert_times = self.db.query(AlertModel.generated_at).filter(
            AlertModel.generated_at >= window_start,
            AlertModel.generated_at <= now,
        ).all()

        for (gen_time,) in alert_times:
            if gen_time:
                gen_utc = _ensure_utc(gen_time)
                idx = int((gen_utc - window_start) / bucket_delta)
                if 0 <= idx < bucket_count:
                    buckets[idx].alerts_count += 1

        return buckets

    def _aggregate_severity_distribution(self, window_start: datetime) -> List[SeverityCount]:
        """Calculates alert counts and percentages grouped strictly by severity."""
        raw_counts = self.db.query(
            AlertModel.severity, func.count(AlertModel.id)
        ).filter(
            AlertModel.generated_at >= window_start
        ).group_by(AlertModel.severity).all()

        count_dict = {sev.upper(): cnt for sev, cnt in raw_counts if sev}
        total_alerts = sum(count_dict.values())

        standard_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        results: List[SeverityCount] = []
        for sev in standard_severities:
            cnt = count_dict.get(sev, 0)
            pct = round((cnt / total_alerts * 100.0), 1) if total_alerts > 0 else 0.0
            results.append(SeverityCount(
                severity=sev,
                count=cnt,
                percentage=pct,
            ))
        return results

    def _aggregate_top_categories(self, window_start: datetime) -> List[CategoryCount]:
        """Calculates detection categories from detection rules and alerts."""
        joined = self.db.query(
            DetectionRuleModel.category, func.count(AlertModel.id)
        ).join(
            DetectionRuleModel, AlertModel.detection_rule_id == DetectionRuleModel.rule_id
        ).filter(
            AlertModel.generated_at >= window_start
        ).group_by(DetectionRuleModel.category).order_by(desc(func.count(AlertModel.id))).limit(10).all()

        total = sum(cnt for _, cnt in joined)
        if not joined:
            # Fall back to target_service if alerts exist without rules
            fallback = self.db.query(
                AlertModel.target_service, func.count(AlertModel.id)
            ).filter(
                AlertModel.generated_at >= window_start
            ).group_by(AlertModel.target_service).limit(5).all()
            total = sum(cnt for _, cnt in fallback)
            return [
                CategoryCount(
                    category=svc.upper() if svc else "UNCLASSIFIED",
                    count=cnt,
                    percentage=round((cnt / total * 100.0), 1) if total > 0 else 0.0,
                )
                for svc, cnt in fallback
            ]

        return [
            CategoryCount(
                category=cat.replace("_", " ").title() if cat else "General",
                count=cnt,
                percentage=round((cnt / total * 100.0), 1) if total > 0 else 0.0,
            )
            for cat, cnt in joined
        ]

    def _get_recent_alerts(self, limit: int = 8) -> List[RecentAlertItem]:
        """Fetches the latest security alerts for the dashboard triage panel."""
        alerts = self.db.query(AlertModel).order_by(desc(AlertModel.generated_at)).limit(limit).all()
        results: List[RecentAlertItem] = []
        for a in alerts:
            results.append(RecentAlertItem(
                alert_id=str(a.alert_id),
                title=a.title,
                severity=a.severity,
                confidence=int(a.confidence),
                observed_at=a.first_observed_at.isoformat() if a.first_observed_at else a.generated_at.isoformat(),
                session_id=None,  # session_id or correlation link
                source_address=a.source_address,
                source_profile_id=a.observed_source_id,
                decoy_id=a.decoy_id,
                target_service=a.target_service,
                assessment_status=a.assessment_status,
                detection_rule_id=a.detection_rule_id,
            ))
        return results

    def _get_recent_investigations(self, limit: int = 5) -> List[RecentInvestigationItem]:
        """Fetches recent campaign investigation clusters."""
        clusters = self.db.query(InvestigationClusterModel).order_by(
            desc(InvestigationClusterModel.last_observed_at)
        ).limit(limit).all()

        results: List[RecentInvestigationItem] = []
        for c in clusters:
            counts = (c.evidence_summary or {}).get("entity_counts", {})
            results.append(RecentInvestigationItem(
                id=c.cluster_id,
                cluster_code=c.cluster_id,
                title=c.title,
                lifecycle_status=c.lifecycle_status,
                priority=c.priority,
                confidence_level="MODERATE",
                confidence_score=0.75,
                last_activity_at=c.last_observed_at.isoformat() if c.last_observed_at else c.created_at.isoformat(),
                associated_sessions_count=counts.get("sessions", 0),
                associated_alerts_count=counts.get("alerts", 0),
                assigned_to=c.analyst_owner,
            ))
        return results

    def _get_sensor_overview(self, now: datetime) -> List[SensorOverviewItem]:
        """Calculates sensor operational health using a real telemetry freshness policy."""
        sensors = self.db.query(HoneypotModel).all()
        results: List[SensorOverviewItem] = []

        for s in sensors:
            ev_count = self.db.query(func.count(SecurityEventModel.id)).filter(
                SecurityEventModel.decoy_id == s.decoy_id
            ).scalar() or 0

            last_obs = self.db.query(func.max(SecurityEventModel.observed_at)).filter(
                SecurityEventModel.decoy_id == s.decoy_id
            ).scalar()

            # Freshness policy calculation
            latency_sec: Optional[int] = None
            if last_obs is not None:
                last_obs_utc = _ensure_utc(last_obs)
                latency_sec = max(0, int((now - last_obs_utc).total_seconds()))

            if s.status.upper() != "ACTIVE":
                health: str = "INACTIVE"
                desc = "Sensor marked inactive in configuration"
            elif last_obs is None:
                health = "OFFLINE"
                desc = "No telemetry received yet"
            elif latency_sec is not None and latency_sec <= 900:  # <= 15 minutes
                health = "ONLINE"
                desc = f"Active telemetry received {latency_sec // 60}m ago"
            elif latency_sec is not None and latency_sec <= 7200:  # <= 2 hours
                health = "DEGRADED"
                desc = f"Telemetry delayed ({latency_sec // 60}m since last event)"
            else:
                health = "OFFLINE"
                desc = "No telemetry within past 2 hours"

            results.append(SensorOverviewItem(
                sensor_id=s.decoy_id,
                name=s.name,
                decoy_type=s.decoy_type,
                protocol=s.protocol,
                environment=s.environment,
                status=s.status,
                health_status=health,  # type: ignore
                events_received=ev_count,
                last_telemetry_at=last_obs.isoformat() if last_obs else None,
                telemetry_latency_seconds=latency_sec,
                freshness_description=desc,
            ))

        return results

    def _get_pipeline_health_summary(self, now: datetime) -> PipelineHealthSummary:
        """Collects platform pipeline operational health and ingestion stats."""
        readiness = health_service.check_readiness(self.db)
        pipeline = health_service.get_pipeline_health(self.db)

        last_ingestion = health_service.metrics.last_successful_ingestion_timestamp
        freshness_sec: Optional[int] = None
        if last_ingestion:
            try:
                ing_dt = datetime.fromisoformat(last_ingestion)
                ing_dt_utc = _ensure_utc(ing_dt)
                freshness_sec = max(0, int((now - ing_dt_utc).total_seconds()))
            except Exception:
                freshness_sec = None

        return PipelineHealthSummary(
            overall_status=pipeline.get("overall_status", "OPERATIONAL"),
            database_ready=readiness.get("database_ready", False),
            database_latency_ms=readiness.get("database_latency_ms", 0.0),
            ingestion_pipeline_status="OPERATIONAL" if readiness.get("database_ready") else "DEGRADED",
            last_successful_ingestion=last_ingestion,
            active_sse_clients=stream_manager.active_connections_count,
            total_messages_published=event_publisher.total_published,
            data_freshness_seconds=freshness_sec,
        )

    def global_search(self, query: str, limit: int = 5) -> GlobalSearchResponse:
        """Executes bounded, indexed search across alerts, events, sessions, profiles, investigations."""
        q = query.strip()
        results: Dict[str, List[SearchResultItem]] = {
            "ALERTS": [],
            "EVENTS": [],
            "SESSIONS": [],
            "SOURCE_PROFILES": [],
            "INVESTIGATIONS": [],
        }

        if len(q) < 2:
            return GlobalSearchResponse(query=query, total_results=0, results_by_category=results)

        like_term = f"%{q}%"

        # 1. Search Alerts
        alerts = self.db.query(AlertModel).filter(
            or_(
                AlertModel.title.ilike(like_term),
                AlertModel.source_address.ilike(like_term),
                AlertModel.detection_rule_id.ilike(like_term),
            )
        ).limit(limit).all()
        for a in alerts:
            results["ALERTS"].append(SearchResultItem(
                category="ALERTS",
                id=str(a.alert_id),
                title=a.title,
                subtitle=f"{a.severity} | {a.source_address} | Rule: {a.detection_rule_id}",
                details={"severity": a.severity, "confidence": a.confidence, "source_address": a.source_address},
                navigation_url=f"/alerts?alert_id={a.alert_id}",
            ))

        # 2. Search Events
        events = self.db.query(SecurityEventModel).filter(
            or_(
                SecurityEventModel.source_address.ilike(like_term),
                SecurityEventModel.event_type.ilike(like_term),
                SecurityEventModel.decoy_id.ilike(like_term),
            )
        ).limit(limit).all()
        for e in events:
            results["EVENTS"].append(SearchResultItem(
                category="EVENTS",
                id=str(e.event_id),
                title=f"{e.event_type} on {e.decoy_id}",
                subtitle=f"{e.source_address} -> {e.target_service} ({e.action})",
                details={"event_type": e.event_type, "decoy_id": e.decoy_id, "source_address": e.source_address},
                navigation_url=f"/events?event_id={e.event_id}",
            ))

        # 3. Search Sessions
        sessions = self.db.query(ActivitySessionModel).filter(
            or_(
                ActivitySessionModel.session_id.ilike(like_term),
                ActivitySessionModel.source_address.ilike(like_term),
                ActivitySessionModel.decoy_id.ilike(like_term),
            )
        ).limit(limit).all()
        for s in sessions:
            results["SESSIONS"].append(SearchResultItem(
                category="SESSIONS",
                id=s.session_id,
                title=f"Session {s.session_id}",
                subtitle=f"{s.source_address} on {s.decoy_id} ({s.event_count} events)",
                details={"source_address": s.source_address, "decoy_id": s.decoy_id, "status": s.session_status},
                navigation_url=f"/sessions?session_id={s.session_id}",
            ))

        # 4. Search Source Profiles
        profiles = self.db.query(SourceProfileModel).filter(
            or_(
                SourceProfileModel.source_ip.ilike(like_term),
                SourceProfileModel.profile_id.ilike(like_term),
                SourceProfileModel.display_label.ilike(like_term),
            )
        ).limit(limit).all()
        for p in profiles:
            results["SOURCE_PROFILES"].append(SearchResultItem(
                category="SOURCE_PROFILES",
                id=p.profile_id,
                title=p.display_label or p.source_ip,
                subtitle=f"IP: {p.source_ip} | Priority: {p.priority_rating}",
                details={"source_ip": p.source_ip, "priority": p.priority_rating},
                navigation_url=f"/source-intelligence?profile_id={p.profile_id}",
            ))

        # 5. Search Investigations
        investigations = self.db.query(InvestigationClusterModel).filter(
            or_(
                InvestigationClusterModel.title.ilike(like_term),
                InvestigationClusterModel.cluster_id.ilike(like_term),
                InvestigationClusterModel.description.ilike(like_term),
            )
        ).limit(limit).all()
        for c in investigations:
            results["INVESTIGATIONS"].append(SearchResultItem(
                category="INVESTIGATIONS",
                id=c.cluster_id,
                title=f"[{c.cluster_id}] {c.title}",
                subtitle=f"{c.lifecycle_status} | Priority: {c.priority}",
                details={"status": c.lifecycle_status, "priority": c.priority},
                navigation_url=f"/investigations?cluster_id={c.cluster_id}",
            ))

        total_count = sum(len(items) for items in results.values())
        return GlobalSearchResponse(
            query=query,
            total_results=total_count,
            results_by_category=results,
        )

    def get_notifications(self, limit: int = 10) -> NotificationListResponse:
        """Synthesizes real-time in-app notifications from high-priority system events."""
        notifications: List[InAppNotification] = []

        # 1. Critical & High Alerts
        alerts = self.db.query(AlertModel).filter(
            AlertModel.severity.in_(["CRITICAL", "HIGH"])
        ).order_by(desc(AlertModel.generated_at)).limit(5).all()

        for a in alerts:
            notifications.append(InAppNotification(
                id=f"notif-alert-{a.alert_id}",
                title=f"{a.severity} Threat Alert: {a.title}",
                message=f"Observed from {a.source_address} on decoy {a.decoy_id} (Confidence: {a.confidence}%)",
                severity=a.severity,  # type: ignore
                category="ALERT",
                timestamp=a.generated_at.isoformat(),
                target_url=f"/alerts?alert_id={a.alert_id}",
                is_read=False,
            ))

        # 2. Critical Investigations
        clusters = self.db.query(InvestigationClusterModel).filter(
            InvestigationClusterModel.priority.in_(["CRITICAL", "HIGH"]),
            InvestigationClusterModel.lifecycle_status.in_(["ACTIVE", "UNDER_REVIEW"]),
        ).order_by(desc(InvestigationClusterModel.last_observed_at)).limit(3).all()

        for c in clusters:
            notifications.append(InAppNotification(
                id=f"notif-investigation-{c.cluster_id}",
                title=f"Investigation [{c.cluster_id}]: {c.title}",
                message=f"Status: {c.lifecycle_status} | Priority: {c.priority}",
                severity="HIGH" if c.priority == "CRITICAL" else "MEDIUM",
                category="INVESTIGATION",
                timestamp=c.last_observed_at.isoformat() if c.last_observed_at else c.created_at.isoformat(),
                target_url=f"/investigations?cluster_id={c.cluster_id}",
                is_read=False,
            ))

        # Sort notifications by timestamp descending
        notifications.sort(key=lambda n: n.timestamp, reverse=True)
        trimmed = notifications[:limit]

        return NotificationListResponse(
            unread_count=len(trimmed),
            total_count=len(trimmed),
            items=trimmed,
        )

