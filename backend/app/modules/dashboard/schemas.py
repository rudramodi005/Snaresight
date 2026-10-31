"""Pydantic schemas for SnareSight SOC Dashboard & Operations Overview (Task P25).

Provides typed response models for metric aggregations, activity trend time series,
severity and detection distributions, recent alerts/investigations, sensor health,
global search results, and in-app notifications.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


TimeRangeLiteral = Literal["1h", "24h", "7d", "30d"]
SeverityLiteral = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SensorStatusLiteral = Literal["ONLINE", "DEGRADED", "OFFLINE", "INACTIVE"]


class MetricValue(BaseModel):
    """Individual dashboard metric card payload with optional trend comparison."""
    label: str
    value: int | float | str
    description: str
    previous_value: Optional[int | float | str] = None
    change_percentage: Optional[float] = None
    trend_direction: Optional[Literal["UP", "DOWN", "FLAT"]] = None
    is_available: bool = True


class OverviewMetrics(BaseModel):
    """Aggregate metric counters displayed in top metric cards."""
    total_events: MetricValue
    total_alerts: MetricValue
    critical_alerts: MetricValue
    high_severity_alerts: MetricValue
    observed_sessions: MetricValue
    active_investigations: MetricValue
    observed_source_profiles: MetricValue
    connected_sensors: MetricValue


class TrendBucket(BaseModel):
    """Individual time bucket for activity trend chart."""
    timestamp: str  # ISO UTC timestamp
    bucket_label: str  # e.g. "14:00", "Oct 31"
    events_count: int = 0
    alerts_count: int = 0


class SeverityCount(BaseModel):
    """Count of alerts for a specific severity level."""
    severity: str
    count: int
    percentage: float


class CategoryCount(BaseModel):
    """Count of alerts for a detection category."""
    category: str
    count: int
    percentage: float


class RecentAlertItem(BaseModel):
    """Summary item for recent security alerts table."""
    alert_id: str
    title: str
    severity: str
    confidence: int
    observed_at: str  # ISO timestamp
    session_id: Optional[str] = None
    source_address: str
    source_profile_id: Optional[str] = None
    decoy_id: str
    target_service: str
    assessment_status: str
    detection_rule_id: str


class RecentInvestigationItem(BaseModel):
    """Summary item for active/recent campaign investigations."""
    id: str
    cluster_code: str
    title: str
    lifecycle_status: str
    priority: str
    confidence_level: str
    confidence_score: float
    last_activity_at: str  # ISO timestamp
    associated_sessions_count: int
    associated_alerts_count: int
    assigned_to: Optional[str] = None


class SensorOverviewItem(BaseModel):
    """Honeypot decoy sensor operational health & telemetry freshness."""
    sensor_id: str
    name: str
    decoy_type: str
    protocol: str
    environment: str
    status: str
    health_status: SensorStatusLiteral
    events_received: int
    last_telemetry_at: Optional[str] = None
    telemetry_latency_seconds: Optional[int] = None
    freshness_description: str


class PipelineHealthSummary(BaseModel):
    """Operational health summary of platform backend components."""
    overall_status: str
    database_ready: bool
    database_latency_ms: float
    ingestion_pipeline_status: str
    last_successful_ingestion: Optional[str] = None
    active_sse_clients: int
    total_messages_published: int
    data_freshness_seconds: Optional[int] = None


class DashboardOverviewResponse(BaseModel):
    """Unified response payload for GET /api/v1/dashboard/overview."""
    time_range: str
    window_start: str
    window_end: str
    generated_at: str
    metrics: OverviewMetrics
    activity_trend: List[TrendBucket]
    severity_distribution: List[SeverityCount]
    top_categories: List[CategoryCount]
    recent_alerts: List[RecentAlertItem]
    recent_investigations: List[RecentInvestigationItem]
    sensors: List[SensorOverviewItem]
    pipeline_health: PipelineHealthSummary


class SearchResultItem(BaseModel):
    """Individual entity search result."""
    category: Literal["ALERTS", "EVENTS", "SESSIONS", "SOURCE_PROFILES", "INVESTIGATIONS"]
    id: str
    title: str
    subtitle: str
    details: Dict[str, Any] = Field(default_factory=dict)
    navigation_url: str


class GlobalSearchResponse(BaseModel):
    """Response payload for GET /api/v1/dashboard/search."""
    query: str
    total_results: int
    results_by_category: Dict[str, List[SearchResultItem]]


class InAppNotification(BaseModel):
    """Lightweight in-app notification item generated from system events."""
    id: str
    title: str
    message: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: Literal["ALERT", "INVESTIGATION", "SENSOR", "PIPELINE"]
    timestamp: str
    target_url: Optional[str] = None
    is_read: bool = False


class NotificationListResponse(BaseModel):
    """Response payload for GET /api/v1/dashboard/notifications."""
    unread_count: int
    total_count: int
    items: List[InAppNotification]

