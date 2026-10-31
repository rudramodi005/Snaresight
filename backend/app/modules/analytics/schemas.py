"""Pydantic schemas for SOC Analytics, Reporting & Executive Overview (Task P30)."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnalyticsFilterQuery(BaseModel):
    """Query parameters for analytics aggregation."""
    time_range: str = Field(default="24h", description="15m, 1h, 24h, 7d, 30d, custom")
    start_time: Optional[datetime] = Field(default=None)
    end_time: Optional[datetime] = Field(default=None)
    sensor_id: Optional[str] = Field(default=None)
    event_category: Optional[str] = Field(default=None)
    detection_category: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    session_id: Optional[str] = Field(default=None)
    investigation_id: Optional[str] = Field(default=None)
    tactic_id: Optional[str] = Field(default=None)


class ComparisonMetric(BaseModel):
    """Metric comparison between current and previous equivalent period."""
    current: int = 0
    previous: int = 0
    absolute_change: int = 0
    percentage_change: float = 0.0


class AnalyticsOverviewResponse(BaseModel):
    """High-level security activity summary cards with previous-period comparison."""
    time_range: str
    start_time: str
    end_time: str
    data_freshness_timestamp: str
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    active_sessions: int
    suspicious_sessions: int
    active_investigations: int
    reporting_sensors: int
    comparison: Dict[str, ComparisonMetric]


class EventTimelineBucket(BaseModel):
    """Single time interval bucket for events."""
    timestamp: str
    total_count: int
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_sensor: Dict[str, int] = Field(default_factory=dict)
    by_protocol: Dict[str, int] = Field(default_factory=dict)


class EventTimelineResponse(BaseModel):
    """Time-series of observed events grouped by time interval."""
    time_range: str
    bucket_interval: str
    total_events: int
    buckets: List[EventTimelineBucket]


class AlertTimelineBucket(BaseModel):
    """Single time interval bucket for alerts."""
    timestamp: str
    total_count: int
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)


class AlertTimelineResponse(BaseModel):
    """Time-series of generated alerts grouped by time interval."""
    time_range: str
    bucket_interval: str
    total_alerts: int
    buckets: List[AlertTimelineBucket]


class EventAlertOverviewResponse(BaseModel):
    """Overview correlating raw observed events with security alerts."""
    total_events: int
    total_alerts: int
    event_to_alert_ratio: float
    events_supporting_alerts: int
    alert_coverage_percentage: float
    explanation_notice: str


class DetectionRulePerformanceItem(BaseModel):
    """Performance and trigger frequency for a single detection rule."""
    rule_id: str
    rule_name: str
    rule_version: str
    category: str
    trigger_count: int
    related_alert_count: int
    last_triggered_at: Optional[str] = None
    default_confidence: int
    is_active: bool


class CategoryBreakdownItem(BaseModel):
    category: str
    alert_count: int
    percentage: float


class DetectionAnalyticsResponse(BaseModel):
    """Detection performance statistics across rules and categories."""
    total_active_rules: int
    rules_with_triggers: int
    rules_without_triggers: int
    category_breakdown: List[CategoryBreakdownItem]
    top_rules: List[DetectionRulePerformanceItem]
    inactive_rules: List[DetectionRulePerformanceItem]
    performance_caveat: str


class SeverityMetricItem(BaseModel):
    severity: str
    count: int
    percentage: float
    color: str


class SeverityAnalyticsResponse(BaseModel):
    """Distribution of alert severities."""
    total_alerts: int
    breakdown: List[SeverityMetricItem]
    definitions_notice: str


class ConfidenceBucketItem(BaseModel):
    range_label: str
    min_score: int
    max_score: int
    count: int
    percentage: float
    description: str


class ConfidenceAnalyticsResponse(BaseModel):
    """Distribution of detection confidence scores, separate from severity."""
    total_assessments: int
    average_confidence: float
    buckets: List[ConfidenceBucketItem]
    interpretation_guidelines: str


class DurationDistributionItem(BaseModel):
    bucket_label: str
    count: int
    percentage: float


class SessionAnalyticsResponse(BaseModel):
    """Session telemetry aggregation, suspicious sessions, and duration breakdown."""
    total_sessions: int
    suspicious_sessions: int
    alert_sessions: int
    average_duration_seconds: float
    avg_events_per_session: float
    max_events_per_session: int
    duration_distribution: List[DurationDistributionItem]
    behavioral_sequences_count: int
    interpretation_limits: str


class SourceProfileItem(BaseModel):
    profile_id: str
    source_ip: str
    threat_category: str
    recurrence_count: int
    session_count: int
    first_seen: str
    last_seen: str
    risk_score: float


class SourceAnalyticsResponse(BaseModel):
    """Source intelligence activity and recurring profile analytics."""
    total_profiles: int
    recurring_profiles: int
    single_session_sources: int
    top_recurring_profiles: List[SourceProfileItem]
    privacy_and_identity_caveat: str


class InvestigationAnalyticsItem(BaseModel):
    cluster_id: str
    cluster_name: str
    status: str
    priority_level: str
    alert_count: int
    session_count: int
    lead_analyst: Optional[str] = None
    created_at: str


class InvestigationAnalyticsResponse(BaseModel):
    """Campaign clustering and investigation activity metrics."""
    total_clusters: int
    active_investigations: int
    awaiting_review: int
    resolved_investigations: int
    associated_alerts_count: int
    associated_sessions_count: int
    top_investigations: List[InvestigationAnalyticsItem]
    campaign_definition_notice: str


class AttackTacticCoverageSummary(BaseModel):
    tactic_id: str
    tactic_name: str
    total_techniques: int
    mapped_techniques: int
    alert_supported_techniques: int
    coverage_percentage: float


class AttackAnalyticsResponse(BaseModel):
    """ATT&CK catalogue coverage and mapping breakdown."""
    catalogue_version: str
    total_catalogue_techniques: int
    mapped_techniques_count: int
    supported_by_alerts_count: int
    unmapped_rules_count: int
    pending_analyst_review_count: int
    overall_coverage_pct: float
    tactics: List[AttackTacticCoverageSummary]
    coverage_caveat: str


class SensorHealthItem(BaseModel):
    sensor_id: str
    sensor_name: str
    honeypot_type: str
    is_active: bool
    status: str  # ONLINE, STALE, INACTIVE
    last_telemetry: Optional[str] = None
    event_count_window: int


class SensorAnalyticsResponse(BaseModel):
    """Operational telemetry health per honeypot sensor."""
    total_sensors: int
    reporting_sensors: int
    stale_sensors: int
    sensors: List[SensorHealthItem]
    operational_notice: str


class PipelineHealthAnalyticsResponse(BaseModel):
    """Pipeline throughput, error rates, and queue/SSE status."""
    total_events_ingested: int
    validation_failures: int
    normalization_failures: int
    duplicate_events: int
    throughput_events_per_sec: float
    sse_connections_active: int
    pipeline_state: str  # HEALTHY, DEGRADED, CRITICAL
    last_telemetry_at: Optional[str] = None
    notes: str


class ExecutiveSummaryResponse(BaseModel):
    """Deterministic, metric-grounded executive security summary."""
    reporting_period: str
    start_time: str
    end_time: str
    data_freshness_timestamp: str
    observed_activity_narrative: str
    alert_trends_narrative: str
    detection_categories_narrative: str
    investigation_developments_narrative: str
    sensor_and_pipeline_narrative: str
    attack_coverage_narrative: str
    operational_limitations: List[str]
    key_indicators: Dict[str, Any]


class ReportGenerationRequest(BaseModel):
    """Request to produce an exportable security report."""
    report_title: str = Field(default="SnareSight Security Operations Report", max_length=255)
    report_type: str = Field(default="EXECUTIVE_SUMMARY")
    time_range: str = Field(default="24h")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    file_format: str = Field(default="PDF", description="PDF or CSV")
    sensor_id: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    analyst_id: str = Field(default="analyst_soc_user")


class ReportMetadataResponse(BaseModel):
    """Summary receipt of a generated report."""
    report_id: str
    report_title: str
    report_type: str
    time_range: str
    generated_by: str
    file_format: str
    file_size_bytes: int
    status: str
    created_at: str
    download_url: str

