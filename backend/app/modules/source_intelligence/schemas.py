"""Pydantic schemas for the Source Intelligence Subsystem (Task P23)."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class SimilarFactor(BaseModel):
    """Explains a single contributing dimension to the behavioral similarity score."""

    dimension: str = Field(..., description="Behavioral dimension (e.g. TACTICS, PROTOCOLS, TARGETS)")
    weight: float = Field(..., description="Weight of dimension in aggregate score (0.0 - 1.0)")
    similarity: float = Field(..., description="Calculated similarity for this dimension (0.0 - 1.0)")
    rationale: str = Field(..., description="Human-readable explanation of the comparison")


class SimilarProfileResponse(BaseModel):
    """Represents a behaviorally similar Observed Source Profile."""

    target_profile_id: str
    target_display_label: str
    target_source_ip: str
    similarity_score: float = Field(..., description="Overall similarity percentage (0 - 100)")
    priority: str
    status: str
    contributing_factors: list[SimilarFactor] = Field(default_factory=list)
    common_techniques: list[str] = Field(default_factory=list)
    common_honeypots: list[str] = Field(default_factory=list)


class FeatureMetricsResponse(BaseModel):
    """Behavioral feature baseline calculated for a specific time window."""

    window_type: str = Field(..., description="1H, 24H, 7D, 30D, or ALL_TIME")
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    interaction_tempo: float = Field(..., description="Events per active minute")
    burstiness_ratio: float = Field(..., description="Peak vs average event rate ratio")
    concurrency_level: int = Field(..., description="Max concurrent sessions")
    auth_attempt_count: int
    auth_failure_count: int
    distinct_usernames_count: int
    path_traversal_probes: int
    distinct_paths_probed: int
    distinct_honeypots_targeted: int
    tactic_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    calculated_at: datetime


class RecurrenceResponse(BaseModel):
    """Observed recurrence event of a returning source profile."""

    id: str
    profile_id: str
    dormant_interval_seconds: int
    dormant_interval_display: str
    reactivation_at: datetime
    reactivation_session_id: str
    pattern_similarity: float
    summary: str
    created_at: datetime


class HistoryResponse(BaseModel):
    """Audit log entry for a source profile."""

    id: str
    profile_id: str
    action: str
    analyst_id: Optional[str] = None
    previous_value: Optional[dict[str, Any]] = None
    new_value: Optional[dict[str, Any]] = None
    notes: Optional[str] = None
    created_at: datetime


class SourceProfileResponse(BaseModel):
    """Observed Source Profile response entity."""

    profile_id: str
    display_label: str
    source_ip: str
    ip_family: str
    fingerprint: str
    first_observed_at: datetime
    last_observed_at: datetime
    total_sessions: int
    total_events: int
    total_alerts: int
    distinct_categories: int
    distinct_honeypots: int
    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    behavioral_summary: dict[str, Any] = Field(default_factory=dict)
    profile_priority: str
    profile_status: str
    is_shared_infrastructure: bool
    analyst_notes_count: int
    version: int
    last_aggregated_at: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None


class SourceProfileListResponse(BaseModel):
    """Paginated list of Observed Source Profiles."""

    items: list[SourceProfileResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class TrendPoint(BaseModel):
    """Single time-bucket trend point."""

    timestamp: str
    session_count: int
    event_count: int
    alert_count: int
    top_protocol: str


class ProfileTrendsResponse(BaseModel):
    """Trends and metrics over time for an observed source profile."""

    profile_id: str
    activity_timeline: list[TrendPoint] = Field(default_factory=list)
    windows: dict[str, FeatureMetricsResponse] = Field(default_factory=dict)


class ProfileBehaviorResponse(BaseModel):
    """Detailed behavioral intelligence view for a source profile."""

    profile_id: str
    display_label: str
    source_ip: str
    profile_priority: str
    priority_rationale: str
    baseline_features: FeatureMetricsResponse
    all_time_features: FeatureMetricsResponse
    recurrences: list[RecurrenceResponse] = Field(default_factory=list)
    history: list[HistoryResponse] = Field(default_factory=list)


class AddNoteRequest(BaseModel):
    """Request payload to add an analyst note to a profile."""

    analyst_id: str = Field(..., min_length=1, description="Identifier of the investigating analyst")
    notes: str = Field(..., min_length=1, description="Analyst observation or investigation notes")


class UpdateAssociationRequest(BaseModel):
    """Request payload to update profile association, status, priority, or shared-infrastructure flag."""

    analyst_id: str = Field(..., min_length=1)
    is_shared_infrastructure: Optional[bool] = None
    status: Optional[str] = Field(None, description="ACTIVE, DORMANT, or ARCHIVED")
    priority: Optional[str] = Field(None, description="LOW, MEDIUM, HIGH, CRITICAL, or INSUFFICIENT_DATA")
    notes: Optional[str] = None


class AggregationTriggerRequest(BaseModel):
    """Request payload to manually trigger profile aggregation."""

    profile_id: Optional[str] = None
    force_all: bool = False

