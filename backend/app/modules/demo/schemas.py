"""Pydantic schemas and contracts for the SnareSight Demonstration Lab Subsystem."""

import enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class ScenarioType(str, enum.Enum):
    """Supported synthetic demonstration scenarios."""
    SCENARIO_A = "SCENARIO_A"  # Repeated Login Failures (AUTH-001)
    SCENARIO_B = "SCENARIO_B"  # Username Enumeration (AUTH-003)
    SCENARIO_C = "SCENARIO_C"  # Suspicious Web Path Requests (WEB-001 & WEB-002)
    SCENARIO_D = "SCENARIO_D"  # Multi-Session Behavioral Association (BEHAV-001)
    SCENARIO_E = "SCENARIO_E"  # Analyst Investigation & Case Response
    SCENARIO_F = "SCENARIO_F"  # Operational Failure & Sandbox Recovery
    ALL = "ALL"                # Multi-Vector Composite Benchmark


class DatasetSize(str, enum.Enum):
    """Size configurations for scenario event sets."""
    SMALL = "SMALL"    # ~25 events
    MEDIUM = "MEDIUM"  # ~100 events
    LARGE = "LARGE"    # ~500 events


class ScenarioMeta(BaseModel):
    """Descriptive metadata for demonstration scenarios."""
    scenario_id: ScenarioType
    title: str
    description: str
    mitre_techniques: List[str]
    expected_rules: List[str]
    target_decoy: str
    estimated_events: dict[str, int]


class ScenarioRunRequest(BaseModel):
    """Request payload to trigger a synthetic demonstration scenario."""
    scenario_type: ScenarioType = Field(default=ScenarioType.SCENARIO_A, description="Scenario identifier")
    size: DatasetSize = Field(default=DatasetSize.SMALL, description="Telemetry batch size")
    seed: int = Field(default=42, ge=1, le=999999, description="Deterministic PRNG seed")
    target_decoy_id: str = Field(default="WEB-001", description="Target honeypot decoy identifier")
    source_ip: Optional[str] = Field(default=None, description="Optional override source IP (RFC 5737 testnet)")


class ScenarioRunResponse(BaseModel):
    """Detailed outcome from executing a demonstration scenario."""
    run_id: str
    scenario_type: str
    size: str
    seed: int
    events_generated: int
    events_accepted: int
    events_rejected: int
    detections_triggered: int
    alerts_created: int
    sessions_created: int
    duration_ms: float
    status: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


class EvaluationMetric(BaseModel):
    """Precision and recall evaluation metrics for a single detection rule."""
    rule_id: str
    rule_name: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float


class EvaluationSummaryResponse(BaseModel):
    """Comprehensive ground truth vs. actual detection quality evaluation."""
    total_events_evaluated: int
    overall_true_positives: int
    overall_false_positives: int
    overall_false_negatives: int
    overall_precision: float
    overall_recall: float
    overall_f1_score: float
    average_processing_latency_ms: float
    rules_evaluated: List[EvaluationMetric]
    evaluation_notes: List[str]


class DemoCleanupRequest(BaseModel):
    """Request to safely clean up synthetic demonstration telemetry."""
    dry_run: bool = Field(default=True, description="When True, counts records without deleting")
    run_id: Optional[str] = Field(default=None, description="Optional specific demonstration run ID")


class DemoCleanupResponse(BaseModel):
    """Results of demonstration data cleanup execution."""
    dry_run: bool
    synthetic_events_found: int
    events_protected_by_hold: int
    events_eligible_for_deletion: int
    events_deleted: int
    alerts_deleted: int
    sessions_deleted: int
    execution_ms: float
    message: str


class DemoExportResponse(BaseModel):
    """Synthetic demonstration report export with safety watermark."""
    export_id: str
    generated_at: str
    watermark: str = "SYNTHETIC DEMONSTRATION DATA - NOT REAL INCIDENT"
    scenario_type: str
    total_events: int
    events: List[dict[str, Any]]

