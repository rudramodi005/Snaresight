"""Pydantic schemas for SOC Alert Management and Triage Center (Task P28)."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.modules.alerts.prioritization import PrioritizationResult


class AlertListItem(BaseModel):
    """Summarized alert representation for the SOC alert queue."""
    alert_id: str
    title: str
    summary: str
    severity: str
    confidence: int
    priority_score: float
    priority_level: str
    assessment_status: str
    triage_decision: Optional[str] = None
    evidence_strength: str
    source_address: str
    decoy_id: str
    target_service: str
    detection_rule_id: str
    detection_rule_version: str
    first_observed_at: Optional[str] = None
    last_observed_at: Optional[str] = None
    generated_at: Optional[str] = None
    assigned_analyst: Optional[str] = None
    supporting_events_count: int = 0


class AlertQueueResponse(BaseModel):
    """Paginated response containing matching alerts and query metadata."""
    total: int
    limit: int
    offset: int
    items: List[AlertListItem]


class AlertSummaryResponse(BaseModel):
    """Real-time aggregated alert metrics for the SOC header and summary cards."""
    total_matching: int
    new_alerts: int
    acknowledged_alerts: int
    investigating_alerts: int
    escalated_alerts: int
    resolved_alerts: int
    closed_alerts: int
    unassigned_alerts: int
    requiring_attention: int
    severity_breakdown: Dict[str, int]
    priority_breakdown: Dict[str, int]
    last_refreshed_at: str


class AlertAuditLogItem(BaseModel):
    """Single auditable analyst triage action or lifecycle transition."""
    id: str
    action_type: str
    analyst_id: str
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class AlertNoteItem(BaseModel):
    """Single append-only analyst note."""
    id: str
    author_id: str
    author_role: str
    content: str
    created_at: str


class AlertEvidenceItem(BaseModel):
    """Supporting security event tied to an alert."""
    event_id: str
    evidence_role: str
    evidence_summary: Optional[str] = None
    event_type: str
    category: str
    observed_at: Optional[str] = None
    source_ip: str
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    outcome: str
    raw_event_id: Optional[str] = None
    investigation_url: str


class AlertDetailResponse(BaseModel):
    """Full forensic and operational detail for a single security alert."""
    alert_id: str
    schema_version: str
    title: str
    summary: str
    severity: str
    confidence: int
    assessment_status: str
    priority_score: float
    priority_level: str
    evidence_strength: str
    source_address: str
    observed_source_id: str
    decoy_id: str
    target_service: str
    first_observed_at: Optional[str] = None
    last_observed_at: Optional[str] = None
    generated_at: Optional[str] = None
    updated_at: Optional[str] = None
    detection_explanation: str
    recommendations: Dict[str, Any]
    detection_rule_id: str
    detection_rule_version: str
    assigned_analyst: Optional[str] = None
    triage_decision: Optional[str] = None
    triage_justification: Optional[str] = None
    resolution_category: Optional[str] = None
    resolution_reason: Optional[str] = None
    escalation_reason: Optional[str] = None
    escalation_role: Optional[str] = None
    closure_reason: Optional[str] = None
    prioritization: PrioritizationResult
    supporting_events_count: int
    rule_metadata: Optional[Dict[str, Any]] = None
    recent_notes: List[AlertNoteItem] = Field(default_factory=list)
    recent_history: List[AlertAuditLogItem] = Field(default_factory=list)


class AlertRelationshipsResponse(BaseModel):
    """Correlated cross-subsystem entities associated with the alert."""
    alert_id: str
    session: Optional[Dict[str, Any]] = None
    source_profile: Optional[Dict[str, Any]] = None
    behavioral_sequences: List[Dict[str, Any]] = Field(default_factory=list)
    investigation_clusters: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    disclaimer: str = (
        "Entity relationships represent temporal and contextual correlations within the deception environment. "
        "They do not establish physical attacker identity or cross-campaign attribution."
    )


# --- Request Action Schemas ---

class AcknowledgeRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Identifier of the analyst acknowledging the alert")
    notes: Optional[str] = Field(None, description="Optional acknowledgement commentary")


class AssignRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Target analyst assigned to this alert")
    assigned_by: str = Field(..., min_length=1, description="Analyst or lead initiating assignment")
    notes: Optional[str] = Field(None, description="Assignment guidance or scope")


class InvestigateRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst initiating investigation")
    investigation_cluster_id: Optional[str] = Field(None, description="Optional cluster ID to associate")
    notes: Optional[str] = Field(None, description="Investigation scope notes")


class EscalateRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst requesting escalation")
    reason: str = Field(..., min_length=3, description="Justification for escalation")
    escalation_role: str = Field(..., min_length=2, description="Target role e.g. TIER_2_ANALYST, IR_LEAD")


class ResolveRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst resolving the alert")
    resolution_category: str = Field(..., min_length=2, description="e.g. FALSE_POSITIVE, CONTAINED, BENIGN_SCANNER")
    resolution_reason: str = Field(..., min_length=3, description="Detailed explanation of resolution")


class CloseRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst closing the alert")
    closure_reason: str = Field(..., min_length=3, description="Final disposition and reason for closure")


class AddNoteRequest(BaseModel):
    author_id: str = Field(..., min_length=1, description="Analyst authoring the note")
    author_role: str = Field("SOC_ANALYST", description="Role of the author")
    content: str = Field(..., min_length=1, description="Note text content")


class TriageDecisionRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1, description="Analyst recording triage decision")
    decision: str = Field(
        ...,
        pattern="^(TRUE_POSITIVE|LIKELY_TRUE_POSITIVE|NEEDS_INVESTIGATION|BENIGN_ACTIVITY|FALSE_POSITIVE|INSUFFICIENT_EVIDENCE)$",
        description="Structured triage assessment",
    )
    justification: str = Field(..., min_length=3, description="Evidence-backed explanation for decision")

