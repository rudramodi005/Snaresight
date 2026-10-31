"""Pydantic request and response schemas for Defensive Response and Incident Handling Workflow."""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# -------------------------------------------------------------
# Case Management Schemas
# -------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    """Request to create a new incident response case."""
    title: str = Field(..., min_length=3, max_length=128)
    description: str = Field(..., min_length=5)
    priority: str = Field("P3_MEDIUM", description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW, P5_INFO")
    severity: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    assigned_analyst: Optional[str] = Field(None, max_length=64)
    primary_alert_id: Optional[str] = Field(None, max_length=64)
    primary_cluster_id: Optional[str] = Field(None, max_length=64)
    initial_note: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    """Request to update case fields."""
    title: Optional[str] = Field(None, min_length=3, max_length=128)
    description: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    assigned_analyst: Optional[str] = None


class CaseStatusTransitionRequest(BaseModel):
    """Request to change case lifecycle status."""
    new_status: str = Field(..., description="OPEN, UNDER_REVIEW, INVESTIGATING, RESPONSE_RECOMMENDED, etc.")
    reason: str = Field(..., min_length=3)
    resolution_category: Optional[str] = None


class CaseNoteCreateRequest(BaseModel):
    """Request to add a note or comment to a case."""
    note_type: str = Field("ANALYST_NOTE", description="ANALYST_NOTE, INTERNAL_COMMENT, RESOLUTION_NOTE")
    content: str = Field(..., min_length=1)


class CaseLinkEntityRequest(BaseModel):
    """Request to link an alert, event, session, profile, or campaign to a case."""
    related_entity_type: str = Field(..., description="ALERT, EVENT, SESSION, SOURCE_PROFILE, CAMPAIGN, MITRE_TECHNIQUE")
    related_entity_id: str = Field(..., min_length=1, max_length=64)
    relationship_reason: str = Field(..., min_length=3)
    confidence_score: float = Field(1.0, ge=0.0, le=1.0)


class CaseRelationshipResponse(BaseModel):
    id: Any
    case_id: str
    related_entity_type: str
    related_entity_id: str
    relationship_reason: str
    confidence_score: float
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class CaseNoteResponse(BaseModel):
    id: Any
    case_id: str
    author_username: str
    author_role: str
    note_type: str
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


class ResponseCaseResponse(BaseModel):
    id: Any
    case_id: str
    title: str
    description: str
    status: str
    priority: str
    severity: str
    assigned_analyst: Optional[str] = None
    primary_alert_id: Optional[str] = None
    primary_cluster_id: Optional[str] = None
    resolution_summary: Optional[str] = None
    resolution_category: Optional[str] = None
    reopen_reason: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    relationships: Optional[List[CaseRelationshipResponse]] = None
    notes: Optional[List[CaseNoteResponse]] = None

    class Config:
        from_attributes = True


class CaseListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[ResponseCaseResponse]


# -------------------------------------------------------------
# Recommendation Schemas
# -------------------------------------------------------------

class ResponseRecommendationResponse(BaseModel):
    id: Any
    recommendation_id: str
    case_id: str
    rule_id: str
    rule_version: str
    title: str
    explanation: str
    triggering_evidence: Dict[str, Any]
    supporting_event_ids: List[str]
    priority: str
    confidence: str
    required_permission: str
    requires_approval: bool
    potential_impact: str
    reversal_guidance: str
    status: str
    decision_by: Optional[str] = None
    decision_reason: Optional[str] = None
    decision_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class RecommendationDecisionRequest(BaseModel):
    """Accept or reject a recommendation."""
    decision: str = Field(..., description="ACCEPT or REJECT")
    reason: str = Field(..., min_length=3)


# -------------------------------------------------------------
# Playbook Schemas
# -------------------------------------------------------------

class PlaybookStep(BaseModel):
    step_id: str
    step_name: str
    instruction: str
    action_type: Optional[str] = None
    requires_approval: bool = False


class PlaybookDefinitionResponse(BaseModel):
    playbook_id: str
    version: str
    title: str
    description: str
    trigger_conditions: Dict[str, Any]
    required_inputs: List[str]
    workflow_steps: List[Dict[str, Any]]
    required_permission: str
    requires_approval: bool
    is_active: bool

    class Config:
        from_attributes = True


class PlaybookExecuteRequest(BaseModel):
    inputs: Optional[Dict[str, Any]] = None


class PlaybookExecutionResponse(BaseModel):
    id: Any
    execution_id: str
    playbook_id: str
    case_id: str
    initiated_by: str
    status: str
    current_step_index: int
    step_results: List[Dict[str, Any]]
    inputs: Dict[str, Any]
    outcome_summary: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookStepAdvanceRequest(BaseModel):
    step_result: Dict[str, Any]
    outcome_notes: Optional[str] = None


# -------------------------------------------------------------
# Approval Schemas
# -------------------------------------------------------------

class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(..., description="APPROVE or REJECT")
    reason: str = Field(..., min_length=3)


class ResponseApprovalResponse(BaseModel):
    id: Any
    approval_id: str
    case_id: str
    recommendation_id: Optional[str] = None
    action_type: str
    requested_by: str
    status: str
    justification: str
    approved_by: Optional[str] = None
    decision_reason: Optional[str] = None
    decision_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


# -------------------------------------------------------------
# Action Execution Schemas
# -------------------------------------------------------------

class ActionExecuteRequest(BaseModel):
    action_type: str = Field(..., description="ADD_ANALYST_NOTE, ASSIGN_CASE, CHANGE_PRIORITY, MARK_EVIDENCE_PRESERVED, etc.")
    parameters: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None
    is_simulated: bool = False


class ResponseActionResponse(BaseModel):
    id: Any
    action_id: str
    case_id: str
    approval_id: Optional[str] = None
    action_type: str
    executed_by: str
    execution_status: str
    is_simulated: bool
    parameters: Dict[str, Any]
    result_details: Dict[str, Any]
    executed_at: datetime

    class Config:
        from_attributes = True


# -------------------------------------------------------------
# Evidence Preservation Holds Schemas
# -------------------------------------------------------------

class EvidenceHoldCreateRequest(BaseModel):
    evidence_type: str = Field(..., description="EVENT, SESSION, ALERT, PAYLOAD, ATTACK_CHAIN")
    evidence_identifier: str = Field(..., min_length=1, max_length=64)
    hold_reason: str = Field(..., min_length=3)


class EvidenceHoldReleaseRequest(BaseModel):
    release_justification: str = Field(..., min_length=3)


class EvidencePreservationHoldResponse(BaseModel):
    id: Any
    hold_id: str
    case_id: str
    evidence_type: str
    evidence_identifier: str
    integrity_hash_sha256: Optional[str] = None
    retention_hold_status: str
    hold_reason: str
    applied_by: str
    applied_at: datetime
    released_by: Optional[str] = None
    released_at: Optional[datetime] = None
    release_justification: Optional[str] = None

    class Config:
        from_attributes = True


# -------------------------------------------------------------
# Defensive Response Overview / Metrics
# -------------------------------------------------------------

class ResponseDashboardSummary(BaseModel):
    total_active_cases: int
    open_cases: int
    investigating_cases: int
    awaiting_approval_count: int
    critical_cases_count: int
    high_priority_cases_count: int
    recently_resolved_count: int
    active_evidence_holds_count: int
    cases_by_status: Dict[str, int]
    cases_by_priority: Dict[str, int]
