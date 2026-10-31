/**
 * TypeScript interfaces and types for Defensive Response and Incident Handling Workflow.
 */

export type CaseStatus =
  | 'OPEN'
  | 'UNDER_REVIEW'
  | 'INVESTIGATING'
  | 'RESPONSE_RECOMMENDED'
  | 'AWAITING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'ACTION_IN_PROGRESS'
  | 'MONITORING'
  | 'RESOLVED'
  | 'CLOSED'
  | 'REOPENED';

export type CasePriority =
  | 'P1_CRITICAL'
  | 'P2_HIGH'
  | 'P3_MEDIUM'
  | 'P4_LOW'
  | 'P5_INFO';

export type CaseSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO';

export interface CaseRelationship {
  id: string;
  case_id: string;
  related_entity_type: string;
  related_entity_id: string;
  relationship_reason: string;
  confidence_score: number;
  created_by: string;
  created_at: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author_username: string;
  author_role: string;
  note_type: string;
  content: string;
  created_at: string;
}

export interface ResponseRecommendation {
  id: string;
  recommendation_id: string;
  case_id: string;
  rule_id: string;
  rule_version: string;
  title: string;
  explanation: string;
  triggering_evidence: Record<string, any>;
  supporting_event_ids: string[];
  priority: string;
  confidence: string;
  required_permission: string;
  requires_approval: boolean;
  potential_impact: string;
  reversal_guidance: string;
  status: 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'SUPERSEDED' | 'EXECUTED';
  decision_by?: string;
  decision_reason?: string;
  decision_at?: string;
  created_at: string;
}

export interface PlaybookWorkflowStep {
  step_index: number;
  step_id: string;
  step_name: string;
  instruction: string;
  action_type?: string;
  requires_approval?: boolean;
}

export interface PlaybookDefinition {
  playbook_id: string;
  version: string;
  title: string;
  description: string;
  trigger_conditions: Record<string, any>;
  required_inputs: string[];
  workflow_steps: PlaybookWorkflowStep[];
  required_permission: string;
  requires_approval: boolean;
  is_active: boolean;
}

export interface PlaybookExecution {
  id: string;
  execution_id: string;
  playbook_id: string;
  case_id: string;
  initiated_by: string;
  status: 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'FAILED';
  current_step_index: number;
  step_results: Record<string, any>[];
  inputs: Record<string, any>;
  outcome_summary?: string;
  started_at: string;
  completed_at?: string;
}

export interface ResponseApproval {
  id: string;
  approval_id: string;
  case_id: string;
  recommendation_id?: string;
  action_type: string;
  requested_by: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED';
  justification: string;
  approved_by?: string;
  decision_reason?: string;
  decision_at?: string;
  created_at: string;
}

export interface ResponseAction {
  id: string;
  action_id: string;
  case_id: string;
  approval_id?: string;
  action_type: string;
  executed_by: string;
  execution_status: string;
  is_simulated: boolean;
  parameters: Record<string, any>;
  result_details: Record<string, any>;
  executed_at: string;
}

export interface EvidencePreservationHold {
  id: string;
  hold_id: string;
  case_id: string;
  evidence_type: string;
  evidence_identifier: string;
  integrity_hash_sha256?: string;
  retention_hold_status: 'ACTIVE' | 'RELEASED';
  hold_reason: string;
  applied_by: string;
  applied_at: string;
  released_by?: string;
  released_at?: string;
  release_justification?: string;
}

export interface ResponseCase {
  id: string;
  case_id: string;
  title: string;
  description: string;
  status: CaseStatus;
  priority: CasePriority;
  severity: CaseSeverity;
  assigned_analyst?: string;
  primary_alert_id?: string;
  primary_cluster_id?: string;
  resolution_summary?: string;
  resolution_category?: string;
  reopen_reason?: string;
  created_by: string;
  created_at: string;
  updated_at?: string;
  closed_at?: string;
  relationships?: CaseRelationship[];
  notes?: CaseNote[];
  recommendations?: ResponseRecommendation[];
  executions?: PlaybookExecution[];
  approvals?: ResponseApproval[];
  actions?: ResponseAction[];
  preservation_holds?: EvidencePreservationHold[];
}

export interface CaseListResponse {
  total: number;
  page: number;
  limit: number;
  items: ResponseCase[];
}

export interface ResponseDashboardSummary {
  total_active_cases: number;
  open_cases: number;
  investigating_cases: number;
  awaiting_approval_count: number;
  critical_cases_count: number;
  high_priority_cases_count: number;
  recently_resolved_count: number;
  active_evidence_holds_count: number;
  cases_by_status: Record<string, number>;
  cases_by_priority: Record<string, number>;
}
