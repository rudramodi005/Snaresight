/**
 * TypeScript interfaces and type definitions for SOC Alert Management & Triage Center (Task P28).
 */

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AlertStatus =
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'ESCALATED'
  | 'RESOLVED'
  | 'CLOSED';

export type PriorityLevel = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';

export type TriageDecisionType =
  | 'TRUE_POSITIVE'
  | 'LIKELY_TRUE_POSITIVE'
  | 'NEEDS_INVESTIGATION'
  | 'BENIGN_ACTIVITY'
  | 'FALSE_POSITIVE'
  | 'INSUFFICIENT_EVIDENCE';

export interface PrioritizationResult {
  priority_score: number;
  priority_level: PriorityLevel;
  formula_version: string;
  severity_component: number;
  confidence_component: number;
  evidence_component: number;
  context_component: number;
  recency_component: number;
  rationale: string;
  non_attribution_notice: string;
}

export interface AlertListItem {
  alert_id: string;
  title: string;
  summary: string;
  severity: AlertSeverity;
  confidence: number;
  priority_score: number;
  priority_level: PriorityLevel;
  assessment_status: AlertStatus;
  triage_decision?: TriageDecisionType;
  evidence_strength: string;
  source_address: string;
  decoy_id: string;
  target_service: string;
  detection_rule_id: string;
  detection_rule_version: string;
  first_observed_at?: string;
  last_observed_at?: string;
  generated_at?: string;
  assigned_analyst?: string;
  supporting_events_count: number;
}

export interface AlertQueueResponse {
  total: number;
  limit: number;
  offset: number;
  items: AlertListItem[];
}

export interface AlertSummaryResponse {
  total_matching: number;
  new_alerts: number;
  acknowledged_alerts: number;
  investigating_alerts: number;
  escalated_alerts: number;
  resolved_alerts: number;
  closed_alerts: number;
  unassigned_alerts: number;
  requiring_attention: number;
  severity_breakdown: Record<AlertSeverity, number>;
  priority_breakdown: Record<PriorityLevel, number>;
  last_refreshed_at: string;
}

export interface AlertEvidenceItem {
  event_id: string;
  evidence_role: string;
  evidence_summary?: string;
  event_type: string;
  category: string;
  observed_at?: string;
  source_ip: string;
  destination_port?: number;
  protocol?: string;
  outcome: string;
  raw_event_id?: string;
  investigation_url: string;
}

export interface AlertAuditLogItem {
  id: string;
  action_type: string;
  analyst_id: string;
  previous_status?: string;
  new_status?: string;
  reason?: string;
  details: Record<string, any>;
  created_at: string;
}

export interface AlertNoteItem {
  id: string;
  author_id: string;
  author_role: string;
  content: string;
  created_at: string;
}

export interface AlertRelationshipsResponse {
  alert_id: string;
  session?: {
    session_id: string;
    status: string;
    event_count: number;
    first_seen_at?: string;
    last_seen_at?: string;
    navigation_url: string;
  };
  source_profile?: {
    profile_id: string;
    source_address: string;
    profile_priority: string;
    total_sessions: number;
    total_events: number;
    navigation_url: string;
  };
  behavioral_sequences: Array<{
    sequence_id: string;
    title: string;
    lifecycle_status: string;
    step_count: number;
    navigation_url: string;
  }>;
  investigation_clusters: Array<{
    cluster_id: string;
    title: string;
    lifecycle_status: string;
    priority: string;
    navigation_url: string;
  }>;
  mitre_techniques: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    confidence: number;
    navigation_url: string;
  }>;
  disclaimer: string;
}

export interface AlertDetailResponse {
  alert_id: string;
  schema_version: string;
  title: string;
  summary: string;
  severity: AlertSeverity;
  confidence: number;
  assessment_status: AlertStatus;
  priority_score: number;
  priority_level: PriorityLevel;
  evidence_strength: string;
  source_address: string;
  observed_source_id: string;
  decoy_id: string;
  target_service: string;
  first_observed_at?: string;
  last_observed_at?: string;
  generated_at?: string;
  updated_at?: string;
  detection_explanation: string;
  recommendations: Record<string, any>;
  detection_rule_id: string;
  detection_rule_version: string;
  assigned_analyst?: string;
  triage_decision?: TriageDecisionType;
  triage_justification?: string;
  resolution_category?: string;
  resolution_reason?: string;
  escalation_reason?: string;
  escalation_role?: string;
  closure_reason?: string;
  prioritization: PrioritizationResult;
  supporting_events_count: number;
  rule_metadata?: Record<string, any>;
  recent_notes: AlertNoteItem[];
  recent_history: AlertAuditLogItem[];
}

export interface AlertFilterState {
  severity?: AlertSeverity;
  status?: AlertStatus;
  category?: string;
  assignedAnalyst?: string;
  unassignedOnly: boolean;
  search?: string;
  dateStart?: string;
  dateEnd?: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
  page: number;
  limit: number;
}

