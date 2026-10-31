/**
 * TypeScript type definitions for Threat Campaign Intelligence & Investigation Grouping (Task P24).
 *
 * POLICY GUARDRAIL: A campaign cluster is an investigative grouping, NOT proof of a real-world
 * attacker, organization, intrusion campaign, or common operator.
 */

export interface InvestigationCluster {
  cluster_id: string;
  title: string;
  description: string;
  lifecycle_status: 'CANDIDATE' | 'UNDER_REVIEW' | 'ACTIVE' | 'MONITORING' | 'CLOSED' | 'MERGED' | 'SPLIT';
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  review_status: 'UNREVIEWED' | 'UNDER_REVIEW' | 'ACCEPTED' | 'DISMISSED';
  analyst_owner?: string | null;
  cluster_methodology_version: string;
  first_observed_at: string;
  last_observed_at: string;
  evidence_summary: Record<string, any>;
  destination_cluster_id?: string | null;
  session_count: number;
  source_profile_count: number;
  alert_count: number;
  sequence_count: number;
  created_at: string;
  updated_at?: string | null;
}

export interface PaginatedClustersResponse {
  items: InvestigationCluster[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ClusterSummary {
  total_clusters: number;
  active_investigations: number;
  under_review_count: number;
  candidate_clusters: number;
  monitoring_count: number;
  closed_count: number;
  critical_priority_count: number;
  high_priority_count: number;
}

export interface ClusterMembership {
  id: string;
  cluster_id: string;
  member_type: 'SESSION' | 'SOURCE_PROFILE' | 'ALERT' | 'SEQUENCE' | 'EVENT';
  member_id: string;
  association_method: string;
  association_confidence: number;
  evidence_references: string[];
  membership_status: 'PROPOSED' | 'ACCEPTED' | 'REJECTED' | 'REMOVED';
  analyst_review_status: 'PENDING' | 'APPROVED' | 'DISMISSED';
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  created_at: string;
}

export interface ClusterEvidence {
  evidence_id: string;
  cluster_id: string;
  evidence_type: string;
  evidence_reference: string;
  evidence_description: string;
  contribution_score: number;
  classification: 'SUPPORTING' | 'CONTRADICTING';
  evidence_timestamp: string;
  methodology_version: string;
  created_at: string;
}

export interface ClusterRelationship {
  relationship_id: string;
  source_cluster_id: string;
  target_cluster_id: string;
  relationship_type: 'BEHAVIORAL_SIMILARITY' | 'SEQUENTIAL_PROGRESSION' | 'SHARED_INFRASTRUCTURE' | 'SHARED_TECHNIQUE_SET' | 'SUB_CAMPAIGN';
  supporting_evidence: Record<string, any>;
  relationship_confidence: number;
  analyst_review_status: 'PROPOSED' | 'ACCEPTED' | 'REJECTED';
  created_at: string;
}

export interface ClusterAuditLog {
  id: string;
  cluster_id: string;
  actor: string;
  action: string;
  target?: string | null;
  previous_state?: Record<string, any> | null;
  new_state?: Record<string, any> | null;
  reason?: string | null;
  timestamp: string;
}

export interface ClusterTimelineItem {
  item_id: string;
  item_type: 'SESSION' | 'ALERT' | 'SEQUENCE' | 'SOURCE_PROFILE_ACTIVITY' | 'MITRE_MAPPING' | 'ANALYST_ACTION' | 'MERGE' | 'SPLIT';
  timestamp: string;
  title: string;
  summary: string;
  reference_id: string;
  source_identifier?: string | null;
  decoy_id?: string | null;
  details: Record<string, any>;
}

export interface ClusterTimelineResponse {
  cluster_id: string;
  items: ClusterTimelineItem[];
  total_items: number;
}

export interface ClusterAttackTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  supporting_rules: string[];
  associated_sessions: string[];
  mapping_confidence: number;
  methodology_version: string;
}

export interface ClusterDetail {
  cluster: InvestigationCluster;
  members: ClusterMembership[];
  evidence: ClusterEvidence[];
  relationships: ClusterRelationship[];
  attack_techniques: ClusterAttackTechnique[];
  audit_logs: ClusterAuditLog[];
}

export interface AddNotePayload {
  analyst_id: string;
  notes: string;
}

export interface LifecycleTransitionPayload {
  analyst_id: string;
  target_status: 'CANDIDATE' | 'UNDER_REVIEW' | 'ACTIVE' | 'MONITORING' | 'CLOSED' | 'MERGED' | 'SPLIT';
  reason: string;
}

export interface MemberDecisionPayload {
  analyst_id: string;
  decision: 'ACCEPT' | 'REJECT';
  reason?: string;
}

export interface MergePayload {
  analyst_id: string;
  source_cluster_id: string;
  reason: string;
}

export interface SplitPayload {
  analyst_id: string;
  member_ids: string[];
  new_cluster_title: string;
  new_cluster_description: string;
  reason: string;
}

export interface ClosePayload {
  analyst_id: string;
  closure_reason: string;
  resolution_status: 'RESOLVED' | 'FALSE_POSITIVE' | 'BENIGN_ACTIVITY';
}

