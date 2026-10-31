/**
 * TypeScript contracts for SnareSight Behavioral Sequences and Attack-Chain Analysis (Task P22).
 */

export type SequenceLifecycleStatus =
  | 'NEW'
  | 'OBSERVING'
  | 'UNDER_REVIEW'
  | 'REVIEWED'
  | 'CLOSED'
  | 'DISMISSED';

export type SequenceAnalystReviewStatus =
  | 'UNREVIEWED'
  | 'CONFIRMED_PROGRESSION'
  | 'DISMISSED_COINCIDENCE'
  | 'INCONCLUSIVE';

export type SequencePatternType =
  | 'REPEATED_AUTHENTICATION'
  | 'AUTH_THEN_ENUMERATION'
  | 'ENUMERATION_THEN_EXPLOIT'
  | 'MULTI_TECHNIQUE_PROGRESSION'
  | 'RECURRING_HONEYPOT_TARGET'
  | 'CROSS_PROTOCOL_INTERACTION';

export type SequenceMemberType =
  | 'SESSION'
  | 'EVENT'
  | 'DETECTION'
  | 'ATTACK_MAPPING';

export type SequenceRelationshipType =
  | 'OBSERVED_BEFORE'
  | 'SAME_TRUSTED_INTERACTION'
  | 'SHARED_SOURCE_CONTEXT'
  | 'BEHAVIORALLY_SIMILAR'
  | 'RELATED_DETECTION_PATTERN'
  | 'ANALYST_LINKED';

export interface SequenceMember {
  id: string;
  sequence_id: string;
  member_type: SequenceMemberType;
  member_record_id: string;
  sequence_position: number;
  observed_at: string;
  relationship_reason: string;
  correlation_method: string;
  created_at: string;
}

export interface SequenceRelationship {
  id: string;
  sequence_id: string;
  source_member_id: string;
  target_member_id: string;
  relationship_type: SequenceRelationshipType;
  explanation: string;
  confidence_score: number;
  evidence_payload: Record<string, any>;
  created_at: string;
}

export interface SequenceEvidenceItem {
  id: string;
  sequence_id: string;
  evidence_record_type: string;
  evidence_record_id: string;
  field_name: string;
  field_value: string;
  evidence_provenance: Record<string, any>;
  observed_at: string;
  created_at: string;
}

export interface SequenceHistoryRecord {
  id: string;
  sequence_id: string;
  assessed_by: string;
  previous_status: string | null;
  new_status: string;
  assessment_action: string;
  assessment_notes: string | null;
  policy_version: string;
  timestamp: string;
}

export interface BehavioralSequence {
  sequence_id: string;
  title: string;
  sequence_pattern: SequencePatternType;
  description: string;
  lifecycle_status: SequenceLifecycleStatus;
  first_observed_at: string;
  last_observed_at: string;
  session_count: number;
  event_count: number;
  detection_count: number;
  correlation_confidence: number;
  sequence_relevance: number;
  aggregate_severity: string | null;
  analyst_review_status: SequenceAnalystReviewStatus;
  primary_source_address: string | null;
  primary_decoy_id: string | null;
  correlation_policy_version: string;
  metadata_summary: Record<string, any>;
  created_at: string;
  updated_at: string | null;
}

export interface BehavioralSequenceDetail extends BehavioralSequence {
  members: SequenceMember[];
  relationships: SequenceRelationship[];
  evidence_items: SequenceEvidenceItem[];
  history_records: SequenceHistoryRecord[];
}

export interface PaginatedSequencesResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: BehavioralSequence[];
}

export interface SequenceTimelineEntry {
  entry_id: string;
  sequence_id: string;
  member_type: SequenceMemberType;
  member_record_id: string;
  timestamp: string;
  title: string;
  description: string;
  category: string;
  severity: string | null;
  session_id?: string | null;
  decoy_id?: string | null;
  technique_id?: string | null;
  details: Record<string, any>;
}

export interface SequenceTimelineResponse {
  sequence_id: string;
  title: string;
  total_entries: number;
  first_observed_at: string;
  last_observed_at: string;
  entries: SequenceTimelineEntry[];
}

export interface SequenceAssessmentRequest {
  assessment_action: 'CONFIRM' | 'DISMISS' | 'INCONCLUSIVE';
  review_notes: string;
  new_status?: SequenceLifecycleStatus;
}

export interface SequenceStatusUpdateRequest {
  new_status: SequenceLifecycleStatus;
  reason: string;
}

export interface SequenceStatistics {
  total_sequences: number;
  new_sequences: number;
  observing_sequences: number;
  under_review_sequences: number;
  reviewed_sequences: number;
  dismissed_sequences: number;
  closed_sequences: number;
  average_sessions_per_sequence: number;
  by_pattern: Record<string, number>;
  by_severity: Record<string, number>;
  by_review_status: Record<string, number>;
}

