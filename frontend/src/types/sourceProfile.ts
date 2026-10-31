/**
 * TypeScript type definitions for SnareSight Source Intelligence & Profiling (Task P23).
 *
 * POLICY GUARDRAIL: Strictly labelled as "Observed Source Profile" or
 * "Source Context Profile", never as "confirmed attacker identity".
 */

export interface SourceProfile {
  profile_id: string;
  display_label: string;
  source_ip: string;
  ip_family: 'IPv4' | 'IPv6';
  fingerprint: string;
  first_observed_at: string;
  last_observed_at: string;
  total_sessions: number;
  total_events: number;
  total_alerts: number;
  distinct_categories: number;
  distinct_honeypots: number;
  protocol_distribution: Record<string, number>;
  behavioral_summary: {
    honeypots?: string[];
    categories?: string[];
    priority_rationale?: string;
    is_private_ip?: boolean;
    auth_summary?: {
      attempts: number;
      failures: number;
      distinct_usernames: number;
    };
    traversal_summary?: {
      probes: number;
      distinct_paths: number;
    };
  };
  profile_priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT_DATA';
  profile_status: 'ACTIVE' | 'DORMANT' | 'ARCHIVED';
  is_shared_infrastructure: boolean;
  analyst_notes_count: number;
  version: number;
  last_aggregated_at: string;
  created_at: string;
  updated_at?: string | null;
}

export interface PaginatedSourceProfilesResponse {
  items: SourceProfile[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface FeatureMetrics {
  window_type: '1H' | '24H' | '7D' | '30D' | 'ALL_TIME';
  window_start?: string | null;
  window_end?: string | null;
  interaction_tempo: number;
  burstiness_ratio: number;
  concurrency_level: number;
  auth_attempt_count: number;
  auth_failure_count: number;
  distinct_usernames_count: number;
  path_traversal_probes: number;
  distinct_paths_probed: number;
  distinct_honeypots_targeted: number;
  tactic_distribution: Record<string, number>;
  technique_distribution: Record<string, number>;
  severity_breakdown: Record<string, number>;
  calculated_at: string;
}

export interface RecurrenceItem {
  id: string;
  profile_id: string;
  dormant_interval_seconds: number;
  dormant_interval_display: string;
  reactivation_at: string;
  reactivation_session_id: string;
  pattern_similarity: number;
  summary: string;
  created_at: string;
}

export interface HistoryItem {
  id: string;
  profile_id: string;
  action: string;
  analyst_id?: string | null;
  previous_value?: Record<string, any> | null;
  new_value?: Record<string, any> | null;
  notes?: string | null;
  created_at: string;
}

export interface ProfileBehaviorResponse {
  profile_id: string;
  display_label: string;
  source_ip: string;
  profile_priority: string;
  priority_rationale: string;
  baseline_features: FeatureMetrics;
  all_time_features: FeatureMetrics;
  recurrences: RecurrenceItem[];
  history: HistoryItem[];
}

export interface SimilarFactor {
  dimension: string;
  weight: number;
  similarity: number;
  rationale: string;
}

export interface SimilarProfile {
  target_profile_id: string;
  target_display_label: string;
  target_source_ip: string;
  similarity_score: number;
  priority: string;
  status: string;
  contributing_factors: SimilarFactor[];
  common_techniques: string[];
  common_honeypots: string[];
}

export interface TrendPoint {
  timestamp: string;
  session_count: number;
  event_count: number;
  alert_count: number;
  top_protocol: string;
}

export interface ProfileTrendsResponse {
  profile_id: string;
  activity_timeline: TrendPoint[];
  windows: Record<string, FeatureMetrics>;
}

export interface AddNotePayload {
  analyst_id: string;
  notes: string;
}

export interface UpdateAssociationPayload {
  analyst_id: string;
  is_shared_infrastructure?: boolean;
  status?: 'ACTIVE' | 'DORMANT' | 'ARCHIVED';
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INSUFFICIENT_DATA';
  notes?: string;
}

