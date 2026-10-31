/**
 * TypeScript type definitions for SnareSight Session Correlation and Investigation Timelines (Task P21).
 */

export type SessionStatus = 'ACTIVE' | 'IDLE' | 'CLOSED' | 'TIMED_OUT' | 'UNKNOWN';

export type CorrelationMethod =
  | 'EXPLICIT_SESSION_ID'
  | 'EXPLICIT_CONNECTION_ID'
  | 'CONTEXTUAL_FALLBACK'
  | 'STANDALONE';

export type TimelineEntryType =
  | 'SESSION_STARTED'
  | 'CONNECTION_ESTABLISHED'
  | 'HTTP_REQUEST'
  | 'AUTHENTICATION_FAILURE'
  | 'DECOY_AUTHENTICATION_ACCEPTED'
  | 'ENUMERATION_ACTIVITY'
  | 'DIRECTORY_TRAVERSAL'
  | 'SUSPICIOUS_REQUEST'
  | 'DETECTION_GENERATED'
  | 'ATTACK_MAPPING_GENERATED'
  | 'ANALYST_REVIEW_ACTION'
  | 'SESSION_IDLE'
  | 'SESSION_TIMEOUT'
  | 'CONNECTION_CLOSED';

export interface ActivitySessionSummary {
  session_id: string;
  decoy_id: string;
  honeypot_type: string;
  source_address: string;
  source_port?: number | null;
  target_service: string;
  protocol: string;
  correlation_method: CorrelationMethod;
  first_observed_at: string;
  last_activity_at: string;
  ended_at?: string | null;
  session_status: SessionStatus;
  event_count: number;
  detection_count: number;
  highest_severity?: string | null;
  duration_seconds?: number | null;
}

export interface ActivitySession extends ActivitySessionSummary {
  explicit_session_id?: string | null;
  connection_id?: string | null;
  correlation_key: string;
  first_ingested_at: string;
  last_ingested_at: string;
  correlation_policy_version: string;
  metadata_summary: Record<string, any>;
  created_at: string;
  updated_at?: string | null;
}

export interface PaginatedSessions {
  total: number;
  page: number;
  page_size: number;
  items: ActivitySessionSummary[];
}

export interface TimelineEntry {
  entry_id: string;
  session_id: string;
  source_record_id: string;
  timestamp: string;
  ingestion_timestamp?: string | null;
  entry_type: TimelineEntryType;
  title: string;
  description: string;
  component: string;
  category: string;
  severity?: string | null;
  is_detection: boolean;
  is_late_arrival: boolean;
  related_detection_id?: string | null;
  related_technique_id?: string | null;
  related_mapping_id?: string | null;
  mapping_status?: string | null;
  metadata: Record<string, any>;
}

export interface SessionTimeline {
  session_id: string;
  decoy_id: string;
  source_address: string;
  total_entries: number;
  first_observed_at: string;
  last_activity_at: string;
  session_status: SessionStatus;
  entries: TimelineEntry[];
}

export interface SessionEvent {
  event_id: string;
  raw_event_id?: string | null;
  event_type: string;
  event_category: string;
  action: string;
  outcome: string;
  source_address: string;
  target_service: string;
  observed_at: string;
  ingested_at: string;
  association_method: string;
  correlation_confidence: number;
  is_late_arrival: boolean;
  sanitized_metadata: Record<string, any>;
}

export interface SessionStatistics {
  total_sessions: number;
  active_sessions: number;
  idle_sessions: number;
  closed_sessions: number;
  timed_out_sessions: number;
  sessions_with_detections: number;
  total_events_correlated: number;
  average_events_per_session: number;
  by_honeypot: Record<string, number>;
  by_protocol: Record<string, number>;
  by_correlation_method: Record<string, number>;
}
