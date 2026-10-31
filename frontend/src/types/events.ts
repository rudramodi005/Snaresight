/**
 * TypeScript type definitions for Security Events Explorer (Task P27).
 */

export type ReviewStatus = 'UNREVIEWED' | 'UNDER_REVIEW' | 'REVIEWED' | 'ESCALATED' | 'DISMISSED';
export type DetectionStatus = 'DETECTED' | 'NORMAL';
export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecurityEventItem {
  event_id: string;
  raw_event_id: string;
  timestamp: string;
  event_category: string;
  event_type: string;
  action: string;
  outcome: string;
  sensor_id: string;
  protocol: string;
  session_id: string;
  source_address: string;
  source_port?: number;
  target_service: string;
  target_port: number;
  detection_status: DetectionStatus;
  has_alerts: boolean;
  alerts_count: number;
  highest_alert_severity?: AlertSeverity;
  review_status: ReviewStatus;
  investigation_cluster_id?: string;
  investigation_code?: string;
}

export interface PaginatedSecurityEventsResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: SecurityEventItem[];
}

export interface SecurityEventSummaryResponse {
  total_events: number;
  detected_events: number;
  clean_events: number;
  distinct_sources: number;
  distinct_sensors: number;
  categories_breakdown: Record<string, number>;
  sensors_breakdown: Record<string, number>;
  outcomes_breakdown: Record<string, number>;
}

export interface EventRelationshipItem {
  entity_type: string;
  entity_id: string;
  relationship_type: string;
  label: string;
  description: string;
  severity?: string;
  confidence?: number;
  navigation_url?: string;
}

export interface EventProcessingStage {
  stage: string;
  timestamp: string;
  status: string;
  details: Record<string, any>;
}

export interface EventAuditLogItem {
  id: string;
  action_type: string;
  analyst_id: string;
  review_status: string;
  notes?: string;
  created_at: string;
  extra_data: Record<string, any>;
}

export interface EventDetailResponse {
  overview: SecurityEventItem;
  normalized_payload: Record<string, any>;
  provenance: Record<string, any>;
  relationships: EventRelationshipItem[];
  processing_history: EventProcessingStage[];
  evidence_provenance: Record<string, any>;
  audit_logs: EventAuditLogItem[];
}

export interface EventTimelineEntry {
  event_id: string;
  timestamp: string;
  event_category: string;
  event_type: string;
  action: string;
  outcome: string;
  sensor_id: string;
  source_address: string;
  is_current_event: boolean;
  relationship_context: string;
  has_alert: boolean;
  alert_severity?: AlertSeverity;
  alert_title?: string;
}

export interface EventTimelineResponse {
  event_id: string;
  session_id?: string;
  context_type: string;
  total_events: number;
  timeline: EventTimelineEntry[];
}

export interface EventComparisonField {
  field_name: string;
  is_match: boolean;
  values_by_event_id: Record<string, any>;
}

export interface EventComparisonResponse {
  compared_event_ids: string[];
  matching_fields_count: number;
  differing_fields_count: number;
  fields: EventComparisonField[];
  caveat_notice: string;
}

export interface EventFilters {
  start_time?: string;
  end_time?: string;
  category?: string;
  event_type?: string;
  sensor_id?: string;
  protocol?: string;
  source_address?: string;
  session_id?: string;
  detection_status?: string;
  outcome?: string;
  severity?: string;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  page?: number;
  page_size?: number;
}
