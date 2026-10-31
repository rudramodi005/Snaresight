/**
 * TypeScript type definitions for SnareSight SOC Analytics, Security Reporting & Executive Overview (Task P30).
 */

export type TimeRangeOption = '15m' | '1h' | '24h' | '7d' | '30d' | 'custom';

export interface ComparisonMetric {
  current: number;
  previous: number;
  absolute_change: number;
  percentage_change: number;
}

export interface AnalyticsOverviewResponse {
  time_range: string;
  start_time: string;
  end_time: string;
  data_freshness_timestamp: string;
  total_events: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  active_sessions: number;
  suspicious_sessions: number;
  active_investigations: number;
  reporting_sensors: number;
  comparison: Record<string, ComparisonMetric>;
}

export interface EventTimelineBucket {
  timestamp: string;
  total_count: number;
  by_category: Record<string, number>;
  by_sensor: Record<string, number>;
  by_protocol: Record<string, number>;
}

export interface EventTimelineResponse {
  time_range: string;
  bucket_interval: string;
  total_events: number;
  buckets: EventTimelineBucket[];
}

export interface AlertTimelineBucket {
  timestamp: string;
  total_count: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_status: Record<string, number>;
}

export interface AlertTimelineResponse {
  time_range: string;
  bucket_interval: string;
  total_alerts: number;
  buckets: AlertTimelineBucket[];
}

export interface EventAlertOverviewResponse {
  total_events: number;
  total_alerts: number;
  event_to_alert_ratio: number;
  events_supporting_alerts: number;
  alert_coverage_percentage: number;
  explanation_notice: string;
}

export interface DetectionRulePerformanceItem {
  rule_id: string;
  rule_name: string;
  rule_version: string;
  category: string;
  trigger_count: number;
  related_alert_count: number;
  last_triggered_at?: string | null;
  default_confidence: number;
  is_active: boolean;
}

export interface CategoryBreakdownItem {
  category: string;
  alert_count: number;
  percentage: number;
}

export interface DetectionAnalyticsResponse {
  total_active_rules: number;
  rules_with_triggers: number;
  rules_without_triggers: number;
  category_breakdown: CategoryBreakdownItem[];
  top_rules: DetectionRulePerformanceItem[];
  inactive_rules: DetectionRulePerformanceItem[];
  performance_caveat: string;
}

export interface SeverityMetricItem {
  severity: string;
  count: number;
  percentage: number;
  color: string;
}

export interface SeverityAnalyticsResponse {
  total_alerts: number;
  breakdown: SeverityMetricItem[];
  definitions_notice: string;
}

export interface ConfidenceBucketItem {
  range_label: string;
  min_score: number;
  max_score: number;
  count: number;
  percentage: number;
  description: string;
}

export interface ConfidenceAnalyticsResponse {
  total_assessments: number;
  average_confidence: number;
  buckets: ConfidenceBucketItem[];
  interpretation_guidelines: string;
}

export interface DurationDistributionItem {
  bucket_label: string;
  count: number;
  percentage: number;
}

export interface SessionAnalyticsResponse {
  total_sessions: number;
  suspicious_sessions: number;
  alert_sessions: number;
  average_duration_seconds: number;
  avg_events_per_session: number;
  max_events_per_session: number;
  duration_distribution: DurationDistributionItem[];
  behavioral_sequences_count: number;
  interpretation_limits: string;
}

export interface SourceProfileItem {
  profile_id: string;
  source_ip: string;
  threat_category: string;
  recurrence_count: number;
  session_count: number;
  first_seen: string;
  last_seen: string;
  risk_score: number;
}

export interface SourceAnalyticsResponse {
  total_profiles: number;
  recurring_profiles: number;
  single_session_sources: number;
  top_recurring_profiles: SourceProfileItem[];
  privacy_and_identity_caveat: string;
}

export interface InvestigationAnalyticsItem {
  cluster_id: string;
  cluster_name: string;
  status: string;
  priority_level: string;
  alert_count: number;
  session_count: number;
  lead_analyst?: string | null;
  created_at: string;
}

export interface InvestigationAnalyticsResponse {
  total_clusters: number;
  active_investigations: number;
  awaiting_review: number;
  resolved_investigations: number;
  associated_alerts_count: number;
  associated_sessions_count: number;
  top_investigations: InvestigationAnalyticsItem[];
  campaign_definition_notice: string;
}

export interface AttackTacticCoverageSummary {
  tactic_id: string;
  tactic_name: string;
  total_techniques: number;
  mapped_techniques: number;
  alert_supported_techniques: number;
  coverage_percentage: number;
}

export interface AttackAnalyticsResponse {
  catalogue_version: string;
  total_catalogue_techniques: number;
  mapped_techniques_count: number;
  supported_by_alerts_count: number;
  unmapped_rules_count: number;
  pending_analyst_review_count: number;
  overall_coverage_pct: number;
  tactics: AttackTacticCoverageSummary[];
  coverage_caveat: string;
}

export interface SensorHealthItem {
  sensor_id: string;
  sensor_name: string;
  honeypot_type: string;
  is_active: boolean;
  status: 'ONLINE' | 'STALE' | 'INACTIVE';
  last_telemetry?: string | null;
  event_count_window: number;
}

export interface SensorAnalyticsResponse {
  total_sensors: number;
  reporting_sensors: number;
  stale_sensors: number;
  sensors: SensorHealthItem[];
  operational_notice: string;
}

export interface PipelineHealthAnalyticsResponse {
  total_events_ingested: number;
  validation_failures: number;
  normalization_failures: number;
  duplicate_events: number;
  throughput_events_per_sec: number;
  sse_connections_active: number;
  pipeline_state: 'HEALTHY' | 'DEGRADED' | 'STALE';
  last_telemetry_at?: string | null;
  notes: string;
}

export interface ExecutiveSummaryResponse {
  reporting_period: string;
  start_time: string;
  end_time: string;
  data_freshness_timestamp: string;
  observed_activity_narrative: string;
  alert_trends_narrative: string;
  detection_categories_narrative: string;
  investigation_developments_narrative: string;
  sensor_and_pipeline_narrative: string;
  attack_coverage_narrative: string;
  operational_limitations: string[];
  key_indicators: Record<string, any>;
}

export interface ReportGenerationRequest {
  report_title?: string;
  report_type?: string;
  time_range: string;
  start_time?: string | null;
  end_time?: string | null;
  file_format: 'PDF' | 'CSV';
  sensor_id?: string | null;
  event_category?: string | null;
  severity?: string | null;
  analyst_id?: string;
}

export interface ReportMetadataResponse {
  report_id: string;
  report_title: string;
  report_type: string;
  time_range: string;
  generated_by: string;
  file_format: string;
  file_size_bytes: number;
  status: string;
  created_at: string;
  download_url: string;
}

