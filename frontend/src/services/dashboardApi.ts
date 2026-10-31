/**
 * REST API client for SOC Dashboard & Operations Overview.
 */

export interface MetricCardValue {
  label: string;
  value: number | string;
  description: string;
  previous_value?: number | string;
  change_percentage?: number;
  trend_direction?: 'UP' | 'DOWN' | 'FLAT';
  is_available: boolean;
}

export interface DashboardOverview {
  time_range: string;
  window_start: string;
  window_end: string;
  generated_at: string;
  metrics: {
    total_events: MetricCardValue;
    total_alerts: MetricCardValue;
    critical_alerts: MetricCardValue;
    high_severity_alerts: MetricCardValue;
    observed_sessions: MetricCardValue;
    active_investigations: MetricCardValue;
    observed_source_profiles: MetricCardValue;
    connected_sensors: MetricCardValue;
  };
  activity_trend: Array<{
    timestamp: string;
    bucket_label: string;
    events_count: number;
    alerts_count: number;
  }>;
  severity_distribution: Array<{
    severity: string;
    count: number;
    percentage: number;
  }>;
  top_categories: Array<{
    category: string;
    count: number;
    percentage: number;
  }>;
  recent_alerts: Array<{
    alert_id: string;
    title: string;
    severity: string;
    confidence: number;
    observed_at: string;
    source_address: string;
    decoy_id: string;
    target_service: string;
    assessment_status: string;
    detection_rule_id: string;
  }>;
  recent_investigations: Array<{
    id: string;
    cluster_code: string;
    title: string;
    lifecycle_status: string;
    priority: string;
    confidence_level: string;
    confidence_score: number;
    last_activity_at: string;
    associated_sessions_count: number;
    associated_alerts_count: number;
    assigned_to?: string;
  }>;
  sensors: Array<{
    sensor_id: string;
    name: string;
    decoy_type: string;
    protocol: string;
    environment: string;
    status: string;
    health_status: 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'INACTIVE';
    events_received: number;
    last_telemetry_at?: string;
    telemetry_latency_seconds?: number;
    freshness_description: string;
  }>;
  pipeline_health: {
    overall_status: string;
    database_ready: boolean;
    database_latency_ms: number;
    ingestion_pipeline_status: string;
    last_successful_ingestion?: string;
    active_sse_clients: number;
    total_messages_published: number;
    data_freshness_seconds?: number;
  };
}

export async function fetchDashboardOverview(range: string = '24h'): Promise<DashboardOverview> {
  const response = await fetch(`/api/v1/dashboard/overview?range=${range}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch dashboard overview: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchGlobalSearch(query: string) {
  const response = await fetch(`/api/v1/dashboard/search?q=${encodeURIComponent(query)}`);
  if (!response.ok) {
    throw new Error(`Failed to search: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchInAppNotifications() {
  const response = await fetch(`/api/v1/dashboard/notifications`);
  if (!response.ok) {
    throw new Error(`Failed to fetch notifications: ${response.statusText}`);
  }
  return response.json();
}

export const dashboardApi = {
  getOverview: fetchDashboardOverview,
  fetchGlobalSearch,
  fetchInAppNotifications,
};

