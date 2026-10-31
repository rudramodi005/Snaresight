/**
 * TypeScript interfaces and types for Honeypot Sensor Management, Health Monitoring, and Operational Reliability.
 */

export type SensorOperationalStatus =
  | 'REGISTERED'
  | 'ACTIVE'
  | 'DEGRADED'
  | 'OFFLINE'
  | 'MAINTENANCE'
  | 'DISABLED'
  | 'RETIRED';

export type SensorHealthStatus =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'CRITICAL'
  | 'UNKNOWN';

export type OperationalAlertStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'RESOLVED';

export type OperationalAlertSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO';

export interface SensorCredential {
  id: string;
  key_id: string;
  sensor_id: string;
  key_prefix: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
  revocation_reason?: string;
  last_used_at?: string;
}

export interface SensorHeartbeat {
  id: string;
  sensor_id: string;
  timestamp: string;
  status: string;
  latency_ms: number;
  metrics_payload: {
    cpu_percent?: number;
    memory_mb?: number;
    events_buffered?: number;
    queue_depth?: number;
    [key: string]: any;
  };
  error_category?: string;
}

export interface SensorConfiguration {
  id: string;
  sensor_id: string;
  version: string;
  config_payload: Record<string, any>;
  is_current: boolean;
  change_reason?: string;
  updated_by?: string;
  created_at: string;
}

export interface OperationalAlert {
  id: string;
  alert_id: string;
  sensor_id: string;
  alert_category: string;
  severity: OperationalAlertSeverity;
  status: OperationalAlertStatus;
  first_observed_at: string;
  last_observed_at: string;
  evidence_payload: Record<string, any>;
  recommended_action: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  resolved_by?: string;
  resolved_at?: string;
  resolution_notes?: string;
  created_at: string;
}

export interface Sensor {
  id: string;
  sensor_id: string;
  name: string;
  sensor_type: string;
  sensor_version: string;
  deployment_environment: string;
  lab_zone: string;
  operational_status: SensorOperationalStatus;
  health_status: SensorHealthStatus;
  heartbeat_interval_seconds: number;
  missed_heartbeat_count: number;
  last_heartbeat_at?: string;
  last_telemetry_at?: string;
  current_config_version: string;
  supported_telemetry_types: string[];
  admin_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SensorDetail extends Sensor {
  credentials: SensorCredential[];
  recent_heartbeats: SensorHeartbeat[];
  current_configuration?: SensorConfiguration;
  open_operational_alerts: OperationalAlert[];
}

export interface SensorListResponse {
  total: number;
  page: number;
  limit: number;
  items: Sensor[];
}

export interface SensorRegistrationResult {
  sensor: Sensor;
  credential: SensorCredential;
  raw_api_key: string;
}

export interface OperationalAlertListResponse {
  total: number;
  page: number;
  limit: number;
  items: OperationalAlert[];
}

export interface SensorOperationsSummary {
  total_registered_sensors: number;
  active_sensors: number;
  degraded_sensors: number;
  offline_sensors: number;
  maintenance_sensors: number;
  disabled_sensors: number;
  retired_sensors: number;
  last_telemetry_receipt?: string;
  total_telemetry_events_received: number;
  ingestion_success_rate: number;
  open_operational_alerts_count: number;
  critical_operational_alerts_count: number;
  sensors_by_type: Record<string, number>;
  sensors_by_environment: Record<string, number>;
}
