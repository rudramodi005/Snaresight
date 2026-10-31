/**
 * TypeScript types for Platform Security, Health Monitoring, Backup, Recovery, and Resilience.
 */

export type HealthStatus = 'HEALTHY' | 'DEGRADED' | 'CRITICAL' | 'UNKNOWN';
export type InternalAlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type InternalAlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
export type ScenarioStatus = 'READINESS_VERIFIED' | 'ACTION_REQUIRED' | 'ACTIVE_DRILL' | 'DRILL_COMPLETED';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export interface ComponentHealthItem {
  name: string;
  status: HealthStatus;
  latency_ms: number;
  checked_at: string;
  details: Record<string, any>;
}

export interface SystemHealthOverview {
  overall_status: HealthStatus;
  timestamp: string;
  uptime_seconds: number;
  components: ComponentHealthItem[];
  open_internal_alerts_count: number;
  critical_alerts_count: number;
  last_successful_backup?: string | null;
  rpo_compliance_status: 'COMPLIANT' | 'WARNING' | 'BREACHED';
  rto_compliance_status: 'COMPLIANT' | 'WARNING' | 'BREACHED';
}

export interface InternalSecurityEvent {
  id: string;
  event_type: string;
  timestamp: string;
  actor_username?: string;
  actor_role?: string;
  source_component: string;
  outcome: string;
  severity: string;
  correlation_id?: string;
  metadata_payload: Record<string, any>;
}

export interface InternalSecurityAlert {
  id: string;
  alert_id: string;
  rule_id: string;
  rule_version: string;
  title: string;
  description: string;
  severity: InternalAlertSeverity;
  status: InternalAlertStatus;
  first_observed_at: string;
  last_observed_at: string;
  evidence_payload: Record<string, any>;
  recommended_action: string;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  resolved_by?: string | null;
  resolved_at?: string | null;
  resolution_notes?: string | null;
  created_at: string;
}

export interface DatabaseBackup {
  id: string;
  backup_id: string;
  backup_type: 'FULL' | 'PRE_MIGRATION' | 'MANUAL';
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  size_bytes: number;
  checksum_sha256?: string | null;
  storage_location_ref: string;
  started_at: string;
  completed_at?: string | null;
  error_category?: string | null;
  error_details?: string | null;
  initiated_by: string;
  retention_hold: boolean;
  restore_verified: boolean;
  restore_verified_at?: string | null;
}

export interface RestoreTestRecord {
  id: string;
  test_id: string;
  backup_id: string;
  test_environment: string;
  status: 'SUCCESS' | 'FAILED';
  duration_seconds: number;
  schema_compatibility_verified: boolean;
  table_count_verified: number;
  integrity_check_passed: boolean;
  verified_by: string;
  verified_at: string;
  diagnostic_notes?: string | null;
}

export interface DisasterRecoveryConfig {
  id: string;
  config_name: string;
  rpo_target_minutes: number;
  rto_target_minutes: number;
  backup_frequency_hours: number;
  backup_retention_days: number;
  cold_archive_retention_days: number;
  auto_restore_test_frequency_days: number;
  updated_by?: string | null;
  updated_at: string;
  actual_rpo_minutes: number;
  actual_rto_estimate_minutes: number;
  rpo_status: 'COMPLIANT' | 'WARNING' | 'BREACHED';
  rto_status: 'COMPLIANT' | 'WARNING' | 'BREACHED';
}

export interface ChecklistItem {
  item_id: string;
  step_number: number;
  title: string;
  instruction: string;
  completed: boolean;
  verification_criterion: string;
  completed_by?: string | null;
  completed_at?: string | null;
  notes?: string | null;
}

export interface DisasterRecoveryChecklist {
  id: string;
  scenario_id: string;
  scenario_title: string;
  current_status: ScenarioStatus;
  checklist_items: ChecklistItem[];
  last_reviewed_by?: string | null;
  last_reviewed_at?: string | null;
}

export interface InternalIncidentNote {
  id: string;
  incident_id: string;
  author_username: string;
  content: string;
  note_type: 'OBSERVATION' | 'CONTAINMENT' | 'RECOVERY' | 'ROOT_CAUSE';
  created_at: string;
}

export interface InternalIncident {
  id: string;
  incident_id: string;
  title: string;
  description: string;
  severity: InternalAlertSeverity;
  status: IncidentStatus;
  assigned_administrator?: string | null;
  affected_components: string[];
  linked_alert_ids: string[];
  containment_notes?: string | null;
  recovery_actions_taken?: string | null;
  resolution_summary?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  notes: InternalIncidentNote[];
}

export interface AuditVerification {
  verified: boolean;
  total_records: number;
  verified_hashes: number;
  corrupted_records: number;
  details: string;
  timestamp: string;
}

