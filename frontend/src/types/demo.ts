/**
 * TypeScript contracts for SnareSight Demonstration Lab Subsystem.
 */

export type ScenarioType =
  | 'SCENARIO_A'
  | 'SCENARIO_B'
  | 'SCENARIO_C'
  | 'SCENARIO_D'
  | 'SCENARIO_E'
  | 'SCENARIO_F'
  | 'ALL';

export type DatasetSize = 'SMALL' | 'MEDIUM' | 'LARGE';

export interface ScenarioMeta {
  scenario_id: ScenarioType;
  title: string;
  description: string;
  mitre_techniques: string[];
  expected_rules: string[];
  target_decoy: string;
  estimated_events: Record<string, number>;
}

export interface ScenarioRunRequest {
  scenario_type: ScenarioType;
  size: DatasetSize;
  seed: number;
  target_decoy_id?: string;
  source_ip?: string;
}

export interface ScenarioRunResponse {
  run_id: string;
  scenario_type: string;
  size: string;
  seed: number;
  events_generated: number;
  events_accepted: number;
  events_rejected: number;
  detections_triggered: number;
  alerts_created: number;
  sessions_created: number;
  duration_ms: number;
  status: string;
  summary: string;
  details: {
    unique_sessions?: number;
    alerts?: Array<{
      alert_id: string;
      detection_rule_id: string;
      title: string;
      severity: string;
      confidence: number;
    }>;
    escalated_case_id?: string;
    evidence_hold_id?: string;
    resilience?: Record<string, any>;
  };
}

export interface EvaluationMetric {
  rule_id: string;
  rule_name: string;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export interface EvaluationSummaryResponse {
  total_events_evaluated: number;
  overall_true_positives: number;
  overall_false_positives: number;
  overall_false_negatives: number;
  overall_precision: number;
  overall_recall: number;
  overall_f1_score: number;
  average_processing_latency_ms: number;
  rules_evaluated: EvaluationMetric[];
  evaluation_notes: string[];
}

export interface DemoCleanupRequest {
  dry_run: boolean;
  run_id?: string;
}

export interface DemoCleanupResponse {
  dry_run: boolean;
  synthetic_events_found: number;
  events_protected_by_hold: number;
  events_eligible_for_deletion: number;
  events_deleted: number;
  alerts_deleted: number;
  sessions_deleted: number;
  execution_ms: number;
  message: string;
}

export interface DemoExportResponse {
  export_id: string;
  generated_at: string;
  watermark: string;
  scenario_type: string;
  total_events: number;
  events: Array<Record<string, any>>;
}
