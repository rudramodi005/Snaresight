/**
 * TypeScript type definitions for SnareSight MITRE ATT&CK integration.
 */

export interface ExternalReference {
  source_name: string;
  external_id?: string | null;
  url?: string | null;
  description?: string | null;
}

export interface Tactic {
  stix_id: string;
  tactic_id: string;
  tactic_name: string;
  short_name: string;
  description?: string | null;
  dataset_version: string;
  is_deprecated: boolean;
  is_revoked: boolean;
  external_references: ExternalReference[];
}

export interface Subtechnique {
  stix_id: string;
  subtechnique_id: string;
  subtechnique_name: string;
  parent_technique_id: string;
  parent_stix_id?: string | null;
  description?: string | null;
  dataset_version: string;
  platforms: string[];
  is_deprecated: boolean;
  is_revoked: boolean;
  external_references: ExternalReference[];
}

export interface Technique {
  stix_id?: string | null;
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic_name: string;
  framework_version: string;
  description?: string | null;
  is_subtechnique: boolean;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  is_deprecated: boolean;
  is_revoked: boolean;
  external_references: ExternalReference[];
  subtechniques: Subtechnique[];
}

export interface CatalogueStatus {
  catalogue_available: boolean;
  active_version?: string | null;
  framework_domain: string;
  last_import_at?: string | null;
  health_status: 'HEALTHY' | 'EMPTY' | 'DEGRADED';
  total_tactics: number;
  total_techniques: number;
  total_subtechniques: number;
  total_relationships: number;
}

export interface DatasetVersion {
  domain: string;
  version: string;
  stix_version: string;
  source_repo: string;
  source_filename: string;
  retrieval_date: string;
  release_date?: string | null;
  sha256_checksum: string;
  is_active: boolean;
  status: string;
  object_count: number;
  created_at: string;
}

export interface PaginatedTechniques {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: Technique[];
}

export interface DryRunPreview {
  dataset_domain: string;
  dataset_version: string;
  sha256_checksum: string;
  total_objects: number;
  tactics_discovered: number;
  techniques_discovered: number;
  subtechniques_discovered: number;
  relationships_discovered: number;
  unsupported_objects: number;
  objects_to_add: number;
  objects_to_update: number;
  objects_to_deprecate_or_revoke: number;
  validation_warnings: string[];
  validation_errors: string[];
  is_valid: boolean;
}

export interface ImportExecutionReceipt {
  import_run_id: string;
  status: string;
  dataset_version: string;
  sha256_checksum: string;
  total_parsed: number;
  total_accepted: number;
  total_rejected: number;
  total_added: number;
  total_updated: number;
  total_unchanged: number;
  total_deprecated: number;
  total_revoked: number;
  execution_duration_ms: number;
  completed_at: string;
}

// ============================================================================
// P20 Evidence-Based Detection Mapping Types
// ============================================================================

export type MappingCategory =
  | 'DIRECTLY_SUPPORTED'
  | 'PARTIALLY_SUPPORTED'
  | 'REQUIRES_ANALYST_REVIEW'
  | 'NOT_MAPPED';

export type MappingConfidenceLevel = 'LOW' | 'MODERATE' | 'HIGH';

export type ReviewStatus = 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'NEEDS_MORE_EVIDENCE';

export type ReviewAction = 'ACCEPT' | 'REJECT' | 'REQUEST_MORE_EVIDENCE';

export interface MappingEvidence {
  id: string;
  mapping_id: string;
  event_id?: string | null;
  evidence_type: string;
  evidence_description: string;
  evidence_fields: Record<string, any>;
  relevance_score: number;
  evidence_timestamp: string;
  provenance?: Record<string, any> | null;
  created_at: string;
}

export interface DetectionMapping {
  mapping_id: string;
  detection_result_id: string;
  alert_id?: string | null;
  rule_id: string;
  rule_version: string;
  technique_id: string;
  technique_name?: string | null;
  tactic_id?: string | null;
  tactic_name?: string | null;
  subtechnique_id?: string | null;
  subtechnique_name?: string | null;
  dataset_version: string;
  mapping_definition_id: string;
  mapping_definition_version: string;
  mapping_category: MappingCategory;
  mapping_confidence: number;
  mapping_confidence_level: MappingConfidenceLevel;
  confidence_explanation: string;
  mapping_rationale: string;
  review_status: ReviewStatus;
  review_comment?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  assessed_at: string;
  created_at: string;
  updated_at?: string | null;
  evidence: MappingEvidence[];
}

export interface PaginatedMappings {
  total: number;
  page: number;
  page_size: number;
  items: DetectionMapping[];
}

export interface MappingReviewRequest {
  action: ReviewAction;
  comment: string;
}

export interface MappingReviewResponse {
  mapping_id: string;
  action: ReviewAction;
  previous_status: ReviewStatus;
  new_status: ReviewStatus;
  reviewed_by: string;
  reviewed_at: string;
  comment: string;
}

export interface MappingStatistics {
  total_mappings: number;
  directly_supported: number;
  partially_supported: number;
  requires_analyst_review: number;
  not_mapped_count: number;
  pending_reviews: number;
  accepted_mappings: number;
  rejected_mappings: number;
  needs_more_evidence_mappings: number;
  by_confidence_level: Record<string, number>;
  by_tactic: Record<string, number>;
  by_technique: Record<string, number>;
}



// ============================================================================
// P29 MITRE ATT&CK Threat Intelligence and Mapping Dashboard Types
// ============================================================================

export interface AttackCatalogueMetadata {
  domain: string;
  version: string;
  stix_version: string;
  source_repo: string;
  source_filename: string;
  retrieval_date?: string | null;
  release_date?: string | null;
  sha256_checksum: string;
  is_active: boolean;
  status: string;
  object_count: number;
  mapping_registry_version: string;
  last_updated_at?: string | null;
}

export interface AttackSummaryResponse {
  catalogue_version?: string;
  mapping_registry_version?: string;
  last_refreshed_at: string;
  total_catalogue_techniques: number;
  total_catalogue_subtechniques: number;
  total_catalogue_tactics: number;
  // Backend schema properties:
  techniques_mapped_to_detections?: number;
  techniques_with_alert_evidence?: number;
  techniques_pending_review?: number;
  detection_rules_mapped?: number;
  detection_rules_unmapped?: number;
  catalogue_metadata?: AttackCatalogueMetadata;
  // Frontend compatibility aliases:
  mapped_techniques_count?: number;
  supported_by_alerts_count?: number;
  pending_analyst_review_count?: number;
  active_detection_rules_mapped?: number;
  unmapped_detection_rules_count?: number;
  total_active_detection_rules?: number;
  coverage_percentage?: number;
}

export interface AttackTacticOverviewItem {
  tactic_id: string;
  tactic_name: string;
  short_name: string;
  display_order?: number;
  description?: string | null;
  total_techniques?: number;
  mapped_techniques_count?: number;
  supporting_rules_count?: number;
  active_alerts_count?: number;
  related_alerts_count?: number;
  investigations_referencing_count?: number;
  coverage_percentage?: number;
}

export type AttackVisualState = 'UNMAPPED' | 'RULE_MAPPED' | 'ALERT_EVIDENCE' | 'REVIEW_REQUIRED';

export interface AttackMatrixCell {
  technique_id: string;
  technique_name: string;
  is_subtechnique: boolean;
  parent_technique_id?: string | null;
  subtechnique_count: number;
  visual_state: AttackVisualState;
  mapped_rules_count: number;
  alert_evidence_count: number;
  pending_reviews_count: number;
  confidence_score?: number | null;
}

export interface AttackMatrixColumn {
  tactic_id: string;
  tactic_name: string;
  short_name: string;
  display_order: number;
  total_techniques: number;
  mapped_techniques_count: number;
  techniques: AttackMatrixCell[];
}

export interface AttackMatrixResponse {
  catalogue_version: string;
  matrix_generated_at: string;
  total_tactics: number;
  columns: AttackMatrixColumn[];
}

export interface AttackTechniqueExplorerItem {
  technique_id: string;
  technique_name: string;
  is_subtechnique: boolean;
  parent_technique_id?: string | null;
  primary_tactic_id: string;
  primary_tactic_name: string;
  tactics: string[];
  platforms: string[];
  visual_state: AttackVisualState;
  mapped_rules_count: number;
  supporting_alerts_count: number;
  pending_reviews_count: number;
  mapping_confidence?: number | null;
}

export interface AttackTechniqueExplorerResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: AttackTechniqueExplorerItem[];
}

export interface AttackTechniqueMappingItem {
  mapping_definition_id: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  mapping_category: string;
  default_confidence: number;
  mapping_rationale: string;
  is_active: boolean;
  documentation_reference?: string | null;
}

export interface AttackTechniqueEvidenceItem {
  mapping_id: string;
  alert_id?: string | null;
  detection_rule_id: string;
  detection_rule_name: string;
  session_id?: string | null;
  event_id?: string | null;
  evidence_type: string;
  evidence_summary: string;
  confidence_score: number;
  review_status: string;
  recorded_at: string;
  alert_navigation_url?: string | null;
  event_navigation_url?: string | null;
}

export interface AttackTechniqueDetailResponse {
  technique_id: string;
  technique_name: string;
  is_subtechnique: boolean;
  parent_technique_id?: string | null;
  tactics: Array<{ tactic_id: string; tactic_name: string }>;
  platforms: string[];
  data_sources: string[];
  description?: string | null;
  subtechniques: Array<{ subtechnique_id: string; subtechnique_name: string }>;
  configured_mappings: AttackTechniqueMappingItem[];
  live_evidence: AttackTechniqueEvidenceItem[];
  non_attribution_caveat: string;
}

export interface AttackTacticCoverageMetric {
  tactic_id: string;
  tactic_name: string;
  total_techniques: number;
  mapped_techniques?: number;
  evidence_backed_techniques?: number;
  coverage_percentage?: number;
  evidence_percentage?: number;
  rule_mapped_techniques?: number;
  alert_supported_techniques?: number;
  rule_coverage_pct?: number;
  alert_coverage_pct?: number;
}

export interface AttackCoverageAnalyticsResponse {
  catalogue_version: string;
  total_catalogue_techniques: number;
  total_mapped_techniques?: number;
  total_evidence_backed_techniques?: number;
  techniques_with_rule_coverage?: number;
  techniques_with_alert_evidence?: number;
  techniques_with_multiple_rules?: number;
  detection_rules_total?: number;
  detection_rules_mapped?: number;
  detection_rules_coverage_pct?: number;
  overall_mapping_coverage_pct?: number;
  overall_evidence_coverage_pct?: number;
  overall_rule_coverage_pct?: number;
  overall_alert_coverage_pct?: number;
  tactic_breakdown?: AttackTacticCoverageMetric[];
  tactic_coverage?: AttackTacticCoverageMetric[];
}

export interface AttackTraceabilityItem {
  technique_id: string;
  technique_name: string;
  mapping_id: string;
  mapping_category: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  alert_id?: string | null;
  alert_title?: string | null;
  severity?: string | null;
  event_id?: string | null;
  event_type?: string | null;
  session_id?: string | null;
  has_live_alert: boolean;
  navigation_url: string;
}

export interface AttackTraceabilityResponse {
  total_traces: number;
  traces: AttackTraceabilityItem[];
}

export interface MappingReviewActionRequest {
  action: 'APPROVE' | 'REJECT' | 'REQUEST_REVIEW';
  comment: string;
  analyst_id?: string;
}
