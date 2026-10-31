/**
 * REST API Client for SnareSight MITRE ATT&CK catalogue endpoints.
 */

import {
  CatalogueStatus,
  DatasetVersion,
  DetectionMapping,
  DryRunPreview,
  ImportExecutionReceipt,
  MappingReviewRequest,
  MappingReviewResponse,
  MappingStatistics,
  PaginatedMappings,
  PaginatedTechniques,
  Subtechnique,
  Tactic,
  Technique,
  AttackCatalogueMetadata,
  AttackSummaryResponse,
  AttackTacticOverviewItem,
  AttackMatrixResponse,
  AttackTechniqueExplorerResponse,
  AttackTechniqueDetailResponse,
  AttackCoverageAnalyticsResponse,
  AttackTraceabilityResponse,
  MappingReviewActionRequest,
} from '../types/mitre';

const BASE_URL = '/api/v1/mitre';
const ATTACK_URL = '/api/v1/attack';
const DETECTIONS_URL = '/api/v1/detections';

export const mitreApi = {
  /**
   * Fetches active catalogue health and summary counts.
   */
  async getStatus(): Promise<CatalogueStatus> {
    const res = await fetch(`${BASE_URL}/status`);
    if (!res.ok) throw new Error(`Failed to fetch MITRE status: ${res.statusText}`);
    return res.json();
  },

  /**
   * Lists available dataset versions.
   */
  async getVersions(): Promise<DatasetVersion[]> {
    const res = await fetch(`${BASE_URL}/versions`);
    if (!res.ok) throw new Error(`Failed to fetch dataset versions: ${res.statusText}`);
    return res.json();
  },

  /**
   * Queries tactics for active or specified version.
   */
  async getTactics(version?: string): Promise<Tactic[]> {
    const url = version ? `${BASE_URL}/tactics?version=${encodeURIComponent(version)}` : `${BASE_URL}/tactics`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch tactics: ${res.statusText}`);
    return res.json();
  },

  /**
   * Queries single tactic details by ID.
   */
  async getTactic(tacticId: string): Promise<Tactic> {
    const res = await fetch(`${BASE_URL}/tactics/${encodeURIComponent(tacticId)}`);
    if (!res.ok) throw new Error(`Tactic not found: ${tacticId}`);
    return res.json();
  },

  /**
   * Queries paginated techniques with search and filters.
   */
  async getTechniques(params: {
    page?: number;
    pageSize?: number;
    search?: string;
    tactic?: string;
    platform?: string;
    statusFilter?: string;
  } = {}): Promise<PaginatedTechniques> {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.pageSize) query.set('page_size', params.pageSize.toString());
    if (params.search) query.set('search', params.search);
    if (params.tactic) query.set('tactic', params.tactic);
    if (params.platform) query.set('platform', params.platform);
    if (params.statusFilter) query.set('status_filter', params.statusFilter);

    const res = await fetch(`${BASE_URL}/techniques?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch techniques: ${res.statusText}`);
    return res.json();
  },

  /**
   * Queries single technique and its sub-techniques.
   */
  async getTechnique(techniqueId: string): Promise<Technique> {
    const res = await fetch(`${BASE_URL}/techniques/${encodeURIComponent(techniqueId)}`);
    if (!res.ok) throw new Error(`Technique not found: ${techniqueId}`);
    return res.json();
  },

  /**
   * Queries sub-techniques belonging to a technique.
   */
  async getSubtechniques(techniqueId: string): Promise<Subtechnique[]> {
    const res = await fetch(`${BASE_URL}/techniques/${encodeURIComponent(techniqueId)}/subtechniques`);
    if (!res.ok) throw new Error(`Subtechniques not found for technique: ${techniqueId}`);
    return res.json();
  },

  /**
   * Administrative dry-run import preview.
   */
  async dryRunImport(payload: Record<string, unknown>, adminToken: string): Promise<DryRunPreview> {
    const res = await fetch(`${BASE_URL}/import/dry-run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Dry-run failed: ${res.statusText}`);
    return res.json();
  },

  /**
   * Administrative approve and commit import.
   */
  async approveImport(payload: Record<string, unknown>, adminToken: string): Promise<ImportExecutionReceipt> {
    const res = await fetch(`${BASE_URL}/import/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Import failed: ${res.statusText}`);
    return res.json();
  },

  // ==========================================================================
  // P20 Detection Mappings & Analyst Reviews
  // ==========================================================================

  /**
   * Lists paginated detection-to-ATT&CK mappings with optional filtering.
   */
  async listMappings(params: {
    page?: number;
    pageSize?: number;
    ruleId?: string;
    alertId?: string;
    techniqueId?: string;
    category?: string;
    confidenceLevel?: string;
    reviewStatus?: string;
  } = {}): Promise<PaginatedMappings> {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.pageSize) query.set('page_size', params.pageSize.toString());
    if (params.ruleId) query.set('rule_id', params.ruleId);
    if (params.alertId) query.set('alert_id', params.alertId);
    if (params.techniqueId) query.set('technique_id', params.techniqueId);
    if (params.category) query.set('category', params.category);
    if (params.confidenceLevel) query.set('confidence_level', params.confidenceLevel);
    if (params.reviewStatus) query.set('review_status', params.reviewStatus);

    const res = await fetch(`${BASE_URL}/mappings?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to list mappings: ${res.statusText}`);
    return res.json();
  },

  /**
   * Retrieves single mapping details including evidence list.
   */
  async getMapping(mappingId: string): Promise<DetectionMapping> {
    const res = await fetch(`${BASE_URL}/mappings/${encodeURIComponent(mappingId)}`);
    if (!res.ok) throw new Error(`Mapping not found: ${mappingId}`);
    return res.json();
  },

  /**
   * Retrieves all ATT&CK mappings associated with a detection result ID or alert ID.
   */
  async getMappingsForDetection(detectionId: string): Promise<DetectionMapping[]> {
    const res = await fetch(`${DETECTIONS_URL}/${encodeURIComponent(detectionId)}/mitre-mappings`);
    if (!res.ok) throw new Error(`Failed to fetch mappings for detection: ${detectionId}`);
    return res.json();
  },

  /**
   * Retrieves all SnareSight detections mapped to a specific technique.
   */
  async getDetectionsForTechnique(techniqueId: string): Promise<DetectionMapping[]> {
    const res = await fetch(`${BASE_URL}/techniques/${encodeURIComponent(techniqueId)}/detections`);
    if (!res.ok) throw new Error(`Failed to fetch detections for technique: ${techniqueId}`);
    return res.json();
  },

  /**
   * Submits an analyst review action (ACCEPT, REJECT, REQUEST_MORE_EVIDENCE).
   */
  async submitReview(
    mappingId: string,
    req: MappingReviewRequest,
    authToken?: string
  ): Promise<MappingReviewResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const res = await fetch(`${BASE_URL}/mappings/${encodeURIComponent(mappingId)}/review`, {
      method: 'POST',
      headers,
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Review submission failed: ${res.statusText}`);
    return res.json();
  },

  /**
   * Retrieves aggregate mapping operational statistics.
   */
  async getMappingStatistics(): Promise<MappingStatistics> {
    const res = await fetch(`${BASE_URL}/mappings/statistics`);
    if (!res.ok) throw new Error(`Failed to fetch mapping statistics: ${res.statusText}`);
    return res.json();
  },

  // ==========================================================================
  // P29 MITRE ATT&CK Threat Intelligence and Mapping Dashboard Endpoints
  // ==========================================================================

  /**
   * Fetches active catalogue release metadata and provenance.
   */
  async getCatalogueMetadata(): Promise<AttackCatalogueMetadata> {
    const res = await fetch(`${ATTACK_URL}/catalogue/metadata`);
    if (!res.ok) throw new Error(`Failed to fetch catalogue metadata: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches high-level executive dashboard summary KPIs.
   */
  async getAttackSummary(): Promise<AttackSummaryResponse> {
    const res = await fetch(`${ATTACK_URL}/summary`);
    if (!res.ok) throw new Error(`Failed to fetch attack summary: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches canonical Enterprise tactics overview list.
   */
  async getTacticsOverview(): Promise<AttackTacticOverviewItem[]> {
    const res = await fetch(`${ATTACK_URL}/tactics`);
    if (!res.ok) throw new Error(`Failed to fetch tactics overview: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches interactive ATT&CK matrix layout with visual states.
   */
  async getAttackMatrix(params: {
    tactic?: string;
    statusFilter?: string;
    search?: string;
  } = {}): Promise<AttackMatrixResponse> {
    const query = new URLSearchParams();
    if (params.tactic) query.set('tactic', params.tactic);
    if (params.statusFilter) query.set('status_filter', params.statusFilter);
    if (params.search) query.set('search', params.search);

    const res = await fetch(`${ATTACK_URL}/matrix?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch attack matrix: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches paginated techniques with server-side search, filtering, and sorting.
   */
  async getTechniquesExplorer(params: {
    search?: string;
    tactic?: string;
    platform?: string;
    statusFilter?: string;
    page?: number;
    pageSize?: number;
    sortBy?: string;
    sortDir?: string;
  } = {}): Promise<AttackTechniqueExplorerResponse> {
    const query = new URLSearchParams();
    if (params.search) query.set('search', params.search);
    if (params.tactic) query.set('tactic', params.tactic);
    if (params.platform) query.set('platform', params.platform);
    if (params.statusFilter) query.set('status_filter', params.statusFilter);
    if (params.page) query.set('page', params.page.toString());
    if (params.pageSize) query.set('page_size', params.pageSize.toString());
    if (params.sortBy) query.set('sort_by', params.sortBy);
    if (params.sortDir) query.set('sort_dir', params.sortDir);

    const res = await fetch(`${ATTACK_URL}/techniques?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch techniques explorer: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches full technique details, subtechniques, configured rules, and live alert evidence.
   */
  async getTechniqueDetail(techniqueId: string): Promise<AttackTechniqueDetailResponse> {
    const res = await fetch(`${ATTACK_URL}/techniques/${encodeURIComponent(techniqueId)}`);
    if (!res.ok) throw new Error(`Technique not found: ${techniqueId}`);
    return res.json();
  },

  /**
   * Fetches mapping coverage analytics across catalogue and tactics.
   */
  async getCoverageAnalytics(): Promise<AttackCoverageAnalyticsResponse> {
    const res = await fetch(`${ATTACK_URL}/coverage`);
    if (!res.ok) throw new Error(`Failed to fetch coverage analytics: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches detection rule to ATT&CK traceability traces.
   */
  async getTraceability(params: {
    ruleId?: string;
    techniqueId?: string;
  } = {}): Promise<AttackTraceabilityResponse> {
    const query = new URLSearchParams();
    if (params.ruleId) query.set('rule_id', params.ruleId);
    if (params.techniqueId) query.set('technique_id', params.techniqueId);

    const res = await fetch(`${ATTACK_URL}/traceability?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch traceability: ${res.statusText}`);
    return res.json();
  },

  /**
   * Approves a mapping definition with review comment and analyst attribution.
   */
  async approveAttackMapping(
    mappingId: string,
    comment: string,
    analystId = 'analyst_soc_user'
  ): Promise<any> {
    const res = await fetch(`${ATTACK_URL}/mappings/${encodeURIComponent(mappingId)}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'APPROVE', comment, analyst_id: analystId }),
    });
    if (!res.ok) throw new Error(`Approval failed: ${res.statusText}`);
    return res.json();
  },

  /**
   * Rejects a mapping definition with review comment.
   */
  async rejectAttackMapping(
    mappingId: string,
    comment: string,
    analystId = 'analyst_soc_user'
  ): Promise<any> {
    const res = await fetch(`${ATTACK_URL}/mappings/${encodeURIComponent(mappingId)}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'REJECT', comment, analyst_id: analystId }),
    });
    if (!res.ok) throw new Error(`Rejection failed: ${res.statusText}`);
    return res.json();
  },

  /**
   * Requests review or more evidence for a mapping definition.
   */
  async requestAttackMappingReview(
    mappingId: string,
    comment: string,
    analystId = 'analyst_soc_user'
  ): Promise<any> {
    const res = await fetch(`${ATTACK_URL}/mappings/${encodeURIComponent(mappingId)}/request-review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'REQUEST_REVIEW', comment, analyst_id: analystId }),
    });
    if (!res.ok) throw new Error(`Request review failed: ${res.statusText}`);
    return res.json();
  },
};


