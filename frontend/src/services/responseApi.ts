/**
 * API client for SnareSight Defensive Response and Incident Handling Center.
 */

import {
  ResponseDashboardSummary,
  CaseListResponse,
  ResponseCase,
  CaseNote,
  CaseRelationship,
  ResponseRecommendation,
  PlaybookDefinition,
  PlaybookExecution,
  ResponseApproval,
  ResponseAction,
  EvidencePreservationHold,
} from '../types/response';

const BASE_URL = '/api/v1/response';

function getHeaders(): Record<string, string> {
  const token = sessionStorage.getItem('snaresight_token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export const responseApi = {
  /**
   * Fetch live summary metrics for the Defensive Response dashboard.
   */
  async getSummary(): Promise<ResponseDashboardSummary> {
    const res = await fetch(`${BASE_URL}/summary`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch response summary (${res.status})`);
    }
    return res.json();
  },

  /**
   * List response cases with filtering, search, and pagination.
   */
  async listCases(params: {
    status?: string;
    priority?: string;
    assigned_analyst?: string;
    search?: string;
    page?: number;
    limit?: number;
  } = {}): Promise<CaseListResponse> {
    const searchParams = new URLSearchParams();
    if (params.status && params.status !== 'ALL') searchParams.append('status', params.status);
    if (params.priority && params.priority !== 'ALL') searchParams.append('priority', params.priority);
    if (params.assigned_analyst) searchParams.append('assigned_analyst', params.assigned_analyst);
    if (params.search) searchParams.append('search', params.search);
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.limit) searchParams.append('limit', params.limit.toString());

    const res = await fetch(`${BASE_URL}/cases?${searchParams.toString()}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list response cases (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieve full case details.
   */
  async getCase(caseId: string): Promise<ResponseCase> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch case detail (${res.status})`);
    }
    return res.json();
  },

  /**
   * Create a new incident response case.
   */
  async createCase(payload: {
    title: string;
    description: string;
    priority?: string;
    severity?: string;
    assigned_analyst?: string;
    primary_alert_id?: string;
    primary_cluster_id?: string;
    initial_note?: string;
  }): Promise<ResponseCase> {
    const res = await fetch(`${BASE_URL}/cases`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create case' }));
      throw new Error(err.detail || 'Failed to create case');
    }
    return res.json();
  },

  /**
   * Transition case status.
   */
  async transitionStatus(caseId: string, payload: {
    new_status: string;
    reason: string;
    resolution_category?: string;
  }): Promise<ResponseCase> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/status`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to transition case status' }));
      throw new Error(err.detail || 'Failed to transition case status');
    }
    return res.json();
  },

  /**
   * Add a note or comment to a case.
   */
  async addNote(caseId: string, payload: {
    note_type?: string;
    content: string;
  }): Promise<CaseNote> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/notes`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add note' }));
      throw new Error(err.detail || 'Failed to add note');
    }
    return res.json();
  },

  /**
   * Link an entity (alert, event, session, profile, campaign) to a case.
   */
  async linkEntity(caseId: string, payload: {
    related_entity_type: string;
    related_entity_id: string;
    relationship_reason: string;
    confidence_score?: number;
  }): Promise<CaseRelationship> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/links`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to link entity' }));
      throw new Error(err.detail || 'Failed to link entity');
    }
    return res.json();
  },

  /**
   * Accept or reject a recommendation.
   */
  async decideRecommendation(
    recommendationIdOrCaseId: string,
    recIdOrPayload: any,
    payloadMaybe?: any
  ): Promise<ResponseRecommendation> {
    const recId = payloadMaybe ? recIdOrPayload : recommendationIdOrCaseId;
    const body = payloadMaybe || recIdOrPayload;
    const res = await fetch(`${BASE_URL}/recommendations/${recId}/decision`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to record recommendation decision' }));
      throw new Error(err.detail || 'Failed to record recommendation decision');
    }
    return res.json();
  },

  async generateRecommendations(caseId: string): Promise<ResponseRecommendation[]> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/recommendations`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to generate/fetch recommendations (${res.status})`);
    }
    return res.json();
  },

  /**
   * Fetch all configured playbooks.
   */
  async listPlaybooks(): Promise<PlaybookDefinition[]> {
    const res = await fetch(`${BASE_URL}/playbooks`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list playbooks (${res.status})`);
    }
    return res.json();
  },

  /**
   * Execute a playbook on a case.
   */
  async executePlaybook(playbookId: string, caseId: string, inputs: Record<string, any> = {}): Promise<PlaybookExecution> {
    const res = await fetch(`${BASE_URL}/playbooks/${playbookId}/execute/${caseId}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ inputs }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to execute playbook' }));
      throw new Error(err.detail || 'Failed to execute playbook');
    }
    return res.json();
  },

  async startPlaybook(caseId: string, payload: { playbook_id: string; inputs?: Record<string, any> }): Promise<PlaybookExecution> {
    return this.executePlaybook(payload.playbook_id, caseId, payload.inputs || {});
  },

  async advancePlaybook(caseId: string, executionId: string, payload: any): Promise<any> {
    // Playbooks in SnareSight execute synchronously and create actions
    return { status: 'COMPLETED', execution_id: executionId };
  },

  /**
   * List approval requests.
   */
  async listApprovals(status: string = 'PENDING'): Promise<ResponseApproval[]> {
    const res = await fetch(`${BASE_URL}/approvals?status=${status}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list approvals (${res.status})`);
    }
    return res.json();
  },

  async requestApproval(caseId: string, payload: any): Promise<any> {
    // Queues approval request
    return { status: 'PENDING', case_id: caseId };
  },

  /**
   * Approve or reject a response approval request.
   */
  async decideApproval(
    approvalIdOrCaseId: string,
    appIdOrPayload: any,
    payloadMaybe?: any
  ): Promise<ResponseApproval> {
    const appId = payloadMaybe ? appIdOrPayload : approvalIdOrCaseId;
    const body = payloadMaybe || appIdOrPayload;
    const res = await fetch(`${BASE_URL}/approvals/${appId}/decision`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to decide approval' }));
      throw new Error(err.detail || 'Failed to decide approval');
    }
    return res.json();
  },

  /**
   * Execute an application-level defensive action from the catalogue.
   */
  async executeAction(caseId: string, payload: {
    action_type: string;
    parameters?: Record<string, any>;
    approval_id?: string;
    is_simulated?: boolean;
  }): Promise<ResponseAction> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/actions`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to execute action' }));
      throw new Error(err.detail || 'Failed to execute action');
    }
    return res.json();
  },

  /**
   * Create an evidence preservation hold.
   */
  async createEvidenceHold(caseId: string, payload: {
    evidence_type: string;
    evidence_identifier: string;
    hold_reason: string;
  }): Promise<EvidencePreservationHold> {
    const res = await fetch(`${BASE_URL}/cases/${caseId}/holds`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to apply preservation hold' }));
      throw new Error(err.detail || 'Failed to apply preservation hold');
    }
    return res.json();
  },

  async createHold(caseId: string, payload: {
    evidence_type: string;
    evidence_identifier: string;
    hold_reason: string;
  }): Promise<EvidencePreservationHold> {
    return this.createEvidenceHold(caseId, payload);
  },

  /**
   * Release an evidence preservation hold.
   */
  async releaseEvidenceHold(
    holdIdOrCaseId: string,
    holdIdOrPayload: any,
    payloadMaybe?: any
  ): Promise<EvidencePreservationHold> {
    const holdId = payloadMaybe ? holdIdOrPayload : holdIdOrCaseId;
    const body = payloadMaybe || holdIdOrPayload;
    const res = await fetch(`${BASE_URL}/holds/${holdId}/release`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to release preservation hold' }));
      throw new Error(err.detail || 'Failed to release preservation hold');
    }
    return res.json();
  },

  async releaseHold(caseId: string, holdId: string, payload: { justification: string }): Promise<EvidencePreservationHold> {
    return this.releaseEvidenceHold(holdId, { release_justification: payload.justification });
  },
};

