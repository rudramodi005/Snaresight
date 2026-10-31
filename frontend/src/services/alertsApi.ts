/**
 * API client for SOC Alert Management & Triage Center (Task P28).
 */

import {
  AlertQueueResponse,
  AlertSummaryResponse,
  AlertDetailResponse,
  AlertEvidenceItem,
  AlertRelationshipsResponse,
  AlertAuditLogItem,
  AlertNoteItem,
  AlertFilterState,
  TriageDecisionType,
} from '../types/alerts';

const API_BASE = '/api/v1/alerts';

export async function fetchAlertsQueue(filters: AlertFilterState): Promise<AlertQueueResponse> {
  const params = new URLSearchParams();

  if (filters.severity) params.set('severity', filters.severity);
  if (filters.status) params.set('status', filters.status);
  if (filters.category) params.set('category', filters.category);
  if (filters.assignedAnalyst) params.set('assigned_analyst', filters.assignedAnalyst);
  if (filters.unassignedOnly) params.set('unassigned_only', 'true');
  if (filters.search) params.set('search', filters.search);
  if (filters.dateStart) params.set('date_start', filters.dateStart);
  if (filters.dateEnd) params.set('date_end', filters.dateEnd);
  if (filters.sortBy) params.set('sort_by', filters.sortBy);
  if (filters.sortOrder) params.set('sort_order', filters.sortOrder);
  params.set('page', String(filters.page));
  params.set('limit', String(filters.limit));

  const res = await fetch(`${API_BASE}?${params.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertsSummary(): Promise<AlertSummaryResponse> {
  const res = await fetch(`${API_BASE}/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertDetail(alertId: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert detail: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertEvidence(alertId: string): Promise<AlertEvidenceItem[]> {
  const res = await fetch(`${API_BASE}/${alertId}/evidence`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertRelationships(alertId: string): Promise<AlertRelationshipsResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/relationships`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert relationships: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertHistory(alertId: string): Promise<AlertAuditLogItem[]> {
  const res = await fetch(`${API_BASE}/${alertId}/history`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert history: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertNotes(alertId: string): Promise<AlertNoteItem[]> {
  const res = await fetch(`${API_BASE}/${alertId}/notes`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert notes: ${res.statusText}`);
  }
  return res.json();
}

export async function acknowledgeAlert(alertId: string, analystId: string, notes?: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/acknowledge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to acknowledge alert: ${res.statusText}`);
  }
  return res.json();
}

export async function assignAlert(alertId: string, analystId: string, assignedBy: string, notes?: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, assigned_by: assignedBy, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to assign alert: ${res.statusText}`);
  }
  return res.json();
}

export async function startInvestigation(alertId: string, analystId: string, clusterId?: string, notes?: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, investigation_cluster_id: clusterId, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to start investigation: ${res.statusText}`);
  }
  return res.json();
}

export async function escalateAlert(alertId: string, analystId: string, reason: string, escalationRole: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/escalate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, reason, escalation_role: escalationRole }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to escalate alert: ${res.statusText}`);
  }
  return res.json();
}

export async function resolveAlert(alertId: string, analystId: string, resolutionCategory: string, resolutionReason: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, resolution_category: resolutionCategory, resolution_reason: resolutionReason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to resolve alert: ${res.statusText}`);
  }
  return res.json();
}

export async function closeAlert(alertId: string, analystId: string, closureReason: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/close`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, closure_reason: closureReason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to close alert: ${res.statusText}`);
  }
  return res.json();
}

export async function addAlertNote(alertId: string, authorId: string, content: string, authorRole = 'SOC_ANALYST'): Promise<AlertNoteItem> {
  const res = await fetch(`${API_BASE}/${alertId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ author_id: authorId, author_role: authorRole, content }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to add note: ${res.statusText}`);
  }
  return res.json();
}

export async function recordTriageDecision(alertId: string, analystId: string, decision: TriageDecisionType, justification: string): Promise<AlertDetailResponse> {
  const res = await fetch(`${API_BASE}/${alertId}/triage-decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analyst_id: analystId, decision, justification }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to record triage decision: ${res.statusText}`);
  }
  return res.json();
}

