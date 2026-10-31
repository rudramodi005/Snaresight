/**
 * REST API client service for Threat Campaign Intelligence & Investigation Grouping (Task P24).
 */

import {
  InvestigationCluster,
  PaginatedClustersResponse,
  ClusterSummary,
  ClusterDetail,
  ClusterMembership,
  ClusterEvidence,
  ClusterRelationship,
  ClusterAttackTechnique,
  ClusterAuditLog,
  ClusterTimelineResponse,
  AddNotePayload,
  LifecycleTransitionPayload,
  MemberDecisionPayload,
  MergePayload,
  SplitPayload,
  ClosePayload,
} from '../types/campaign';

const BASE_URL = '/api/v1/investigations';

export async function listInvestigations(params?: {
  status?: string;
  priority?: string;
  review_status?: string;
  search?: string;
  sort_by?: string;
  sort_order?: string;
  page?: number;
  page_size?: number;
}): Promise<PaginatedClustersResponse> {
  const query = new URLSearchParams();
  if (params?.status) query.append('status', params.status);
  if (params?.priority) query.append('priority', params.priority);
  if (params?.review_status) query.append('review_status', params.review_status);
  if (params?.search) query.append('search', params.search);
  if (params?.sort_by) query.append('sort_by', params.sort_by);
  if (params?.sort_order) query.append('sort_order', params.sort_order);
  if (params?.page) query.append('page', params.page.toString());
  if (params?.page_size) query.append('page_size', params.page_size.toString());

  const url = `${BASE_URL}?${query.toString()}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch investigations: ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigationSummary(): Promise<ClusterSummary> {
  const res = await fetch(`${BASE_URL}/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation summary: ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigationCluster(clusterId: string): Promise<InvestigationCluster> {
  const res = await fetch(`${BASE_URL}/${clusterId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigationClusterDetail(clusterId: string): Promise<ClusterDetail> {
  const res = await fetch(`${BASE_URL}/${clusterId}/detail`);
  if (!res.ok) {
    throw new Error(`Failed to fetch detail for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterMembers(clusterId: string): Promise<ClusterMembership[]> {
  const res = await fetch(`${BASE_URL}/${clusterId}/members`);
  if (!res.ok) {
    throw new Error(`Failed to fetch members for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterEvidence(clusterId: string): Promise<ClusterEvidence[]> {
  const res = await fetch(`${BASE_URL}/${clusterId}/evidence`);
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterTimeline(
  clusterId: string,
  limit = 100,
  offset = 0,
  chronological = true
): Promise<ClusterTimelineResponse> {
  const res = await fetch(
    `${BASE_URL}/${clusterId}/timeline?limit=${limit}&offset=${offset}&chronological=${chronological}`
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterRelationships(clusterId: string): Promise<ClusterRelationship[]> {
  const res = await fetch(`${BASE_URL}/${clusterId}/relationships`);
  if (!res.ok) {
    throw new Error(`Failed to fetch relationships for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterAttackTechniques(clusterId: string): Promise<ClusterAttackTechnique[]> {
  const res = await fetch(`${BASE_URL}/${clusterId}/attack-techniques`);
  if (!res.ok) {
    throw new Error(`Failed to fetch attack techniques for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getClusterAuditLogs(clusterId: string): Promise<ClusterAuditLog[]> {
  const res = await fetch(`${BASE_URL}/${clusterId}/audit`);
  if (!res.ok) {
    throw new Error(`Failed to fetch audit logs for cluster '${clusterId}': ${res.statusText}`);
  }
  return res.json();
}

export async function addAnalystNote(clusterId: string, payload: AddNotePayload): Promise<{ success: boolean }> {
  const res = await fetch(`${BASE_URL}/${clusterId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to add note: ${res.statusText}`);
  }
  return res.json();
}

export async function transitionClusterLifecycle(
  clusterId: string,
  payload: LifecycleTransitionPayload
): Promise<InvestigationCluster> {
  const res = await fetch(`${BASE_URL}/${clusterId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to transition lifecycle: ${res.statusText}`);
  }
  return res.json();
}

export async function submitMemberDecision(
  clusterId: string,
  memberId: string,
  payload: MemberDecisionPayload
): Promise<{ success: boolean; membership_status: string }> {
  const res = await fetch(`${BASE_URL}/${clusterId}/members/${memberId}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to submit member decision: ${res.statusText}`);
  }
  return res.json();
}

export async function mergeClusters(
  destinationClusterId: string,
  payload: MergePayload
): Promise<InvestigationCluster> {
  const res = await fetch(`${BASE_URL}/${destinationClusterId}/merge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to merge clusters: ${res.statusText}`);
  }
  return res.json();
}

export async function splitCluster(
  sourceClusterId: string,
  payload: SplitPayload
): Promise<InvestigationCluster> {
  const res = await fetch(`${BASE_URL}/${sourceClusterId}/split`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to split cluster: ${res.statusText}`);
  }
  return res.json();
}

export async function closeInvestigation(
  clusterId: string,
  payload: ClosePayload
): Promise<InvestigationCluster> {
  const res = await fetch(`${BASE_URL}/${clusterId}/close`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to close investigation: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerClustering(payload?: { time_window_hours?: number; force_all?: boolean }): Promise<{
  success: boolean;
  discovered_clusters_count: number;
  cluster_ids: string[];
}> {
  const res = await fetch(`${BASE_URL}/cluster`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload || { time_window_hours: 48, force_all: true }),
  });
  if (!res.ok) {
    throw new Error(`Failed to trigger clustering: ${res.statusText}`);
  }
  return res.json();
}

