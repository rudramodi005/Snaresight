/**
 * REST API client service for SnareSight Behavioral Sequences (Task P22).
 */

import {
  BehavioralSequence,
  BehavioralSequenceDetail,
  PaginatedSequencesResponse,
  SequenceAssessmentRequest,
  SequenceEvidenceItem,
  SequenceStatistics,
  SequenceStatusUpdateRequest,
  SequenceTimelineResponse,
} from '../types/sequence';

const BASE_URL = '/api/v1/sequences';

export async function listSequences(params?: {
  page?: number;
  page_size?: number;
  status?: string;
  pattern?: string;
  source_address?: string;
  decoy_id?: string;
  min_sessions?: number;
  min_confidence?: number;
  min_relevance?: number;
}): Promise<PaginatedSequencesResponse> {
  const query = new URLSearchParams();
  if (params?.page) query.append('page', params.page.toString());
  if (params?.page_size) query.append('page_size', params.page_size.toString());
  if (params?.status) query.append('status', params.status);
  if (params?.pattern) query.append('pattern', params.pattern);
  if (params?.source_address) query.append('source_address', params.source_address);
  if (params?.decoy_id) query.append('decoy_id', params.decoy_id);
  if (params?.min_sessions !== undefined) query.append('min_sessions', params.min_sessions.toString());
  if (params?.min_confidence !== undefined) query.append('min_confidence', params.min_confidence.toString());
  if (params?.min_relevance !== undefined) query.append('min_relevance', params.min_relevance.toString());

  const url = `${BASE_URL}?${query.toString()}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch sequences: ${res.statusText}`);
  }
  return res.json();
}

export async function getSequence(sequenceId: string): Promise<BehavioralSequenceDetail> {
  const res = await fetch(`${BASE_URL}/${sequenceId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceTimeline(
  sequenceId: string,
  limit: number = 300
): Promise<SequenceTimelineResponse> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/timeline?limit=${limit}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline for sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceEvidence(
  sequenceId: string
): Promise<SequenceEvidenceItem[]> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/evidence`);
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence for sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceSessions(sequenceId: string): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/sessions`);
  if (!res.ok) {
    throw new Error(`Failed to fetch sessions for sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceDetections(sequenceId: string): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/detections`);
  if (!res.ok) {
    throw new Error(`Failed to fetch detections for sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceMitre(sequenceId: string): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/mitre`);
  if (!res.ok) {
    throw new Error(`Failed to fetch ATT&CK mappings for sequence '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function recordAssessment(
  sequenceId: string,
  payload: SequenceAssessmentRequest
): Promise<BehavioralSequence> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/assessment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to record assessment for '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function updateSequenceStatus(
  sequenceId: string,
  payload: SequenceStatusUpdateRequest
): Promise<BehavioralSequence> {
  const res = await fetch(`${BASE_URL}/${sequenceId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to update status for '${sequenceId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSequenceStatistics(): Promise<SequenceStatistics> {
  const res = await fetch(`${BASE_URL}/statistics`);
  if (!res.ok) {
    throw new Error(`Failed to fetch sequence statistics: ${res.statusText}`);
  }
  return res.json();
}

