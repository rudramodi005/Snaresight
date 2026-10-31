/**
 * REST API client service for SnareSight Observed Source Profiles (Task P23).
 */

import {
  SourceProfile,
  PaginatedSourceProfilesResponse,
  ProfileBehaviorResponse,
  ProfileTrendsResponse,
  SimilarProfile,
  AddNotePayload,
  UpdateAssociationPayload,
} from '../types/sourceProfile';

const BASE_URL = '/api/v1/source-profiles';

export async function listSourceProfiles(params?: {
  search?: string;
  priority?: string;
  status?: string;
  sort_by?: string;
  sort_order?: string;
  page?: number;
  page_size?: number;
}): Promise<PaginatedSourceProfilesResponse> {
  const query = new URLSearchParams();
  if (params?.search) query.append('search', params.search);
  if (params?.priority) query.append('priority', params.priority);
  if (params?.status) query.append('status', params.status);
  if (params?.sort_by) query.append('sort_by', params.sort_by);
  if (params?.sort_order) query.append('sort_order', params.sort_order);
  if (params?.page) query.append('page', params.page.toString());
  if (params?.page_size) query.append('page_size', params.page_size.toString());

  const url = `${BASE_URL}?${query.toString()}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch source profiles: ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfile(profileId: string): Promise<SourceProfile> {
  const res = await fetch(`${BASE_URL}/${profileId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch source profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfileSessions(profileId: string, limit = 50, offset = 0): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${profileId}/sessions?limit=${limit}&offset=${offset}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch sessions for profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfileEvents(profileId: string, limit = 100, offset = 0): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${profileId}/events?limit=${limit}&offset=${offset}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch events for profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfileAlerts(profileId: string, limit = 50, offset = 0): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/${profileId}/alerts?limit=${limit}&offset=${offset}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts for profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfileBehavior(profileId: string): Promise<ProfileBehaviorResponse> {
  const res = await fetch(`${BASE_URL}/${profileId}/behavior`);
  if (!res.ok) {
    throw new Error(`Failed to fetch behavior for profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSourceProfileTrends(profileId: string): Promise<ProfileTrendsResponse> {
  const res = await fetch(`${BASE_URL}/${profileId}/trends`);
  if (!res.ok) {
    throw new Error(`Failed to fetch trends for profile '${profileId}': ${res.statusText}`);
  }
  return res.json();
}

export async function getSimilarProfiles(profileId: string, limit = 5, minSimilarity = 30): Promise<SimilarProfile[]> {
  const res = await fetch(`${BASE_URL}/${profileId}/similar?limit=${limit}&min_similarity=${minSimilarity}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch similar profiles: ${res.statusText}`);
  }
  return res.json();
}

export async function addAnalystNote(profileId: string, payload: AddNotePayload): Promise<{ success: boolean; analyst_notes_count: number }> {
  const res = await fetch(`${BASE_URL}/${profileId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to add note: ${res.statusText}`);
  }
  return res.json();
}

export async function updateProfileAssociation(profileId: string, payload: UpdateAssociationPayload): Promise<SourceProfile> {
  const res = await fetch(`${BASE_URL}/${profileId}/association`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to update association: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerAggregation(payload?: { profile_id?: string; force_all?: boolean }): Promise<{ success: boolean; aggregated_profiles_count: number }> {
  const res = await fetch(`${BASE_URL}/aggregate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload || { force_all: true }),
  });
  if (!res.ok) {
    throw new Error(`Failed to trigger aggregation: ${res.statusText}`);
  }
  return res.json();
}

