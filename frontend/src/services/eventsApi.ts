/**
 * REST API client for Security Events Explorer (Task P27).
 */

import {
  PaginatedSecurityEventsResponse,
  SecurityEventSummaryResponse,
  EventDetailResponse,
  EventRelationshipItem,
  EventTimelineResponse,
  EventComparisonResponse,
  EventAuditLogItem,
  EventFilters,
} from '../types/events';

const BASE_URL = '/api/v1/events';

export async function fetchSecurityEvents(
  filters: EventFilters = {}
): Promise<PaginatedSecurityEventsResponse> {
  const params = new URLSearchParams();

  if (filters.start_time) params.append('start_time', filters.start_time);
  if (filters.end_time) params.append('end_time', filters.end_time);
  if (filters.category) params.append('category', filters.category);
  if (filters.event_type) params.append('event_type', filters.event_type);
  if (filters.sensor_id) params.append('sensor_id', filters.sensor_id);
  if (filters.protocol) params.append('protocol', filters.protocol);
  if (filters.source_address) params.append('source_address', filters.source_address);
  if (filters.session_id) params.append('session_id', filters.session_id);
  if (filters.detection_status) params.append('detection_status', filters.detection_status);
  if (filters.outcome) params.append('outcome', filters.outcome);
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.search) params.append('search', filters.search);
  if (filters.sort_by) params.append('sort_by', filters.sort_by);
  if (filters.sort_order) params.append('sort_order', filters.sort_order);
  if (filters.page) params.append('page', filters.page.toString());
  if (filters.page_size) params.append('page_size', filters.page_size.toString());

  const response = await fetch(`${BASE_URL}?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch security events: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchEventsSummary(
  startTime?: string,
  endTime?: string
): Promise<SecurityEventSummaryResponse> {
  const params = new URLSearchParams();
  if (startTime) params.append('start_time', startTime);
  if (endTime) params.append('end_time', endTime);

  const response = await fetch(`${BASE_URL}/summary?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch events summary: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchEventDetail(eventId: string): Promise<EventDetailResponse> {
  const response = await fetch(`${BASE_URL}/${eventId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch event detail for '${eventId}': ${response.statusText}`);
  }
  return response.json();
}

export async function fetchEventRelationships(eventId: string): Promise<EventRelationshipItem[]> {
  const response = await fetch(`${BASE_URL}/${eventId}/relationships`);
  if (!response.ok) {
    throw new Error(`Failed to fetch relationships for '${eventId}': ${response.statusText}`);
  }
  return response.json();
}

export async function fetchEventTimeline(
  eventId: string,
  windowMinutes: number = 60
): Promise<EventTimelineResponse> {
  const response = await fetch(`${BASE_URL}/${eventId}/timeline?window_minutes=${windowMinutes}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch timeline for '${eventId}': ${response.statusText}`);
  }
  return response.json();
}

export async function compareSecurityEvents(eventIds: string[]): Promise<EventComparisonResponse> {
  const response = await fetch(`${BASE_URL}/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event_ids: eventIds }),
  });
  if (!response.ok) {
    throw new Error(`Failed to compare events: ${response.statusText}`);
  }
  return response.json();
}

export async function addEventNote(
  eventId: string,
  note: string,
  analystId: string = 'soc_lead'
): Promise<EventAuditLogItem> {
  const response = await fetch(`${BASE_URL}/${eventId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note, analyst_id: analystId }),
  });
  if (!response.ok) {
    throw new Error(`Failed to add note to event '${eventId}': ${response.statusText}`);
  }
  return response.json();
}

export async function updateEventReviewStatus(
  eventId: string,
  reviewStatus: string,
  note?: string,
  analystId: string = 'soc_lead'
): Promise<EventAuditLogItem> {
  const response = await fetch(`${BASE_URL}/${eventId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      review_status: reviewStatus,
      note,
      analyst_id: analystId,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to update review status for event '${eventId}': ${response.statusText}`);
  }
  return response.json();
}

export async function associateEventWithInvestigation(
  eventId: string,
  clusterId: string,
  reason: string,
  analystId: string = 'soc_lead'
): Promise<{ status: string; message: string; cluster_id: string; cluster_code: string }> {
  const response = await fetch(`${BASE_URL}/${eventId}/investigations/${clusterId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      cluster_id: clusterId,
      reason,
      analyst_id: analystId,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to associate event with investigation: ${response.statusText}`);
  }
  return response.json();
}

