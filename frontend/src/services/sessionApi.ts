/**
 * REST API Client for SnareSight Session Correlation and Timelines (Task P21).
 */

import {
  ActivitySession,
  PaginatedSessions,
  SessionEvent,
  SessionStatistics,
  SessionTimeline,
} from '../types/session';

const BASE_URL = '/api/v1/sessions';

export const sessionApi = {
  /**
   * Retrieves paginated activity sessions with optional filtering.
   */
  async listSessions(params: {
    page?: number;
    pageSize?: number;
    decoyId?: string;
    honeypotType?: string;
    sourceAddress?: string;
    status?: string;
    minEvents?: number;
    hasDetections?: boolean;
  } = {}): Promise<PaginatedSessions> {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.pageSize) query.set('page_size', params.pageSize.toString());
    if (params.decoyId) query.set('decoy_id', params.decoyId);
    if (params.honeypotType) query.set('honeypot_type', params.honeypotType);
    if (params.sourceAddress) query.set('source_address', params.sourceAddress);
    if (params.status) query.set('status', params.status);
    if (params.minEvents) query.set('min_events', params.minEvents.toString());
    if (params.hasDetections !== undefined) query.set('has_detections', params.hasDetections.toString());

    const res = await fetch(`${BASE_URL}?${query.toString()}`);
    if (!res.ok) throw new Error(`Failed to list sessions: ${res.statusText}`);
    return res.json();
  },

  /**
   * Retrieves detailed activity session record.
   */
  async getSession(sessionId: string): Promise<ActivitySession> {
    const res = await fetch(`${BASE_URL}/${encodeURIComponent(sessionId)}`);
    if (!res.ok) throw new Error(`Session not found: ${sessionId}`);
    return res.json();
  },

  /**
   * Builds and retrieves chronological investigation timeline.
   */
  async getSessionTimeline(sessionId: string, limit: number = 200): Promise<SessionTimeline> {
    const res = await fetch(`${BASE_URL}/${encodeURIComponent(sessionId)}/timeline?limit=${limit}`);
    if (!res.ok) throw new Error(`Failed to fetch timeline for session: ${sessionId}`);
    return res.json();
  },

  /**
   * Retrieves normalized security events attached to an activity session.
   */
  async getSessionEvents(sessionId: string): Promise<SessionEvent[]> {
    const res = await fetch(`${BASE_URL}/${encodeURIComponent(sessionId)}/events`);
    if (!res.ok) throw new Error(`Failed to fetch events for session: ${sessionId}`);
    return res.json();
  },

  /**
   * Retrieves security detections and alerts for a session.
   */
  async getSessionDetections(sessionId: string): Promise<any[]> {
    const res = await fetch(`${BASE_URL}/${encodeURIComponent(sessionId)}/detections`);
    if (!res.ok) throw new Error(`Failed to fetch detections for session: ${sessionId}`);
    return res.json();
  },

  /**
   * Retrieves ATT&CK mappings associated with a session.
   */
  async getSessionMitreMappings(sessionId: string): Promise<any[]> {
    const res = await fetch(`${BASE_URL}/${encodeURIComponent(sessionId)}/mitre-mappings`);
    if (!res.ok) throw new Error(`Failed to fetch ATT&CK mappings for session: ${sessionId}`);
    return res.json();
  },

  /**
   * Retrieves aggregate operational statistics for correlated sessions.
   */
  async getStatistics(): Promise<SessionStatistics> {
    const res = await fetch(`${BASE_URL}/statistics`);
    if (!res.ok) throw new Error(`Failed to fetch session statistics: ${res.statusText}`);
    return res.json();
  },
};

