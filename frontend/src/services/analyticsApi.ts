/**
 * REST API client for SnareSight SOC Analytics and Security Reporting (Task P30).
 */

import {
  AnalyticsOverviewResponse,
  EventTimelineResponse,
  AlertTimelineResponse,
  EventAlertOverviewResponse,
  DetectionAnalyticsResponse,
  SeverityAnalyticsResponse,
  ConfidenceAnalyticsResponse,
  SessionAnalyticsResponse,
  SourceAnalyticsResponse,
  InvestigationAnalyticsResponse,
  AttackAnalyticsResponse,
  SensorAnalyticsResponse,
  PipelineHealthAnalyticsResponse,
  ExecutiveSummaryResponse,
  ReportGenerationRequest,
  ReportMetadataResponse,
} from '../types/analytics';

const BASE_URL = '/api/v1/analytics';
const REPORTS_URL = '/api/v1/reports';

export interface AnalyticsFilterParams {
  timeRange?: string;
  startTime?: string;
  endTime?: string;
  sensorId?: string;
  eventCategory?: string;
  detectionCategory?: string;
  severity?: string;
  sessionId?: string;
  investigationId?: string;
  tacticId?: string;
}

function buildQueryString(params: AnalyticsFilterParams = {}): string {
  const q = new URLSearchParams();
  if (params.timeRange) q.set('time_range', params.timeRange);
  if (params.startTime) q.set('start_time', params.startTime);
  if (params.endTime) q.set('end_time', params.endTime);
  if (params.sensorId) q.set('sensor_id', params.sensorId);
  if (params.eventCategory) q.set('event_category', params.eventCategory);
  if (params.detectionCategory) q.set('detection_category', params.detectionCategory);
  if (params.severity) q.set('severity', params.severity);
  if (params.sessionId) q.set('session_id', params.sessionId);
  if (params.investigationId) q.set('investigation_id', params.investigationId);
  if (params.tacticId) q.set('tactic_id', params.tacticId);
  return q.toString() ? `?${q.toString()}` : '';
}

export const analyticsApi = {
  async getOverview(params: AnalyticsFilterParams = {}): Promise<AnalyticsOverviewResponse> {
    const res = await fetch(`${BASE_URL}/overview${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch analytics overview: ${res.statusText}`);
    return res.json();
  },

  async getEventsTimeline(params: AnalyticsFilterParams = {}): Promise<EventTimelineResponse> {
    const res = await fetch(`${BASE_URL}/events/timeline${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch events timeline: ${res.statusText}`);
    return res.json();
  },

  async getAlertsTimeline(params: AnalyticsFilterParams = {}): Promise<AlertTimelineResponse> {
    const res = await fetch(`${BASE_URL}/alerts/timeline${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch alerts timeline: ${res.statusText}`);
    return res.json();
  },

  async getEventAlertOverview(params: AnalyticsFilterParams = {}): Promise<EventAlertOverviewResponse> {
    const res = await fetch(`${BASE_URL}/event-alert-overview${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch event-alert overview: ${res.statusText}`);
    return res.json();
  },

  async getDetectionAnalytics(params: AnalyticsFilterParams = {}): Promise<DetectionAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/detections${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch detection analytics: ${res.statusText}`);
    return res.json();
  },

  async getSeverityAnalytics(params: AnalyticsFilterParams = {}): Promise<SeverityAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/severity${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch severity analytics: ${res.statusText}`);
    return res.json();
  },

  async getConfidenceAnalytics(params: AnalyticsFilterParams = {}): Promise<ConfidenceAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/confidence${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch confidence analytics: ${res.statusText}`);
    return res.json();
  },

  async getSessionAnalytics(params: AnalyticsFilterParams = {}): Promise<SessionAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/sessions${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch session analytics: ${res.statusText}`);
    return res.json();
  },

  async getSourceAnalytics(params: AnalyticsFilterParams = {}): Promise<SourceAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/sources${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch source analytics: ${res.statusText}`);
    return res.json();
  },

  async getInvestigationAnalytics(params: AnalyticsFilterParams = {}): Promise<InvestigationAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/investigations${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch investigation analytics: ${res.statusText}`);
    return res.json();
  },

  async getAttackCoverage(params: AnalyticsFilterParams = {}): Promise<AttackAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/attack-coverage${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch ATT&CK analytics: ${res.statusText}`);
    return res.json();
  },

  async getSensorAnalytics(params: AnalyticsFilterParams = {}): Promise<SensorAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/sensors${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch sensor analytics: ${res.statusText}`);
    return res.json();
  },

  async getPipelineHealth(params: AnalyticsFilterParams = {}): Promise<PipelineHealthAnalyticsResponse> {
    const res = await fetch(`${BASE_URL}/pipeline-health${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch pipeline health: ${res.statusText}`);
    return res.json();
  },

  async getExecutiveSummary(params: AnalyticsFilterParams = {}): Promise<ExecutiveSummaryResponse> {
    const res = await fetch(`${BASE_URL}/executive-summary${buildQueryString(params)}`);
    if (!res.ok) throw new Error(`Failed to fetch executive summary: ${res.statusText}`);
    return res.json();
  },

  async generateReport(req: ReportGenerationRequest): Promise<ReportMetadataResponse> {
    const res = await fetch(`${REPORTS_URL}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Failed to generate report: ${res.statusText}`);
    return res.json();
  },

  async getReportMetadata(reportId: string): Promise<ReportMetadataResponse> {
    const res = await fetch(`${REPORTS_URL}/${encodeURIComponent(reportId)}`);
    if (!res.ok) throw new Error(`Failed to fetch report metadata: ${res.statusText}`);
    return res.json();
  },
};

