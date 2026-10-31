/**
 * API client for SnareSight Demonstration Lab & Synthetic Evaluation Subsystem.
 */

import {
  ScenarioMeta,
  ScenarioRunRequest,
  ScenarioRunResponse,
  EvaluationSummaryResponse,
  DemoCleanupRequest,
  DemoCleanupResponse,
  DemoExportResponse,
} from '../types/demo';

const BASE_URL = '/api/v1/demo';

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

export const demoApi = {
  async listScenarios(): Promise<ScenarioMeta[]> {
    const res = await fetch(`${BASE_URL}/scenarios`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to load scenarios: ${res.statusText}`);
    }
    return res.json();
  },

  async runScenario(payload: ScenarioRunRequest): Promise<ScenarioRunResponse> {
    const res = await fetch(`${BASE_URL}/scenarios/run`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Scenario execution failed: ${res.statusText}`);
    }
    return res.json();
  },

  async getEvaluation(): Promise<EvaluationSummaryResponse> {
    const res = await fetch(`${BASE_URL}/evaluation`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch evaluation metrics: ${res.statusText}`);
    }
    return res.json();
  },

  async cleanupData(payload: DemoCleanupRequest): Promise<DemoCleanupResponse> {
    const res = await fetch(`${BASE_URL}/cleanup`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Demonstration cleanup failed: ${res.statusText}`);
    }
    return res.json();
  },

  async exportData(): Promise<DemoExportResponse> {
    const res = await fetch(`${BASE_URL}/export`, {
      method: 'GET',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to export demonstration data: ${res.statusText}`);
    }
    return res.json();
  },
};

