/**
 * API client for SnareSight Platform Security, Diagnostics, Backups, and Resilience.
 */

import {
  SystemHealthOverview,
  InternalSecurityEvent,
  InternalSecurityAlert,
  DatabaseBackup,
  RestoreTestRecord,
  DisasterRecoveryConfig,
  DisasterRecoveryChecklist,
  InternalIncident,
  InternalIncidentNote,
  AuditVerification,
} from '../types/resilience';

const BASE_URL = '/api/v1/resilience';

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

export const resilienceApi = {
  /**
   * Comprehensive system health diagnostics.
   */
  async getDiagnostics(): Promise<SystemHealthOverview> {
    const res = await fetch(`${BASE_URL}/health/diagnostics`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch diagnostics (${res.status})`);
    }
    return res.json();
  },

  /**
   * Run cryptographic audit chain verification.
   */
  async verifyAuditTrail(): Promise<AuditVerification> {
    const res = await fetch(`${BASE_URL}/audit/verify`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Audit verification failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Internal security events stream.
   */
  async listEvents(params?: { event_type?: string; severity?: string; limit?: number }): Promise<InternalSecurityEvent[]> {
    const query = new URLSearchParams();
    if (params?.event_type) query.set('event_type', params.event_type);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.limit) query.set('limit', String(params.limit));

    const res = await fetch(`${BASE_URL}/events?${query.toString()}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list internal events (${res.status})`);
    }
    return res.json();
  },

  /**
   * Internal security alerts.
   */
  async listAlerts(params?: { status?: string; severity?: string }): Promise<InternalSecurityAlert[]> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.severity) query.set('severity', params.severity);

    const res = await fetch(`${BASE_URL}/alerts?${query.toString()}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list internal alerts (${res.status})`);
    }
    return res.json();
  },

  async acknowledgeAlert(alertId: string, notes?: string): Promise<InternalSecurityAlert> {
    const res = await fetch(`${BASE_URL}/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ notes }),
    });
    if (!res.ok) {
      throw new Error(`Failed to acknowledge alert (${res.status})`);
    }
    return res.json();
  },

  async resolveAlert(alertId: string, resolution_notes: string): Promise<InternalSecurityAlert> {
    const res = await fetch(`${BASE_URL}/alerts/${alertId}/resolve`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ resolution_notes }),
    });
    if (!res.ok) {
      throw new Error(`Failed to resolve alert (${res.status})`);
    }
    return res.json();
  },

  /**
   * Backups and restore testing.
   */
  async listBackups(): Promise<DatabaseBackup[]> {
    const res = await fetch(`${BASE_URL}/backups`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list backups (${res.status})`);
    }
    return res.json();
  },

  async initiateBackup(payload: { backup_type: string; retention_hold: boolean }): Promise<DatabaseBackup> {
    const res = await fetch(`${BASE_URL}/backups`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to initiate backup (${res.status})`);
    }
    return res.json();
  },

  async runRestoreTest(backupId: string, test_environment: string = 'isolated_sandbox_db'): Promise<RestoreTestRecord> {
    const res = await fetch(`${BASE_URL}/backups/${backupId}/restore-test`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ test_environment }),
    });
    if (!res.ok) {
      throw new Error(`Restore test failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Disaster recovery configuration & checklists.
   */
  async getDrConfig(): Promise<DisasterRecoveryConfig> {
    const res = await fetch(`${BASE_URL}/dr/config`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch DR config (${res.status})`);
    }
    return res.json();
  },

  async updateDrConfig(config: Partial<DisasterRecoveryConfig>): Promise<DisasterRecoveryConfig> {
    const res = await fetch(`${BASE_URL}/dr/config`, {
      method: 'PUT',
      headers: getHeaders(),
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      throw new Error(`Failed to update DR config (${res.status})`);
    }
    return res.json();
  },

  async listDrChecklists(): Promise<DisasterRecoveryChecklist[]> {
    const res = await fetch(`${BASE_URL}/dr/checklists`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list DR checklists (${res.status})`);
    }
    return res.json();
  },

  async toggleChecklistItem(scenarioId: string, payload: { item_id: string; completed: boolean; notes?: string }): Promise<DisasterRecoveryChecklist> {
    const res = await fetch(`${BASE_URL}/dr/checklists/${scenarioId}/items/toggle`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to toggle checklist item (${res.status})`);
    }
    return res.json();
  },

  /**
   * Internal security incidents.
   */
  async listIncidents(params?: { status?: string; severity?: string }): Promise<InternalIncident[]> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.severity) query.set('severity', params.severity);

    const res = await fetch(`${BASE_URL}/incidents?${query.toString()}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list incidents (${res.status})`);
    }
    return res.json();
  },

  async createIncident(payload: {
    title: string;
    description: string;
    severity: string;
    affected_components: string[];
    linked_alert_ids: string[];
    assigned_administrator?: string;
  }): Promise<InternalIncident> {
    const res = await fetch(`${BASE_URL}/incidents`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to create incident (${res.status})`);
    }
    return res.json();
  },

  async getIncident(incidentId: string): Promise<InternalIncident> {
    const res = await fetch(`${BASE_URL}/incidents/${incidentId}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch incident (${res.status})`);
    }
    return res.json();
  },

  async updateIncident(incidentId: string, payload: Partial<InternalIncident>): Promise<InternalIncident> {
    const res = await fetch(`${BASE_URL}/incidents/${incidentId}`, {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to update incident (${res.status})`);
    }
    return res.json();
  },

  async addIncidentNote(incidentId: string, payload: { content: string; note_type: string }): Promise<InternalIncidentNote> {
    const res = await fetch(`${BASE_URL}/incidents/${incidentId}/notes`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to add incident note (${res.status})`);
    }
    return res.json();
  },
};

