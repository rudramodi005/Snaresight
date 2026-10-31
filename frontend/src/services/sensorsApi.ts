/**
 * API client for SnareSight Honeypot Sensor Operations and Health Monitoring.
 */

import {
  SensorOperationsSummary,
  SensorListResponse,
  SensorDetail,
  Sensor,
  SensorRegistrationResult,
  SensorConfiguration,
  OperationalAlertListResponse,
  OperationalAlert,
  SensorHeartbeat,
} from '../types/sensors';

const BASE_URL = '/api/v1/sensors';

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

export const sensorsApi = {
  /**
   * Fetch overview metrics for the Sensor Operations dashboard.
   */
  async getSummary(): Promise<SensorOperationsSummary> {
    const res = await fetch(`${BASE_URL}/summary`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to fetch sensor summary (${res.status})`);
    }
    return res.json();
  },

  /**
   * Query sensor inventory with search and filters.
   */
  async listSensors(params: {
    status?: string;
    sensor_type?: string;
    environment?: string;
    search?: string;
    page?: number;
    limit?: number;
  } = {}): Promise<SensorListResponse> {
    const searchParams = new URLSearchParams();
    if (params.status && params.status !== 'ALL') searchParams.append('status', params.status);
    if (params.sensor_type && params.sensor_type !== 'ALL') searchParams.append('sensor_type', params.sensor_type);
    if (params.environment && params.environment !== 'ALL') searchParams.append('environment', params.environment);
    if (params.search) searchParams.append('search', params.search);
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.limit) searchParams.append('limit', params.limit.toString());

    const res = await fetch(`${BASE_URL}?${searchParams.toString()}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to list sensors (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieve full sensor workspace detail.
   */
  async getSensorDetail(sensorId: string): Promise<SensorDetail> {
    const res = await fetch(`${BASE_URL}/${sensorId}`, { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`Failed to load sensor detail (${res.status})`);
    }
    return res.json();
  },

  /**
   * Register a new honeypot sensor.
   */
  async registerSensor(payload: {
    sensor_id: string;
    name: string;
    sensor_type: string;
    sensor_version?: string;
    deployment_environment?: string;
    lab_zone?: string;
    heartbeat_interval_seconds?: number;
    supported_telemetry_types?: string[];
    admin_notes?: string;
    initial_config?: Record<string, any>;
  }): Promise<SensorRegistrationResult> {
    const res = await fetch(`${BASE_URL}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to register sensor' }));
      throw new Error(err.detail || 'Failed to register sensor');
    }
    return res.json();
  },

  /**
   * Update sensor operational status (enable, disable, retire).
   */
  async updateStatus(
    sensorId: string,
    payload: { operational_status: string; reason: string }
  ): Promise<Sensor> {
    const res = await fetch(`${BASE_URL}/${sensorId}/status`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update status' }));
      throw new Error(err.detail || 'Failed to update status');
    }
    return res.json();
  },

  /**
   * Rotate sensor API credentials (returns new raw key once).
   */
  async rotateCredentials(sensorId: string): Promise<{ credential: any; raw_api_key: string }> {
    const res = await fetch(`${BASE_URL}/${sensorId}/credentials/rotate`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to rotate credentials' }));
      throw new Error(err.detail || 'Failed to rotate credentials');
    }
    return res.json();
  },

  /**
   * Revoke an individual sensor credential key.
   */
  async revokeCredential(sensorId: string, keyId: string, reason: string): Promise<any> {
    const res = await fetch(
      `${BASE_URL}/${sensorId}/credentials/${keyId}/revoke?reason=${encodeURIComponent(reason)}`,
      {
        method: 'POST',
        headers: getHeaders(),
      }
    );
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to revoke credential' }));
      throw new Error(err.detail || 'Failed to revoke credential');
    }
    return res.json();
  },

  /**
   * Fetch heartbeat history for a sensor.
   */
  async getHeartbeats(sensorId: string, limit: number = 50): Promise<SensorHeartbeat[]> {
    const res = await fetch(`${BASE_URL}/${sensorId}/heartbeats?limit=${limit}`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to load heartbeats (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieve versioned configuration history for a sensor.
   */
  async getConfigurations(sensorId: string): Promise<SensorConfiguration[]> {
    const res = await fetch(`${BASE_URL}/${sensorId}/configurations`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to load configuration history (${res.status})`);
    }
    return res.json();
  },

  /**
   * Commit a new configuration version.
   */
  async commitConfiguration(
    sensorId: string,
    payload: { version: string; config_payload: Record<string, any>; change_reason: string }
  ): Promise<SensorConfiguration> {
    const res = await fetch(`${BASE_URL}/${sensorId}/configurations`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update configuration' }));
      throw new Error(err.detail || 'Failed to update configuration');
    }
    return res.json();
  },

  /**
   * Roll back to an earlier configuration version.
   */
  async rollbackConfiguration(
    sensorId: string,
    payload: { target_version: string; change_reason: string }
  ): Promise<SensorConfiguration> {
    const res = await fetch(`${BASE_URL}/${sensorId}/configurations/rollback`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to rollback configuration' }));
      throw new Error(err.detail || 'Failed to rollback configuration');
    }
    return res.json();
  },

  /**
   * Toggle maintenance mode for a sensor.
   */
  async setMaintenanceMode(
    sensorId: string,
    payload: { enabled: boolean; reason: string }
  ): Promise<Sensor> {
    const res = await fetch(`${BASE_URL}/${sensorId}/maintenance`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to toggle maintenance mode' }));
      throw new Error(err.detail || 'Failed to toggle maintenance mode');
    }
    return res.json();
  },

  /**
   * Query operational alerts segregated from security threat detections.
   */
  async listOperationalAlerts(params: {
    sensor_id?: string;
    category?: string;
    severity?: string;
    status?: string;
    page?: number;
    limit?: number;
  } = {}): Promise<OperationalAlertListResponse> {
    const searchParams = new URLSearchParams();
    if (params.sensor_id) searchParams.append('sensor_id', params.sensor_id);
    if (params.category && params.category !== 'ALL') searchParams.append('category', params.category);
    if (params.severity && params.severity !== 'ALL') searchParams.append('severity', params.severity);
    if (params.status && params.status !== 'ALL') searchParams.append('status', params.status);
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.limit) searchParams.append('limit', params.limit.toString());

    const res = await fetch(`${BASE_URL}/alerts/operational?${searchParams.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to list operational alerts (${res.status})`);
    }
    return res.json();
  },

  /**
   * Acknowledge an operational alert.
   */
  async acknowledgeAlert(alertId: string): Promise<OperationalAlert> {
    const res = await fetch(`${BASE_URL}/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to acknowledge alert (${res.status})`);
    }
    return res.json();
  },

  /**
   * Resolve an operational alert with resolution notes.
   */
  async resolveAlert(alertId: string, resolution_notes: string): Promise<OperationalAlert> {
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
   * Sweep sensor health evaluations across the fleet.
   */
  async sweepHealth(): Promise<any> {
    const res = await fetch(`${BASE_URL}/evaluate-health`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      throw new Error(`Failed to evaluate health (${res.status})`);
    }
    return res.json();
  },
};

