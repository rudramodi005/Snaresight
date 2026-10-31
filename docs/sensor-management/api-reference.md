# Sensor Operations REST API Reference

## Base URL
`/api/v1/sensors`

Administrative endpoints require standard `Authorization: Bearer <token>` authentication headers.
Sensor telemetry and heartbeat endpoints require `X-Sensor-Key: snr_live_...` authentication headers.

---

## 1. Fleet Operations Summary

### `GET /api/v1/sensors/summary`
Retrieves aggregated metrics for the Sensor Operations dashboard.

- **Response `200 OK`**:
```json
{
  "total_registered_sensors": 4,
  "active_sensors": 3,
  "degraded_sensors": 1,
  "offline_sensors": 0,
  "maintenance_sensors": 0,
  "disabled_sensors": 0,
  "retired_sensors": 0,
  "last_telemetry_receipt": "2026-10-31T21:45:10Z",
  "total_telemetry_events_received": 18450,
  "ingestion_success_rate": 99.85,
  "open_operational_alerts_count": 1,
  "critical_operational_alerts_count": 0,
  "sensors_by_type": {
    "WEB_LOGIN_DECOY": 2,
    "COWRIE_SSH": 1,
    "GENERIC_COLLECTOR": 1
  },
  "sensors_by_environment": {
    "isolated_lab": 3,
    "dmz_canary": 1
  }
}
```

---

## 2. Sensor Inventory

### `GET /api/v1/sensors`
Queries sensor inventory with optional filtering, search, and pagination.

- **Query Parameters**:
  - `status`: `ACTIVE`, `DEGRADED`, `OFFLINE`, `MAINTENANCE`, `DISABLED`, `REGISTERED` (optional)
  - `sensor_type`: `WEB_LOGIN_DECOY`, `COWRIE_SSH`, `GENERIC_COLLECTOR` (optional)
  - `environment`: `isolated_lab`, `dmz_canary`, `staging`, `production` (optional)
  - `search`: Keyword searching `sensor_id`, `name`, or `lab_zone` (optional)
  - `page`: default `1`
  - `limit`: default `20`

### `POST /api/v1/sensors`
Registers a new sensor node and generates an initial unrecoverable API key.

- **Request Body**:
```json
{
  "sensor_id": "SENSOR-WEB-002",
  "name": "ApexCore SSO Portal Decoy #2",
  "sensor_type": "WEB_LOGIN_DECOY",
  "sensor_version": "1.0.0",
  "deployment_environment": "isolated_lab",
  "lab_zone": "dmz_zone_beta",
  "heartbeat_interval_seconds": 60,
  "supported_telemetry_types": ["http_request", "auth_attempt"],
  "admin_notes": "Secondary deceptive web portal for credential stuffing detection."
}
```

- **Response `201 Created`**:
```json
{
  "sensor": {
    "sensor_id": "SENSOR-WEB-002",
    "name": "ApexCore SSO Portal Decoy #2",
    "operational_status": "REGISTERED",
    "health_status": "UNKNOWN"
  },
  "credential": {
    "key_id": "KEY-1A2B3C4D5E6F",
    "key_prefix": "snr_live_aBcDeF...",
    "status": "ACTIVE"
  },
  "raw_api_key": "snr_live_aBcDeF1234567890_-xyz..."
}
```

### `GET /api/v1/sensors/{sensor_id}`
Retrieves complete workspace details including masked credentials, recent heartbeats, current configuration, and open operational alerts.

### `POST /api/v1/sensors/{sensor_id}/status`
Updates operational state (`ACTIVE`, `DISABLED`, `RETIRED`) with administrative reason.

---

## 3. Sensor Credentials & Rotation

### `POST /api/v1/sensors/{sensor_id}/credentials/rotate`
Revokes active credentials and returns a new raw secret key once.

- **Response `200 OK`**:
```json
{
  "credential": {
    "key_id": "KEY-9F8E7D6C5B4A",
    "key_prefix": "snr_live_zYxWvU...",
    "status": "ACTIVE"
  },
  "raw_api_key": "snr_live_zYxWvU0987654321_-abc...",
  "warning": "Copy this secret immediately. It will not be displayed again."
}
```

### `POST /api/v1/sensors/{sensor_id}/credentials/{key_id}/revoke`
Revokes an individual credential with mandatory `reason` query parameter.

---

## 4. Heartbeat Ingestion

### `POST /api/v1/sensors/heartbeat`
Submits node vitals. Authenticated via `X-Sensor-Key: snr_live_...`.

- **Request Body**:
```json
{
  "sensor_id": "SENSOR-WEB-001",
  "status": "HEALTHY",
  "latency_ms": 11.8,
  "metrics_payload": {
    "cpu_percent": 9.4,
    "memory_mb": 178.2,
    "events_buffered": 0
  },
  "error_category": null
}
```

---

## 5. Configuration Management

### `GET /api/v1/sensors/{sensor_id}/configurations`
Lists all versioned configurations for a sensor.

### `POST /api/v1/sensors/{sensor_id}/configurations`
Commits a new configuration version.

- **Request Body**:
```json
{
  "version": "1.1.0",
  "change_reason": "Increase deception latency on scanner probes",
  "config_payload": {
    "heartbeat_interval_seconds": 60,
    "log_level": "INFO",
    "deception_latency_ms": 500,
    "canary_tokens_enabled": true
  }
}
```

### `POST /api/v1/sensors/{sensor_id}/configurations/rollback`
Rolls back to a previously approved version.

---

## 6. Operational Alerts

### `GET /api/v1/sensors/alerts/operational`
Lists operational alerts with category, severity, and status filters.

### `POST /api/v1/sensors/alerts/{alert_id}/acknowledge`
Marks an alert as acknowledged.

### `POST /api/v1/sensors/alerts/{alert_id}/resolve`
Resolves an operational alert with resolution justification notes.

