# Honeypot Sensor Management Implementation Assessment

**Date:** 2026-10-31  
**Phase:** 7 — Security & Defensive Response  
**Prompt:** P33 / 40  
**Scope:** Sensor Management, Health Monitoring, Operational Reliability, and Operational Alerting

---

## 1. Existing Sensor Architecture & Reality Check

An inspection of the SnareSight codebase reveals the factual state of honeypot sensor implementations:

1. **Genuinely Implemented Decoy:**
   - **ApexCore Logistics Web Decoy (`WEB-001` / `WEB-DECOY-01`):** Located in `honeypot-lab/web-decoy/`, this is a fully implemented, standalone Python/FastAPI decoy application simulating an enterprise employee SSO login portal. It has 39 automated tests covering input boundaries, keyed HMAC username hashing, password omission, session tracking (`decoy_sess_<uuid>`), and local JSONL logging (`data/events.jsonl`).
2. **Partial / Placeholder Adapters:**
   - **Cowrie Adapter:** Located in `honeypot-lab/cowrie-adapter/`, only contains a placeholder `README.md`. No active adapter process or daemon exists.
3. **Existing Backend Sensor Models:**
   - `HoneypotModel` in `backend/app/db/models/honeypot.py`: Contains minimal metadata (`decoy_id`, `name`, `decoy_type`, `protocol`, `environment`, `status`, `created_at`, `updated_at`).
   - `EventSourceModel` in `backend/app/db/models/honeypot.py`: Represents collector agents (`source_id`, `source_type`, `source_name`, `environment`, `schema_version`, `status`).
4. **Existing Telemetry Ingestion Pipeline:**
   - `POST /api/v1/ingestion/events/batch`: Secured by a single static environment API key (`INGESTION_API_KEY`, header `X-API-Key`).
   - `SourceRegistryValidator` (`app/ingestion/source_registry.py`): Validates that incoming `source_id` and `decoy_id` match pre-registered records in the database or default static fallback cache.
   - Validation & Normalization: Sanitizes sensitive credentials, checks schema conformity, normalizes timestamps to UTC, computes deterministic SHA-256 event fingerprints, deduplicates, and persists into `raw_events` and `security_events`.

---

## 2. Current Sensor Communication & Health Checks

- **Communication Method:** 
  - The web decoy generates canonical JSONL records locally.
  - Collector agents forward batches to `/api/v1/ingestion/events/batch` via HTTP with an API key.
  - Decoys have **zero direct database connectivity** to PostgreSQL; all telemetry flows through the authenticated HTTP ingestion gateway.
- **Existing Health Checks:**
  - `web-decoy/app/routes/health.py`: Returns a basic `{"status": "ok"}` liveness response.
  - Backend `PipelineHealthService` (`app/monitoring/service.py`): Checks PostgreSQL connection latency and internal metrics queue status (`/api/v1/health/readiness` and `/liveness`).
- **Deficiencies in Existing Health Monitoring:**
  - No per-sensor heartbeat submission or tracking.
  - No heartbeat interval configuration or missed heartbeat counter.
  - No classification of sensor state into `ACTIVE`, `DEGRADED`, `OFFLINE`, `MAINTENANCE`, `DISABLED`, or `RETIRED`.
  - No tracking of telemetry ingestion success rate, delivery failures, or latency per sensor.
  - No operational alerts triggered by sensor degradation.

---

## 3. Existing Configuration Controls

- **Current State:**
  - Sensor configuration is statically loaded from local environment files (`.env`) upon process boot.
  - No remote or centralized configuration management exists.
  - No versioned configuration records, change history, or rollback mechanisms exist.
- **Constraints:**
  - Remote shell execution and automatic firewall/OS reconfiguration are strictly prohibited.
  - Central configuration management must maintain versioned desired/effective state, while acknowledging that sensor deployment utilizes safe, controlled application synchronization or approved manual configuration reload.

---

## 4. Identified Gaps & Missing Capabilities

1. **Central Sensor Inventory:** Missing a unified view tracking operational status, health status, deployment environment, lab/zone, heartbeat frequency, and administrative metadata.
2. **Per-Sensor Authentication:** Currently, ingestion relies on a single shared collector key. Individual sensors cannot be authenticated uniquely, rotated, or revoked without affecting the entire fleet.
3. **Heartbeat Protocol & Health Engine:** Missing an authenticated heartbeat endpoint (`POST /api/v1/sensors/heartbeat`), periodic state evaluation, and jitter-tolerant offline classification.
4. **Telemetry Delivery Reliability Tracking:** Missing metrics on per-sensor events generated, received, validated, rejected, and persisted.
5. **Operational Alerting Subsystem:** Missing operational alert generation (e.g. `SENSOR_HEARTBEAT_OVERDUE`, `SENSOR_OFFLINE`, `TELEMETRY_INGESTION_FAILURE`, `AUTH_FAILURE`, `CONFIG_MISMATCH`) separate from threat detection alerts.
6. **Sensor Operations UI:** Missing a dedicated SOC page (`/sensors`) for sensor inventory, health history, operational alert management, and administrative controls.

---

## 5. Security & Isolation Concerns

1. **Impersonation Risk:** A shared ingestion key allows any collector to submit events under any `source_id` or `decoy_id`.
   - *Mitigation:* Issue unique, cryptographically random API keys per sensor. Store only hashed keys (SHA-256) in the database. Validate that the authenticated sensor ID matches the payload.
2. **Secret Leakage in APIs/UI:** Sensor API keys or credentials must never be returned in plain text via list or get endpoints.
   - *Mitigation:* Display the raw API secret only once upon initial registration or rotation. Return only a masked key prefix (`snr_live_...`) in API queries.
3. **Segregation of Operational Alerts vs. Security Threats:**
   - *Mitigation:* Operational health alerts must remain strictly in the operational domain (`operational_alerts`). An offline sensor must never generate a MITRE ATT&CK security alert or inflate threat scores.
4. **PostgreSQL Decoupling:** Honeypot sensors must remain strictly in isolated networks and never possess PostgreSQL connection strings or network routes.

---

## 6. Implementation Plan & Deliverables

1. **Database Schema & Migrations:**
   - Create `backend/app/db/models/sensor.py` with `SensorModel`, `SensorCredentialModel`, `SensorHeartbeatModel`, `SensorConfigurationModel`, `OperationalAlertModel`, and `SensorMaintenanceHistoryModel`.
   - Register in `app/db/models/__init__.py`.
   - Generate and apply Alembic migration `backend/migrations/versions/p33_sensor_management.py`.
2. **Backend Subsystem (`backend/app/modules/sensors/`):**
   - `schemas.py`: Pydantic request/response contracts.
   - `auth.py`: Per-sensor credential verification, generation, and hashing.
   - `health_engine.py`: Health state machine and operational alert generator.
   - `service.py`: Core `SensorService` managing inventory, heartbeats, configuration, alerts, and audit logging.
   - `routes.py`: FastAPI endpoints under `/api/v1/sensors/*`.
   - Register in `backend/app/main.py`.
3. **Frontend Subsystem:**
   - `frontend/src/types/sensors.ts`.
   - `frontend/src/services/sensorsApi.ts`.
   - `frontend/src/features/sensors/SensorOperationsPage.tsx`.
   - Route and navigation integration in `frontend/src/App.tsx`.
4. **Automated Testing:**
   - Unit tests covering registration, authentication, rotation, revocation, heartbeat, health evaluation, configuration rollback, and operational alert lifecycle in `backend/tests/modules/sensors/test_sensor_api.py`.
5. **Documentation Suite:**
   - 10 documentation files in `docs/sensor-management/` plus completion report.

