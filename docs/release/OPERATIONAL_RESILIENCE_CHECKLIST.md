# SnareSight Release Candidate — Operational Resilience & Fault Tolerance Checklist

**Document ID:** RES-P37-001  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Release Target:** v1.0.0-rc1  
**Date:** October 31, 2026  
**Status:** VERIFIED LAB BENCHMARK  

---

## 1. Resilience & Fault Tolerance Verification Matrix

| Failure Scenario | Simulated Fault | Expected System Behavior | Actual Verified Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Database Unavailable** | Terminate PostgreSQL connection pool. | API returns HTTP 503 Service Unavailable without exposing stack traces or connection credentials. | Verified: Error middleware intercepts `OperationalError` and returns clean JSON diagnostic. | **VERIFIED** |
| **2. Backend API Offline** | Stop Uvicorn server while frontend browser is active. | Dashboard shows clean connection banner and retry button. Zero white-screen JavaScript crash. | Verified: Frontend error boundaries catch fetch failures and display inline alert cards. | **VERIFIED** |
| **3. Invalid Schema Payload** | Submit malformed JSON or missing mandatory UUID/session field to `/ingestion/events/batch`. | Schema validator intercepts request, rejects with HTTP 422/400, and returns field diagnostic. | Verified: `TelemetryValidator` rejects with `SCHEMA_VALIDATION_FAILED`. | **VERIFIED** |
| **4. Duplicate Event Submission** | Resubmit identical raw event payload twice. | Deduplication engine computes SHA-256 fingerprint, marks second event `DUPLICATE`, prevents double alerting. | Verified: `EventDeduplicator` records collision without creating redundant alerts. | **VERIFIED** |
| **5. SSE Stream Interruption** | Terminate SSE client connection during active event publishing. | Server cleans up disconnected client generator cleanly; streaming failure never rolls back DB transaction. | Verified: `EventPublisher` handles `ConnectionResetError` gracefully. | **VERIFIED** |
| **6. Sensor Heartbeat Timeout** | Simulate sensor missing heartbeats past configured timeout window. | Fleet manager marks sensor status as `DEGRADED`, raises internal operational alert. | Verified: `SensorFleetService.audit_sensor_health` transitions sensor state. | **VERIFIED** |
| **7. Schema Migration Error** | Execute invalid SQL migration statement in test environment. | Alembic transaction rolls back completely; zero partial table schema corruption. | Verified: PostgreSQL DDL transactional rollback verified. | **VERIFIED** |
| **8. Unauthorized Privilege Escalation** | VIEWER attempts administrative action (backup creation or sensor registration). | Enforced RBAC middleware returns HTTP 403 Forbidden with structured permission error. | Verified: `test_workflow_08_rbac_privilege_enforcement` passed. | **VERIFIED** |
| **9. Backup Restoration Test** | Run sandbox backup restore test (`isolated_sandbox_db`). | Validates database dump integrity into isolated test DB with 0% impact on active production tables. | Verified: `test_workflow_06_platform_health_and_sandbox_recovery` passed. | **VERIFIED** |
| **10. Evidence Deletion Protection** | Attempt demo data cleanup on record tied to active `EvidencePreservationHoldModel`. | Cleanup service identifies active hold and excludes record from deletion. | Verified: `test_10_cleanup_safety_and_retention_hold_protection` passed. | **VERIFIED** |

---

## 2. Emergency Recovery Runbook Summary

1. **Database Failure Recovery:**
   - Verify PostgreSQL container/service status: `pg_isready -h 127.0.0.1 -p 5432`.
   - In event of data corruption, initiate managed restore using latest verified backup ID:
     `POST /api/v1/resilience/backups/{backup_id}/restore-test`.
2. **Telemetry Ingestion Failure Recovery:**
   - Check collector API key synchronization: ensure `X-API-Key` matches `INGESTION_API_KEY`.
   - Inspect rejected events in `/api/v1/resilience/health/diagnostics`.
3. **Sensor Disconnection Recovery:**
   - Submit fresh heartbeat with sensor credentials via `POST /api/v1/sensors/heartbeat`.
   - Sensor state automatically transitions back to `HEALTHY`.

