# End-to-End Ingestion Validation Results

**Document ID:** TEST-E2E-RES-001  
**Classification:** Operational Telemetry Pipeline Verification  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** VERIFIED  

---

## 1. Objective & Scope

This report documents the live end-to-end ingestion test conducted using actual honeypot telemetry generated during Phase 2 / Task P10 validation (`c:\Projects\SnareSight\honeypot-lab\web-decoy\events.jsonl`).

The objective was to prove that telemetry captured in the isolated honeypot lab could be transferred, ingested, validated, normalized, and persisted without manual intervention or data corruption.

---

## 2. Ingestion Execution Trace

### Test Input Record (Excerpt from `events.jsonl`)
```json
{
  "event_id": "06b02660-f4b6-44ea-8373-ba58df034947",
  "timestamp": "2026-10-31T09:47:04.281861Z",
  "schema_version": "1.0",
  "data_provenance": "controlled_test",
  "source": { "source_id": "WEB-DECOY-01", "decoy_id": "WEB-DECOY-01" },
  "event_type": "honeypot.login_attempt",
  "session_id": "sess_e5c02b3cfa39",
  "client": { "ip": "127.0.0.1", "port": null, "user_agent": "python-requests/2.32.3" },
  "interaction": {
    "method": "POST",
    "path": "/login",
    "username_attempted": "admin",
    "headers": { "host": "127.0.0.1:8080", "content-type": "application/x-www-form-urlencoded" }
  }
}
```

### Ingestion Execution Log:
```
[INFO] Starting JsonlTelemetryImporter for file: C:\Projects\SnareSight\honeypot-lab\web-decoy\events.jsonl
[INFO] File size: 852 bytes, Lines: 1
[INFO] Sanitizer inspection passed (0 forbidden keys detected)
[INFO] Validator passed (timestamp valid ISO UTC, clock skew within tolerance)
[INFO] SourceRegistry resolved decoy alias 'WEB-DECOY-01' -> active
[INFO] EventDeduplicator generated fingerprint: 298b48bf56447847c2c01d9f826620ca63673cf5ea3e9cbfbb959952ec9dc2a1
[INFO] Normalized event created: action='attempted_login', outcome='failure', severity='medium'
[INFO] Transaction committed atomically (1 row inserted into raw_events, 1 row inserted into security_events)
```

---

## 3. Database State Post-Ingestion

### 1. `raw_events` Record
- **`raw_event_id`**: `06b02660-f4b6-44ea-8373-ba58df034947`
- **`timestamp`**: `2026-10-31 09:47:04.281861+00:00`
- **`event_type`**: `honeypot.login_attempt`
- **`client_ip`**: `127.0.0.1`
- **`session_id`**: `sess_e5c02b3cfa39`
- **`interaction_data`**: `{"method": "POST", "path": "/login", "username_attempted": "admin"}` (Zero password present)

### 2. `security_events` Record
- **`event_id`**: `f47a9e1d-3841-4c6e-924b-3d0774a819b1`
- **`raw_event_id`**: `06b02660-f4b6-44ea-8373-ba58df034947` (Exact foreign key match)
- **`action`**: `attempted_login`
- **`outcome`**: `failure`
- **`severity`**: `medium`
- **`event_hash`**: `298b48bf56447847c2c01d9f826620ca63673cf5ea3e9cbfbb959952ec9dc2a1`

---

## 4. Idempotent Re-Import Verification

Executing the identical file import a second time produced the following result:
```
Batch Execution Summary:
- Total Processed: 1
- Accepted: 0
- Duplicates: 1
- Rejected: 0
```
**Database Inspection:** Querying `SELECT COUNT(*) FROM raw_events` confirmed exactly 1 row remained in the database. No duplicate records were created.

