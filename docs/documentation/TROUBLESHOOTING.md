# SnareSight: Operational Troubleshooting Knowledge Base

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Audience:** System Administrators, Developers, and Support Engineers  

---

## 1. Quick Diagnostic Decision Tree

If encountering an issue, use this quick triage tree to identify the failing subsystem:

```
[Issue Encountered]
   ├── Cannot connect to Web Dashboard? ------------> See Section 2 (Frontend & Proxy Issues)
   ├── Dashboard loads, but alerts do not update? ---> See Section 3 (SSE & Streaming Issues)
   ├── Sensor reports OFFLINE or drops events? ------> See Section 4 (Sensor Ingestion & Heartbeat)
   ├── Backend crashes on startup / 500 error? ------> See Section 5 (Database & Migration Issues)
   └── Detections not triggering as expected? --------> See Section 6 (Detection Engine Diagnostics)
```

---

## 2. Frontend & Vite Proxy Issues

### 2.1 Error: `Failed to fetch` or `NetworkError when attempting to fetch resource`
* **Symptoms:** Dashboard loads UI layout, but tables display spinning skeletons or red network error banners.
* **Root Cause:**
  1. The FastAPI backend is not running on `127.0.0.1:8000`.
  2. The Vite development proxy (`vite.config.ts`) is misconfigured or pointing to an incorrect port.
* **Remediation Steps:**
  1. Verify backend status:
     ```bash
     curl http://127.0.0.1:8000/health
     ```
  2. If backend is running, verify `frontend/vite.config.ts` proxy configuration:
     ```typescript
     server: {
       proxy: {
         '/api': {
           target: 'http://127.0.0.1:8000',
           changeOrigin: true,
         },
         '/stream': {
           target: 'http://127.0.0.1:8000',
           changeOrigin: true,
         }
       }
     }
     ```
  3. Restart the Vite server: `npm run dev`.

### 2.2 Error: `TypeScript error: Cannot find module` or Build Fails
* **Symptoms:** `npm run build` exits with code 1 during `tsc -b`.
* **Remediation:**
  1. Clear the node modules cache and reinstall:
     ```powershell
     cd frontend
     Remove-Item -Recurse -Force node_modules, package-lock.json
     npm install
     npm run build
     ```

---

## 3. Server-Sent Events (SSE) Streaming Issues

### 3.1 Error: Live Alerts Do Not Appear Without Manual Page Refresh
* **Symptoms:** New events are inserted into the database, but the alert toast banner does not pop up in the browser.
* **Root Cause:** Browser EventSource disconnected or blocked by a proxy buffering chunked HTTP streams.
* **Diagnostics:**
  1. Open browser Developer Tools (F12) > **Network** tab.
  2. Filter by `Fetch/XHR` or `Other` and look for `/api/v1/stream/events`.
  3. Status should be `200 OK` with MIME type `text/event-stream`.
  4. Test direct terminal streaming:
     ```bash
     curl -N http://127.0.0.1:8000/api/v1/stream/events
     ```
* **Remediation:** If behind Nginx or an enterprise reverse proxy, disable response buffering:
  ```nginx
  location /api/v1/stream/ {
      proxy_pass http://snaresight-backend:8000;
      proxy_http_version 1.1;
      proxy_set_header Connection '';
      proxy_buffering off;
      proxy_cache off;
      chunked_transfer_encoding on;
  }
  ```

---

## 4. Sensor Ingestion & Heartbeat Failures

### 4.1 Error: `401 Unauthorized` on Ingestion / Heartbeat
* **Symptoms:** Decoy forwarder log displays: `POST /api/v1/ingestion/events/batch returned 401`.
* **Root Cause:**
  1. Missing or invalid `X-Sensor-Key` header.
  2. Sensor token was rotated or revoked in the backend.
* **Remediation:**
  1. Retrieve the active sensor credentials in the dashboard: **Sensor Management** > **Inspect Sensor**.
  2. Update the token in the forwarder configuration:
     ```bash
     # Example test curl
     curl -X POST "http://127.0.0.1:8000/api/v1/sensors/heartbeat" \
       -H "X-Sensor-Key: <CORRECT_TOKEN>" \
       -H "Content-Type: application/json" \
       -d '{"sensor_id":"sensor-web-01","status":"HEALTHY"}'
     ```

### 4.2 Error: Sensor Status Remains `OFFLINE` Despite Forwarder Running
* **Root Cause:** Heartbeat evaluation service checks for pings within 90 seconds. If system clock on decoy VM has drifted, timestamps may appear in the past.
* **Remediation:**
  1. Synchronize clocks using NTP on the honeypot host:
     ```bash
     sudo chronyd -q 'server pool.ntp.org iburst'
     ```
  2. Trigger manual health re-evaluation:
     ```bash
     curl -X POST "http://127.0.0.1:8000/api/v1/sensors/evaluate-health" \
       -H "Authorization: Bearer <ADMIN_TOKEN>"
     ```

---

## 5. Database Connection & Migration Issues

### 5.1 Error: `could not connect to server: Connection refused (0x0000274D)`
* **Symptoms:** Backend crashes with `psycopg2.OperationalError` or `asyncpg.exceptions.CannotConnectNowError`.
* **Remediation:**
  1. Check if PostgreSQL service is running:
     ```powershell
     # Windows
     Get-Service postgresql*
     Start-Service postgresql-x64-16
     ```
  2. If using Docker:
     ```bash
     docker ps | grep postgres
     docker compose up -d snaresight-db
     ```
  3. Verify connection settings in `backend/.env` match your PostgreSQL password and port (5432).

### 5.2 Error: `alembic.util.exc.CommandError: Can't locate revision identified by 'xxxx'`
* **Symptoms:** Alembic fails during `alembic upgrade head`.
* **Remediation:**
  1. Inspect current migration head:
     ```bash
     cd backend
     alembic current
     ```
  2. If the database schema was modified out-of-band, stamp the database to the known revision:
     ```bash
     alembic stamp p34_operational_resilience
     ```

---

## 6. Threat Detection Engine Diagnostics

### 6.1 Issue: Simulated Brute Force Does Not Trigger Alert
* **Symptoms:** 5 failed logins are sent to the decoy, but no alert appears.
* **Diagnostics:**
  1. Check if the rule is enabled:
     ```bash
     curl http://127.0.0.1:8000/api/v1/attack/catalogue/metadata
     ```
  2. Verify that `AUTH-001` is marked `enabled: true`.
  3. Check temporal sliding window:
     * `AUTH-001` requires $\ge 3$ failed logins within a **300-second window** sharing the same `session_id` or `source_ip`.
     * If the test sent attempts with random different IP addresses and session IDs, each attempt was evaluated as an isolated event.
* **Remediation:** Ensure simulated attack harness keeps `source_ip` or `session_id` constant across the test sequence. (Or trigger `/api/v1/demo/scenarios/run` with `SCN-A` for a guaranteed deterministic test).

