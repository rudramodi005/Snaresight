# Live Demonstration Validation & Verification Protocol

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/LIVE_DEMONSTRATION_VALIDATION.md`  
**Evaluation Scope:** Complete End-to-End User Journey Validation  

---

## 1. Demonstration Protocol Overview

This document specifies the exact, step-by-step verification protocol used to demonstrate SnareSight during formal academic reviews and mentor evaluations. The demonstration relies entirely on the **Deterministic Demonstration Lab** (`/demo`) and synthetic attack scenarios implemented in `backend/app/modules/demo/`.

All steps use actual, working CLI commands, API calls, and browser interactions. Zero fake success messages or mock data are used.

---

## 2. Step-by-Step Demonstration Execution Log

### Step 1: Application Startup & Infrastructure Health
* **Command Executed:**
  ```bash
  docker compose up -d
  # Or natively:
  # Terminal 1: cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8000
  # Terminal 2: cd frontend && npm run dev
  ```
* **Verification Command:**
  ```bash
  curl http://127.0.0.1:8000/health
  ```
* **Expected Result:** HTTP 200 OK with `{"platform":"SnareSight","status":"OPERATIONAL","api_version":"v1"}`.
* **Actual Result:** HTTP 200 OK verified.
* **Evidence Location:** Backend console log; `docs/release/RELEASE_CANDIDATE_REPORT.md`.
* **Limitations:** Requires PostgreSQL and Uvicorn running.

---

### Step 2: Database Connectivity & Schema Lineage
* **Command Executed:**
  ```bash
  cd backend && alembic current
  ```
* **Expected Result:** Reports head revision `p34_operational_resilience`.
* **Actual Result:** `p34_operational_resilience (head)`.
* **Evidence Location:** `backend/migrations/versions/p34_operational_resilience.py`.

---

### Step 3: Sensor Fleet Health Verification
* **Command Executed:**
  ```bash
  curl http://127.0.0.1:8000/api/v1/sensors/summary
  ```
* **Expected Result:** JSON payload showing total sensors registered and healthy count.
* **Actual Result:** Returns sensor metadata with status `HEALTHY`.
* **Evidence Location:** Dashboard Overview Decoy Grid; `backend/app/modules/sensors/`.

---

### Step 4: Triggering Synthetic Scenario A (Web Login Brute Force)
* **Action:** In the browser, navigate to [http://localhost:5173/demo](http://localhost:5173/demo) and click **Run Scenario A**.
* **API Call Equivalent:**
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/v1/demo/scenarios/run" \
    -H "Content-Type: application/json" \
    -d '{"scenario_id": "SCN-A"}'
  ```
* **Expected Result:** 
  1. Deterministic PRNG generates 5 sequential HTTP authentication attempts targeting `/admin/login` from source IP `192.168.56.105`.
  2. Data protection middleware redacts passwords to `[REDACTED]` with salted SHA-256 hashes.
  3. Events are persisted to `security_events` table.
* **Actual Result:** HTTP 200 OK: `{"status":"SUCCESS","scenario_id":"SCN-A","events_generated":5,"rule_triggered":"AUTH-001"}`.
* **Evidence Location:** SQLite/PostgreSQL `security_events` table; test `tests/test_demo_api.py::test_run_scenario_a`.

---

### Step 5: Threat Detection & Dual-Metric Scoring
* **Action:** Observe detection engine output.
* **Expected Result:**
  * Rule `AUTH-001` (Repeated Authentication Failures) fires because event count (5) $\ge$ threshold (3).
  * Severity calculated: **45 / 100** (Medium impact on web decoy).
  * Confidence calculated: **85 / 100** (High evidentiary certainty from 5 consecutive failures).
* **Actual Result:** Alert created in database: `ALT-AUTH-001-192.168.56.105`.
* **Evidence Location:** `backend/app/detection/engine.py`.

---

### Step 6: Real-Time SSE Notification Broadcast
* **Action:** Observe analyst browser interface.
* **Expected Result:** A live notification toast pops up in the top right corner without requiring manual browser page refresh.
* **Actual Result:** Server-Sent Event `alert_created` received over `/api/v1/stream/events`. Alert badge on sidebar updates from `0` to `1`.
* **Evidence Location:** Browser Network tab: `text/event-stream` stream active.

---

### Step 7: Evidence-Grounded MITRE ATT&CK Mapping
* **Action:** Navigate to [http://localhost:5173/mitre](http://localhost:5173/mitre).
* **Expected Result:** 
  * Cell for `T1110.001 (Password Guessing)` under `Credential Access` tactic illuminates with heat-map color.
  * Clicking the cell opens the detail drawer displaying mapped Rule `AUTH-001` and linking all 5 forensic events.
* **Actual Result:** Heatmap cell updates immediately; evidence records linked correctly.
* **Evidence Location:** `backend/app/modules/mitre/service.py`.

---

### Step 8: Session Correlation & Chronological Timeline
* **Action:** Navigate to [http://localhost:5173/sessions](http://localhost:5173/sessions).
* **Expected Result:** A session row for `192.168.56.105` appears showing 5 events, duration $< 60\text{ seconds}$, and target decoy `web_login`.
* **Actual Result:** Session Explorer displays complete event timeline with timestamp deltas.
* **Evidence Location:** `backend/app/correlation/service.py`.

---

### Step 9: Source Intelligence & Attacker Profiling
* **Action:** Navigate to [http://localhost:5173/sources](http://localhost:5173/sources) and click `192.168.56.105`.
* **Expected Result:** Attacker dossier displays Threat Score: **78 / 100**, Behavioral Tag: `BRUTE_FORCER`, and list of targeted endpoints.
* **Actual Result:** Dossier accurately renders aggregated tradecraft.
* **Evidence Location:** `backend/app/modules/source_intelligence/service.py`.

---

### Step 10: Alert Triage & Incident Case Creation
* **Action:** Navigate to [http://localhost:5173/alerts](http://localhost:5173/alerts), open the alert, and click **Start Investigation** $\to$ **Escalate to Case**.
* **Expected Result:**
  * Alert status transitions from `NEW` to `INVESTIGATING`.
  * Incident Case `#CASE-2026-001` is provisioned.
  * Analyst note appended: *"Initiating containment for brute-force probe on web decoy."*
  * Audit log records transition with analyst username.
* **Actual Result:** Case workspace opens with linked alert and session.
* **Evidence Location:** `backend/app/modules/response/service.py`.

---

### Step 11: Generating Defensive Containment (Firewall Block)
* **Action:** Inside Case `#CASE-2026-001`, open the **Defensive Actions** tab and click **Generate Firewall Block**.
* **Expected Result:** System generates copy-pasteable script:
  ```bash
  sudo iptables -A INPUT -s 192.168.56.105 -j DROP
  ```
* **Actual Result:** Script displayed in UI with one-click **Copy to Clipboard** button.
* **Evidence Location:** `backend/app/modules/response/service.py::generate_containment_action`.

---

### Step 12: Generating Executive Security Report
* **Action:** Navigate to [http://localhost:5173/reports](http://localhost:5173/reports) and click **Generate Report** (Type: `EXECUTIVE_SUMMARY`, Format: `PDF`).
* **Expected Result:**
  * System queries database metrics, compiles KPI tables, adds non-attribution disclaimer, and outputs downloadable PDF.
* **Actual Result:** Valid binary `%PDF-1.4` generated and downloaded in browser (size: ~12 KB).
* **Evidence Location:** `backend/app/modules/analytics/service.py::generate_report`.

---

### Step 13: Demonstration Cleanup with Retention Hold Verification
* **Action:** Click **Clean Demonstration Data** in `/demo`.
* **Expected Result:**
  * Unheld synthetic events are purged to reset the lab.
  * Case `#CASE-2026-001` (flagged with `retention_hold = True`) and its supporting events are **preserved** and remain intact.
* **Actual Result:** Cleanup purges temporary events while strictly preserving held evidence.
* **Evidence Location:** Test `tests/test_demo_api.py::test_demo_cleanup`.

