# SnareSight Demonstration Lab — Operational Runbook

**Document ID:** DOC-DEMO-006  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Phase:** 8 — Testing, Demonstration & Evaluation (P36 / 40)  
**Date:** October 31, 2026  
**Target Audience:** Evaluators, Security Architects, SOC Analysts  

---

## 1. Prerequisites & Environment Setup

### 1.1 Backend Service
From the repository root:
```powershell
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify gateway heartbeat:
```powershell
curl http://127.0.0.1:8000/
# Expected: {"platform":"SnareSight","status":"OPERATIONAL","api_version":"v1"}
```

### 1.2 Frontend Dashboard
From the repository root:
```powershell
cd frontend
npm run dev
```
Open browser to `http://localhost:5173`.

---

## 2. Step-by-Step Demonstration Walkthrough

### Step 1: Login to Platform
1. Navigate to `http://localhost:5173/login`.
2. Authenticate using pre-seeded SOC credentials:
   - **Role:** `ANALYST` or `ADMIN`
   - **Username:** `admin` or `analyst`

### Step 2: Access the Demonstration Lab
1. In the left navigation sidebar, click **Demonstration Lab** (`🧪 /demo`).
2. Observe the prominent amber banner indicating **ISOLATED LAB DATA ONLY**.

### Step 3: Run Scenario A (Repeated Login Failures)
1. In the Scenario Grid, click **Scenario A: Repeated Login Failures**.
2. Select Scale: **Small (~25 events)**.
3. Keep Seed: **42**.
4. Click **Launch Synthetic Scenario**.
5. Observe live outcome:
   - Status: `SUCCESS`
   - Generated: `25`, Accepted: `25`, Rejected: `0`
   - Alerts Created: `1` (`AUTH-001`)
   - Duration: `< 300 ms`

### Step 4: Inspect Resulting Alert in SOC Alert Center
1. Click the quick navigation pill **🚨 Alert Management** (`/alerts`).
2. Observe the new explainable alert titled **Repeated Authentication Failures**.
3. Click the alert to view triggering observations, session timeline, and MITRE T1110 technique mapping.

### Step 5: Run Scenario E (End-to-End Analyst Investigation)
1. Return to **🧪 Demonstration Lab** (`/demo`).
2. Select **Scenario E: Analyst Investigation & Response Case**.
3. Click **Launch Synthetic Scenario**.
4. Note the escalated case banner indicating case creation and active **Evidence Preservation Hold**.
5. Click **View in Response Center →** (`/response`) to review case timeline, analyst triage note, and retention lock status.

### Step 6: Verify Detection Quality Evaluation
1. Return to **🧪 Demonstration Lab** (`/demo`).
2. Scroll to the **Threat Detection Quality & Benchmark Evaluation** section.
3. Observe real-time KPI bars:
   - Precision: `100.0%`
   - Recall: `100.0%`
   - F1 Score: `100.0%`
   - Mean Latency: `~5-10 ms/event`
4. Inspect the per-rule breakdown table.

### Step 7: Demonstration Telemetry Management & Safe Cleanup
1. In the **Telemetry Export & Clean** card, click **🔍 Audit Records**.
2. Note the dry-run summary: counts synthetic events found, records protected by active retention holds, and records eligible for deletion.
3. Click **🗑️ Safe Demo Cleanup** and confirm.
4. Verify that eligible demo events are purged while records linked to active evidence holds remain safely preserved.

### Step 8: Export Demonstration Report
1. Click **📥 Export JSON**.
2. Save and inspect the exported file, noting the watermark `SYNTHETIC DEMONSTRATION DATA - NOT REAL INCIDENT`.

