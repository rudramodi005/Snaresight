# SnareSight: Final Demonstration Runbook & Presentation Guide (P40)

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover (Final Prompt 40/40)  
**Document:** `docs/final/P40_FINAL_DEMONSTRATION_RUNBOOK.md`  
**Classification:** Operational Demonstration Runbook  
**Date:** October 2026  

---

## 1. Demonstration Protocol & Ethics

This runbook guides a presenter through an end-to-end live demonstration of SnareSight using the integrated **Demonstration Lab** (`/demo`).

### Non-Negotiable Demonstration Rules:
1. **Never Claim Synthetic Data is Real:** All demonstration activity must be introduced as synthetic, controlled lab telemetry.
2. **Never Claim IP Attribution is Personal Identity:** Emphasize that source IP dossiers represent network behavior clusters, not verified human individuals.
3. **Comply with Lab Isolation:** Decoys must run in host-only / private virtual switches. Zero bridged public networking.

---

## 2. Step-by-Step 17-Stage Demonstration Runbook

### Stage 1: Starting the Application
Launch the backend and frontend using Docker Compose (or native terminals):
```bash
# Option A: Docker Compose (Recommended)
docker compose up -d

# Option B: Native Host Terminals
# Terminal 1 (Backend): cd backend && .\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000
# Terminal 2 (Frontend): cd frontend && npm run dev
```

### Stage 2: Verifying System Health
Verify that the backend and database are operational:
```bash
curl http://127.0.0.1:8000/health
# Response: {"platform":"SnareSight","status":"OPERATIONAL","api_version":"v1"}
```

### Stage 3: Accessing the Dashboard & Authentication
1. Open Google Chrome or Firefox to: `http://localhost:5173`.
2. Login with verified analyst credentials:
   * **Username:** `analyst@snaresight.local`
   * **Password:** `SecurePassword123!`
3. Observe the **Overview Dashboard** with real-time KPI cards.

### Stage 4: Resetting the Demonstration Environment
1. In the sidebar, click **Demonstration Lab** (`/demo`).
2. Click **Clean Demonstration Data** to purge unheld temporary records and ensure a pristine test queue.

### Stage 5: Executing Scenario A (Web Login Brute Force)
1. In the Demonstration Lab, locate the card for **Scenario A (Web Login Brute Force)**.
2. Click **Execute Scenario**.
3. Observe the progress spinner: 5 deterministic HTTP authentication attempts are generated targeting `/admin/login` from IP `192.168.56.105`.

### Stage 6: Observing Real-Time Telemetry Ingestion
1. The ingestion gateway validates the batch payload and checks the sensor key.
2. Normalization middleware redacts passwords to `[REDACTED]` with salted SHA-256 hashes.
3. Events are committed to the PostgreSQL `security_events` table.

### Stage 7: Reviewing Generated Detections & Rule Firing
1. The detection engine evaluates Rule `AUTH-001` (Repeated Authentication Failures).
2. Because event count (5) $\ge$ threshold (3), the rule triggers.

### Stage 8: Reviewing Decoupled Severity & Confidence Scores
1. Observe the dual scores computed on the alert:
   * **Severity Score:** `45 / 100` (Medium impact on corporate web decoy).
   * **Confidence Score:** `85 / 100` (High certainty from 5 consecutive failures).

### Stage 9: Observing Real-Time SSE Dashboard Push
1. Without refreshing the browser, a toast notification appears in the top right:
   * *"New High-Confidence Alert: Repeated Authentication Failures from 192.168.56.105"*.
2. The active alerts badge on the sidebar updates from `0` to `1`.

### Stage 10: Inspecting Evidence-Grounded MITRE ATT&CK Mapping
1. Click **MITRE ATT&CK** in the sidebar (`/mitre`).
2. The cell for `T1110.001 (Password Guessing)` under `Credential Access` illuminates with heat-map color.
3. Click the cell to open the side panel: review the formal ATT&CK description, mapped detection rule `AUTH-001`, and the 5 linked forensic event records.

### Stage 11: Opening Session Timelines
1. Click **Sessions** in the sidebar (`/sessions`).
2. Open the newly formed session for `192.168.56.105`.
3. Review the chronological event timeline showing timestamp deltas and target ports.

### Stage 12: Reviewing Threat Actor Profiling
1. Click **Threat Profiles** in the sidebar (`/sources`) and select `192.168.56.105`.
2. Inspect the dossier: Threat Score (`78 / 100`), Behavioral Tag (`BRUTE_FORCER`), and targeted honeypot list.

### Stage 13: Reviewing Multi-Stage Attack Chains (Scenario F)
1. In `/demo`, click **Execute Scenario F (Multi-Stage Intrusion)**.
2. Navigate to **Attack Chains** (`/attack-chains`).
3. An interactive React Flow directed acyclic graph renders the 4-phase intrusion narrative:
   $$\text{Reconnaissance (T1595)} \longrightarrow \text{Discovery (T1083)} \longrightarrow \text{Credential Access (T1110)} \longrightarrow \text{Execution (T1059)}$$
4. Drag and click nodes to highlight event details.

### Stage 14: Triaging Alerts & Adding Analyst Notes
1. Click **Alerts** (`/alerts`) and open the brute-force alert.
2. Click **Acknowledge**, then **Start Investigation**.
3. In the triage drawer, append an analyst note: *"Confirmed automated dictionary attack against web decoy. Escalating to formal case."*

### Stage 15: Incident Case Creation & Defensive Containment
1. Click **Escalate to Case** (creates Case `#CASE-2026-001`).
2. Toggle **Legal Retention Hold = True** to protect evidence from automated pruning.
3. Open the **Defensive Actions** tab and click **Generate Firewall Block**.
4. Review the generated commands:
   * **iptables:** `sudo iptables -A INPUT -s 192.168.56.105 -j DROP`
   * **UFW:** `sudo ufw deny from 192.168.56.105 to any`
5. Click **Copy Script**.

### Stage 16: Generating & Downloading Executive Report
1. Click **Reports** (`/reports`) and select **Generate Report** (Type: `EXECUTIVE_SUMMARY`, Format: `PDF`).
2. The backend compiles KPI metrics, detection distributions, and non-attribution notices.
3. The browser downloads the valid `%PDF-` report file.

### Stage 17: Safely Concluding the Demonstration
1. Return to `/demo` and click **Evaluate Detection Quality**.
2. Review the final quality metrics: **Precision: 100%, Recall: 100%, F1: 1.000**.
3. Conclude by demonstrating that clicking **Clean Demonstration Data** purges temporary events while strictly preserving held evidence in `#CASE-2026-001`.

---

## 3. Fallback Demonstration Procedure (In Case of Network Outage)

If the local demonstration machine experiences an unexpected container disruption:
1. Open PowerShell terminal:
   ```powershell
   cd c:\Projects\SnareSight\backend
   .\.venv\Scripts\pytest.exe tests/test_demo_api.py -v
   ```
2. Clearly disclose to reviewers:
   > *"Due to a local environment interruption, we are executing our verified automated test fixtures, which run the exact same 6 synthetic attack scenarios against an in-memory relational SQLite engine and verify 100% precision and recall."*

