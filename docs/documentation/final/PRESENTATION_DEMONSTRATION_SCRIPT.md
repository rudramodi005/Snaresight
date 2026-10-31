# SnareSight: Live Demonstration Script & Presenter Runbook

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/PRESENTATION_DEMONSTRATION_SCRIPT.md`  
**Total Estimated Demonstration Time:** 6 Minutes 30 Seconds  

---

## 1. Pre-Demonstration Verification Checklist (T - 5 Minutes)

Before beginning your presentation, verify the local demonstration stack:
1. Ensure Docker Compose is active: `docker compose ps` (all 3 services healthy).
2. Open Google Chrome or Firefox to: `http://localhost:5173`.
3. Open a second tab to: `http://localhost:8000/docs` (Swagger UI fallback).
4. Verify you are logged in as `analyst@snaresight.local`.

---

## 2. Timed Demonstration Script (Stage by Stage)

### Stage 1: Situational Awareness & System Health (0:00 – 1:00)
* **Page to Open:** `http://localhost:5173/` (Overview Dashboard)
* **What to Say:**
  > *"To begin our live demonstration, we are viewing the SnareSight SOC Overview Dashboard. At the top banner, notice our real-time KPI cards: Mean Time to Detect is under 100 milliseconds, and all four decoy sensors report HEALTHY. In the lower panel, our Decoy Grid reflects live heartbeats streamed via Server-Sent Events. Everything you see is connected to a live FastAPI modular monolith and PostgreSQL 16 database."*
* **Action to Perform:** Hover over the Sensor Health status pills and point to the streaming connection indicator.
* **Evidence to Point Out:** Point to the real-time timestamp on the decoy health cards and the zero-lag status.
* **Claims to Avoid:** Do not claim the system has processed millions of real attacks; emphasize that this is an isolated, high-fidelity deception lab.

---

### Stage 2: Triggering Synthetic Scenario A (1:00 – 2:15)
* **Page to Open:** Click **Demonstration Lab** in sidebar (`/demo`).
* **What to Say:**
  > *"Rather than relying on pre-recorded videos or mock screens, SnareSight features an integrated Demonstration Lab. We will now execute Scenario A: Web Login Brute Force. In this scenario, a simulated attacker from IP 192.168.56.105 sends 5 rapid failed login attempts to our web decoy."*
* **Action to Perform:** Click **Run Scenario A** button.
* **Expected Outcome:** 
  * The button turns into a brief loading spinner.
  * A green success banner displays: `Scenario A executed: 5 events generated, Rule AUTH-001 triggered`.
  * Instantly, a toast notification pops up in the top right corner: `New High Confidence Alert: Repeated Authentication Failures`.
* **Evidence to Point Out:** Point out that the alert appeared **without a browser refresh** because the backend pushed the event over the SSE stream.
* **What to Do If Step Fails:** If the network proxy hangs, open Terminal and execute the fallback curl command:
  ```bash
  curl -X POST "http://127.0.0.1:8000/api/v1/demo/scenarios/run" -H "Content-Type: application/json" -d '{"scenario_id":"SCN-A"}'
  ```

---

### Stage 3: Alert Triage & Dual Scoring Inspection (2:15 – 3:30)
* **Page to Open:** Click **Alerts** in sidebar (`/alerts`).
* **What to Say:**
  > *"Now let's switch to the SOC Analyst's triage queue. Here is our newly generated alert: 'Repeated Authentication Failures' from IP 192.168.56.105. 
  > Notice our dual-scoring engine: Severity is scored at 45 (Medium impact because it targeted a web decoy), while Confidence is scored at 85 (High certainty because 5 consecutive failed attempts exceeded our rule threshold).
  > Let's open the forensic drawer. Notice that under our Zero-Password Storage Invariant, the attacker's attempted passwords are automatically redacted to [REDACTED], while a salted SHA-256 hash is preserved for cluster analysis. We will now acknowledge the alert and transition its status to INVESTIGATING."*
* **Action to Perform:** Click on the alert row to open the drawer; click **Acknowledge**, then **Start Investigation**.
* **Evidence to Point Out:** Show the redacted password field and the audit log entry recording the analyst username and transition timestamp.

---

### Stage 4: MITRE ATT&CK Matrix Verification (3:30 – 4:30)
* **Page to Open:** Click **MITRE ATT&CK** in sidebar (`/mitre`).
* **What to Say:**
  > *"Next, we inspect our evidence-grounded MITRE ATT&CK matrix. Under the Credential Access tactic, technique T1110.001 (Password Guessing) is now highlighted. 
  > Unlike platforms that apply speculative tags, SnareSight enforces forensic lineage. Clicking this technique shows the formal MITRE definition, our active detection rule AUTH-001, and links directly to the 5 raw forensic events that proved the technique occurred."*
* **Action to Perform:** Click the illuminated `T1110.001` cell; scroll down the side panel to reveal the linked event records.
* **Evidence to Point Out:** Show the explicit `Evidence Count: 5` and the exact HTTP POST timestamps.

---

### Stage 5: Session Correlation & Attack-Chain Graph (4:30 – 5:30)
* **Page to Open:** Click **Attack Chains** in sidebar (`/attack-chains`).
* **What to Say:**
  > *"To understand intruder progression, we open the Attack Chain visualizer. Powered by React Flow, this interactive directed acyclic graph renders the intruder's journey. 
  > If we look at Scenario F, which simulates a multi-phase intrusion, we observe the attacker progressing from Initial Reconnaissance, through Credential Probing, to Directory Traversal and Execution. We can drag, zoom, and inspect individual nodes to view the forensic payload that triggered each phase."*
* **Action to Perform:** Drag the graph nodes; click a node to highlight its connected edges and event attributes.
* **Evidence to Point Out:** Point to the chronological edges connecting Tactics in temporal sequence.

---

### Stage 6: Case Containment & Defensive Response (5:30 – 6:30)
* **Page to Open:** Click **Case Management** (`/cases`).
* **What to Say:**
  > *"Finally, we demonstrate defensive incident response. Inside our incident case for 192.168.56.105, we have enabled a Legal Retention Hold, ensuring our background pruning job never deletes this evidence.
  > Under Defensive Actions, the analyst clicks 'Generate Firewall Block'. The system immediately outputs copy-pasteable firewall commands for iptables and UFW. We have closed the loop from initial decoy interaction to active perimeter containment in under six minutes."*
* **Action to Perform:** Click **Generate Firewall Block**; click **Copy Script**.
* **Evidence to Point Out:** Show the generated `sudo iptables -A INPUT -s 192.168.56.105 -j DROP` command.
* **Closing Statement:**
  > *"This concludes our live demonstration. We have proven that SnareSight is a working, tested, and fully integrated platform. We welcome your questions."*

---

## 3. Fallback Demonstration Dataset Disclosure

If the local demonstration host experiences an unexpected power loss or virtualization network disruption:
* **Fallback Mode:** Start backend with SQLite in-memory fixture:
  ```bash
  python -m pytest tests/test_demo_api.py -v
  ```
* **Disclosure Notice:** State clearly to reviewers: *"We are running our verified automated test fixtures, which execute the identical synthetic scenarios against an in-memory SQLite relational database."*

