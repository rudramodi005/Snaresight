# SnareSight: Frontend Architecture & UI Design System
**Document ID:** ARCH-007  
**Status:** Approved Frontend Specification  

---

## 1. Technical Framework & Styling Baseline

* **Framework:** React 18 / 19 with TypeScript in strict mode.
* **Build System:** Vite (fast HMR and optimized production bundles).
* **Styling Engine:** Tailwind CSS with a cohesive cybersecurity-themed dark palette (slate/zinc dark backgrounds, semantic accent indicators for severity).
* **Iconography:** Lucide React (clean, accessible SVG icons).
* **Data Visualization:**
  * **Recharts:** Event timeline distributions, severity breakdowns, and decoy traffic comparisons.
  * **React Flow:** Interactive, directed graph rendering of multi-stage attack chains.
* **Real-Time Client:** Native browser `EventSource` API consuming Server-Sent Events (SSE).

---

## 2. Navigation & Layout Hierarchy

```
+-----------------------------------------------------------------------------------+
|  Header Bar: [SnareSight Logo] [Active Decoys: 2] [Status: OK] [Live Indicator] [Profile] |
+-----------------------+-----------------------------------------------------------+
| Sidebar Navigation    | Main Workspace Area                                       |
|                       |                                                           |
| 1. Overview           | [ Executive Metric Cards: Total Events, High Alerts, etc ]|
| 2. Honeypot Decoys    |                                                           |
| 3. Live Event Feed    | [ Recharts: 24h Attack Progression Timeline ]             |
| 4. Alert Center       |                                                           |
| 5. Attack Chains      | [ React Flow: Visual Intrusion Graph ]                    |
| 6. Source Profiles    |                                                           |
| 7. ATT&CK Explorer    | [ Interactive MITRE Coverage Matrix ]                     |
| 8. Investigations     |                                                           |
| 9. Reporting          | [ Active Case Triage & Analyst Investigation Notes ]      |
| 10. System Health     |                                                           |
+-----------------------+-----------------------------------------------------------+
```

---

## 3. Core Page Specifications

1. **Overview Page (`/`):**
   * High-level SOC situational awareness: active decoys, 24h event velocity, critical alerts counter, and top targeted protocols.
2. **Honeypot Management (`/honeypots`):**
   * Decoy inventory cards showing operational state (`ONLINE`, `OFFLINE`), virtual IP, active port, and last heartbeat timestamp.
3. **Live Event Explorer (`/events`):**
   * Filterable tabular view of normalized events with live auto-refresh toggle, timestamp search, and drawer for inspecting raw JSON payloads.
4. **Alert Center (`/alerts`):**
   * Triage view sorting alerts by severity (Critical, High, Medium, Low) and confidence. One-click escalation to investigation.
5. **Attack-Chain Visualizer (`/attack-chains`):**
   * React Flow canvas visualizing intruder progression from initial reconnaissance probe to decoy compromise. Nodes represent events; edges represent temporal or session linkage.
6. **MITRE ATT&CK Matrix (`/mitre`):**
   * Interactive grid mapping observed techniques against the 14 Enterprise ATT&CK tactics, color-coded by detection frequency.
7. **Investigations Workspace (`/investigations`):**
   * Analyst notebook interface for writing case notes, reviewing chained evidence, and exporting incident reports.
8. **System Health (`/health`):**
   * Component latency, database pool status, ingestion throughput, and decoy heartbeat indicators.

---

## 4. UI State Management & Data Policy

* **No False Data Fabrication:** The frontend will **never** synthesize metrics or invent detection results in local client state. All counts, graphs, and statuses are derived directly from backend REST queries and validated SSE events.
* **Clear Provenance Indicators:** Badges explicitly mark data as `[LIVE HONEYPOT]`, `[SYNTHETIC DEMO]`, or `[LAB SIMULATION]`.
* **State Management Strategy:** React Query (`@tanstack/react-query`) or custom lightweight hooks for server state caching, paired with localized component state for UI controls.

