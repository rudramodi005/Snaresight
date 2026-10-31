# SnareSight: Project Handover Dossier & Evaluator Guide

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Target Audience:** Academic Mentors, Project Reviewers, Technical Evaluators, and Successor Maintainers  

---

## 1. Executive Summary & Purpose

This document serves as the formal handover dossier for **SnareSight**, a browser-based Deception-Driven Threat Detection and Security Operations Platform. 

Developed across 8 comprehensive engineering phases (Prompts 01 through 38), SnareSight addresses the critical challenge of alert fatigue in modern cybersecurity operations. By deploying isolated honeypots within private virtual network perimeters, SnareSight converts unauthorized adversary interaction into high-fidelity, actionable threat intelligence.

This dossier provides reviewers and evaluators with a complete verification pathway, summarizing system architecture, implemented capabilities, empirical evaluation results, design trade-offs, and future roadmap opportunities.

---

## 2. Inventory of Implemented Core Modules

The platform is delivered as a production-ready, fully integrated **modular monolith** consisting of 15 subsystems:

| # | Subsystem Module | Codebase Location | Primary Functionality & Value |
|---|---|---|---|
| **1** | **Sensor Management** | `backend/app/modules/sensors/` | Manages honeypot fleet, credentials rotation, and heartbeat monitoring. |
| **2** | **Telemetry Ingestion** | `backend/app/api/ingestion.py` | Authenticated intake (`X-Sensor-Key`), Pydantic schema validation. |
| **3** | **Data Protection** | `backend/app/detection/field_registry.py` | Enforces Zero-Password invariant (salted SHA-256 password hashing). |
| **4** | **Detection Engine** | `backend/app/detection/` | 10 catalogue detection rules evaluated over temporal sliding windows. |
| **5** | **Scoring Engine** | `backend/app/detection/scoring_policy.py` | Independent Severity (0–100) and Confidence (0–100) calculations. |
| **6** | **Session Correlation** | `backend/app/correlation/` | Clusters individual events into intruder sessions by source IP & time. |
| **7** | **Attack Chain Graph** | `frontend/src/pages/AttackChains/` | Directed acyclic graph (React Flow) visualizing multi-stage intrusions. |
| **8** | **MITRE ATT&CK** | `backend/app/modules/mitre/` | Evidence-grounded technique mapping and interactive Enterprise matrix. |
| **9** | **Source Intelligence** | `backend/app/modules/source_intelligence/`| Dossiers on attacker IPs, behavioral tags, and similarity clustering. |
| **10**| **Campaign Intelligence**| `backend/app/modules/campaign_intelligence/`| Heuristic grouping of related intrusion sessions across multi-IP sweeps. |
| **11**| **Incident Cases** | `backend/app/modules/response/` | Full case workspace, investigation notes, and defensive containment. |
| **12**| **SOC Analytics** | `backend/app/modules/analytics/` | Executive KPIs, MTTD tracking, and exportable reports (JSON/Markdown). |
| **13**| **Security & Audit** | `backend/app/modules/security/` | RBAC (`admin`, `analyst`, `auditor`) and append-only audit logs. |
| **14**| **Operational Resilience**| `backend/app/modules/resilience/` | Self-healing, automated backups, and isolated dry-run restore tests. |
| **15**| **Demonstration Lab** | `backend/app/modules/demo/` | Self-contained `/demo` lab executing 6 deterministic attack scenarios. |

---

## 3. Evaluator Quick-Start Verification Checklist

To independently evaluate and verify SnareSight in under 10 minutes:

### Step 1: Environment Startup
```bash
# Clone and enter repo
cd SnareSight

# Quickstart via Docker Compose (Recommended)
docker compose up --build -d

# Verify containers are healthy
docker compose ps
```
* **Expected Result:** `snaresight-db`, `snaresight-backend`, and `snaresight-frontend` all report `healthy`.

### Step 2: Accessing the Dashboard
* Open your browser to [http://localhost](http://localhost) (or port 80/5173).
* Login with analyst credentials:
  * Username: `analyst@snaresight.local`
  * Password: `SecurePassword123!`

### Step 3: Executing the Demonstration Scenarios
1. Click **Demonstration Lab** (`/demo`) in the left navigation sidebar.
2. Under **Scenario A (Web Login Brute Force)**, click **Execute Scenario**.
3. Observe real-time progress:
   * 5 synthetic HTTP authentication events are generated deterministically.
   * Event normalizer applies salted SHA-256 redaction to password fields.
   * Rule `AUTH-001` evaluates the 3-attempt threshold and fires an alert.
   * Real-time toast notification appears in the dashboard via SSE.
4. Click **Evaluate Detection Quality**:
   * Evaluates engine performance across scenarios:
   * **Precision:** 100% (Zero false positives in honeypot telemetry).
   * **Recall:** 100% (All 6 scenarios correctly detected by catalogue rules).
   * **F1-Score:** 1.000.

### Step 4: Reviewing Containment & Forensics
1. Navigate to **Alerts** and open the newly created alert.
2. Click **Start Investigation** $\to$ **Escalate to Case**.
3. Under **Defensive Actions**, click **Generate Firewall Block**.
4. Observe the generated `iptables` and `UFW` rules.

---

## 4. Key Architectural Trade-Offs & Non-Goals

To maintain design integrity and academic focus, specific engineering decisions were made:

1. **Modular Monolith vs Microservices:**
   * *Decision:* Monolithic FastAPI codebase with strict modular boundaries.
   * *Trade-Off:* Simpler local setup, zero network serialization latency, unified PostgreSQL transactions. Avoids the operational overhead of running 10 separate microservice containers.
2. **Server-Sent Events (SSE) vs WebSockets:**
   * *Decision:* SSE utilized for real-time telemetry updates.
   * *Trade-Off:* Unidirectional push over HTTP/1.1 or HTTP/2 avoids stateful socket handshakes, integrates natively with browser `EventSource`, and easily passes through corporate firewalls.
3. **No Active Exploitation / Hack-Backs:**
   * *Decision:* Strictly defensive containment (firewall rule export).
   * *Trade-Off:* Prevents legal liability and avoids rogue port scanning from the honeypot host.

---

## 5. Future Roadmap & Enhancement Opportunities

For subsequent development teams or academic research extensions:

* **Distributed Agent Fleet:** Enhance forwarder agents with mutual TLS (mTLS) for deployment across distributed public cloud regions.
* **STIX 2.1 & TAXII Export:** Implement standardized threat intelligence feed publishing to allow external SIEMs (Splunk, Microsoft Sentinel) to pull SnareSight threat actor profiles.
* **Automated Firewall API Push:** Add direct webhook connectors to push generated IP blocks directly to Cloudflare, AWS WAF, or Palo Alto PAN-OS APIs upon analyst approval.
* **Expanded Decoy Catalogue:** Add dedicated high-interaction decoy modules for Redis, Kubernetes API, and Active Directory LDAP.

---

## 6. Project Artifacts & Authoritative Links

* **Source Code:** [Frontend](file:///c:/Projects/SnareSight/frontend) | [Backend](file:///c:/Projects/SnareSight/backend)
* **Master Documentation Index:** [docs/README.md](file:///c:/Projects/SnareSight/docs/README.md)
* **Developer Setup Guide:** [DEVELOPER_SETUP_GUIDE.md](file:///c:/Projects/SnareSight/docs/documentation/DEVELOPER_SETUP_GUIDE.md)
* **System Architecture:** [SYSTEM_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/documentation/SYSTEM_ARCHITECTURE.md)
* **Complete API Reference:** [API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/documentation/API_REFERENCE.md)
* **Database Reference:** [DATABASE_REFERENCE.md](file:///c:/Projects/SnareSight/docs/documentation/DATABASE_REFERENCE.md)
* **SOC Analyst User Manual:** [SOC_ANALYST_USER_MANUAL.md](file:///c:/Projects/SnareSight/docs/documentation/SOC_ANALYST_USER_MANUAL.md)
* **Administrator Guide:** [ADMINISTRATOR_GUIDE.md](file:///c:/Projects/SnareSight/docs/documentation/ADMINISTRATOR_GUIDE.md)

