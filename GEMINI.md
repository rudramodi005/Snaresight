# AGENTS.md — Project Instructions & Rules for Google Antigravity
# Project: SnareSight — Deception-Driven Threat Detection & SOC Platform

This document serves as the authoritative, persistent instruction manual for Google Antigravity and any AI assistant operating within the SnareSight project. All instructions, constraints, and architecture rules defined here are mandatory and active across all sessions.

---

## 1. Project Identity & Mission

* **Official Project Name:** SnareSight
* **Project Title:** Deception-Driven Threat Detection and Security Operations Platform
* **Mission Objective:** SnareSight is a deception-driven cybersecurity platform designed to deploy and monitor honeypot decoys, capture suspicious adversary interactions, normalize security events, detect malicious behavior via explainable rules, correlate related events into attack chains, map verified observations to MITRE ATT&CK, and present real-time telemetry through a professional SOC dashboard.
* **Core Philosophy:** Every feature must serve deception-driven detection and defensive operations. SnareSight is not a generic dashboard; it is a specialized security operations platform.

---

## 2. Core Capabilities & Scope Boundaries

SnareSight provides the following capabilities:
1. **Honeypot Management:** Isolated web-login decoys initially, with modular integration for SSH (Cowrie).
2. **Decoy Interaction Monitoring:** Real-time capture of interaction telemetry, credential stuffing, and probe attempts.
3. **Security Event Collection & Ingestion:** High-integrity, structured intake of security logs.
4. **Event Normalization & Schema Enforcement:** Unified event format preserving raw evidence and timestamps.
5. **Session Tracking & Provenance:** Associating interactions by session, IP, and fingerprint with strict data provenance.
6. **Rule-Based Threat Detection:** Explainable, deterministic detection rules evaluating attacker behavior.
7. **Severity & Confidence Scoring:** Separate assessment of impact (severity) and certainty (confidence).
8. **Event Correlation & Attack Chains:** Graphing multi-stage intrusions across decoys and timelines.
9. **Evidence-Based MITRE ATT&CK Mapping:** Grounded mapping to ATT&CK tactics and techniques.
10. **Observed Source Activity Profiles:** Pseudonymous profiling of adversary IP patterns and behaviors.
11. **IOC Extraction:** Automated parsing of IP addresses, hashes, payloads, and user-agent strings.
12. **Investigation Management:** Analyst workflows, notes, tagging, and case management.
13. **Defensive Recommendations:** Actionable hardening advice derived from detected adversary tactics.
14. **Security Reporting & Metrics:** Automated summaries of decoy traffic, top targeted decoys, and attacker metrics.
15. **System Health & Decoy Monitoring:** Health checks, pipeline latency, and decoy availability telemetry.

---

## 3. Approved Technology Stack

The following technology stack is officially approved. No substitution is permitted without empirical justification:

* **Frontend:** React, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts (charts), React Flow (attack-chain graph).
* **Backend:** Python, FastAPI, Pydantic (validation & schemas), SQLAlchemy (ORM), Alembic (migrations).
* **Database:** PostgreSQL (relational event and detection store).
* **Live Updates:** Server-Sent Events (SSE) for real-time telemetry streaming to the dashboard.
* **Testing:** Pytest (backend unit/integration), Vitest (frontend unit), Playwright (end-to-end SOC testing).
* **Version Control:** Git (local repository with strict `.gitignore` and private remote).
* **Decoys & Honeypots:** Isolated web-login decoy application; optional modular Cowrie SSH honeypot.
* **Deployment & Isolation:** Windows 11 host (development IDE, frontend, backend API) with an isolated Linux VM/container environment (WSL 2 / Docker internal network) for operational decoys.

---

## 4. Mandatory Project Rules

### Rule A: Project Scope Rule
SnareSight must strictly remain a deception-driven threat detection platform. Every module, route, and UI view must directly contribute to honeypot monitoring, event collection, behavioral analysis, attack-chain visualization, ATT&CK mapping, or analyst investigation. Unrelated security features must not be introduced.

### Rule B: Source-of-Truth Rule
The approved project roadmap and requirements are the primary authority. Never invent, alter, or silently drop requirements. If any requirement is ambiguous, seek explicit user confirmation before proceeding.

### Rule C: Architecture Rule
Adhere strictly to the approved technology stack. Do not replace FastAPI, React, PostgreSQL, or other core technologies without explicit justification and user approval.

### Rule D: Modular Design Rule
Maintain clean separation of concerns:
* Frontend (UI components, API clients, state management)
* Backend API (REST endpoints, SSE streaming, authentication)
* Event Ingestion & Normalization (decoy adapters, schema validation)
* Detection & Correlation Engine (rule evaluation, attack-chain generation)
* Database Layer (SQLAlchemy models, Alembic migrations)
* Decoy Services (isolated honeypot targets)
Do not combine disparate concerns into monolithic files. Avoid unnecessary microservice over-engineering.

### Rule E: Data Integrity & Provenance Rule
All security data must carry clear provenance:
* Distinguish `live_honeypot`, `synthetic_demo`, `controlled_simulation`, and `enriched` events.
* Record event occurrence timestamp (`event_timestamp`) and ingestion timestamp (`ingested_at`) separately.
* Never fabricate evidence or claim simulated data is live without explicit labeling.
* Preserve raw event payloads alongside normalized records.

### Rule F: Threat Detection Rule
Use explainable, rule-based logic for primary threat detection. Every generated alert must include:
* Unique Detection Rule ID and Rule Version.
* Triggering event identifiers (traceable evidence).
* Human-readable explanation of why the rule fired.
* Separate Severity (Low/Medium/High/Critical) and Confidence (Low/Medium/High) scores.
* Associated session ID and targeted decoy ID.
* Prescribed analyst investigation steps.

### Rule G: MITRE ATT&CK Mapping Rule
Map adversary activity only to officially documented MITRE ATT&CK techniques with direct evidentiary support. Store technique IDs (e.g., `T1110.001 - Password Guessing`) and supporting event references. Never claim full framework coverage; map only supported decoy observations.

### Rule H: Investigation Traceability Rule
Ensure unbroken end-to-end traceability across the security lifecycle:
`Raw Event -> Normalized Event -> Detection -> Alert -> Attack Chain -> Investigation Case -> Final Report`.

### Rule I: Frontend & SOC UI Rule
Build a professional, distraction-free Security Operations Center interface:
* Clean visual hierarchy, consistent dark/light cyber-themed styling, and clear status indicators.
* Prohibit fake counters, nonfunctional buttons, permanent placeholder mockups, and excessive decorative animations.
* All dashboard widgets must reflect live backend data or clearly marked demonstration datasets.

### Rule J: Backend Engineering Rule
* Enforce Python type hints across all backend functions.
* Validate all request and ingestion payloads using Pydantic schemas.
* Implement centralized exception handling and structured JSON logging.
* Never trust unvalidated input from decoy endpoints.

### Rule K: Database Rule
* Maintain referential integrity (primary keys, foreign keys, cascade constraints, and indexes).
* Track schema changes exclusively through Alembic migration scripts.
* Never drop raw event history during normalization.
* Never store plaintext honeypot passwords or sensitive tokens.

### Rule L: Security & Lab Isolation Rule (CRITICAL)
1. **Zero Internet Exposure:** Never expose honeypot decoys, test endpoints, or the database to the public Internet during development.
2. **No Bridged Networking:** Never configure bridged network adapters for the honeypot environment. Decoys must remain strictly on isolated host-only, NAT, or internal Docker bridge interfaces (`127.0.0.1` or internal subnet).
3. **Host Defense Integrity:** Never disable or alter Windows Defender or Windows Firewall.
4. **No Execution of Captured Malware:** Never execute payloads or commands collected from decoy interactions.
5. **Zero Hardcoded Secrets:** Never store passwords, API keys, or private tokens in source code or version control.
6. **Approval Required:** Obtain explicit user confirmation before running system-modifying or administrative commands.

### Rule M: Testing & Verification Rule
Every feature must be verified with tests:
* Pytest for backend logic, rules, and database models.
* Vitest for frontend components and data transformations.
* Playwright for critical SOC dashboard end-to-end workflows.
* Never claim a test passed without empirical execution proof. Never suppress test failures.

### Rule N: Documentation Rule
Maintain synchronized documentation for architecture, API schemas, detection rules, and deployment instructions. Update documentation immediately when code changes affect behavior.

### Rule O: Code Quality Rule
Write readable, idiomatic, and maintainable code. Avoid giant source files, dead code, duplicated logic, and unexplained magic numbers.

---

## 5. Antigravity Agent Working Protocol

Every future AI session must strictly adhere to this three-stage protocol:

### Phase 1: Before Implementation
1. Review the current phase, task number, and user instructions.
2. Inspect affected codebase files and verify prerequisites.
3. Formulate and clearly explain the proposed implementation plan.
4. Highlight security and isolation implications.
5. Identify the exact files to be created or modified.
6. Define explicit acceptance criteria.

### Phase 2: During Implementation
1. Follow established architecture and keep code modular.
2. Make focused edits; avoid sweeping, unrelated changes.
3. Validate inputs, handle edge cases, and preserve existing working features.
4. Adhere strictly to the security constraints (localhost binding, no hardcoded secrets).

### Phase 3: After Implementation
1. Inspect all created or modified files.
2. Execute tests and verify actual runtime behavior.
3. Check for regressions in previously working modules.
4. Provide a clear summary of what was completed and what remains for future tasks.
5. Suggest a concise, descriptive Git commit message.
6. Await the user's explicit command before advancing to the next task.

---

## 6. Official Phased Roadmap

* **PHASE 1 — Project Foundation & Windows Setup**
  * `P01`: Windows System and Hardware Assessment (Completed)
  * `P02`: Install and Verify Development Tools (Completed)
  * `P03`: Configure Antigravity and Project Rules (Current Task)
  * `P04`: Architecture, Repository & Security Boundaries
  * `P05`: Initialize Git, Documentation & Project Skeleton
* **PHASE 2 — Lab Isolation & Honeypot Engine**
  * `P06`: Isolated VM & Network Design
  * `P07`: VM, Firewall & Resource Controls
  * `P08`: Isolation Verification & Emergency Shutdown
  * `P09`: Web-Login Decoy Implementation
  * `P10`: Decoy Telemetry Validation
* **PHASE 3 — Event Pipeline & Database Architecture**
  * `P11`: Event Schemas & Ingestion Contracts
  * `P12`: PostgreSQL Setup & Alembic Migrations
  * `P13`: Secure Ingestion Pipeline
  * `P14`: Normalization, Deduplication & Retention
  * `P15`: Live SSE Updates & Pipeline Health Telemetry
* **PHASE 4 — Detection Engine & MITRE ATT&CK**
  * `P16`: Detection Rule Engine Architecture
  * `P17`: Severity & Confidence Scoring Algorithms
  * `P18`: Authentication & Suspicious Request Rules
  * `P19`: Versioned MITRE ATT&CK Knowledge Base
  * `P20`: Evidence-Backed ATT&CK Mappings & Test Suite
* **PHASE 5 — Correlation & Activity Profiling**
  * `P21`: Session & Temporal Correlation Engine
  * `P22`: Attack-Chain Graph Generation
  * `P23`: Pseudonymous Source Activity Profiling
  * `P24`: Auxiliary Log Ingestion & Attribution Confidence
* **PHASE 6 — SOC Dashboard Implementation**
  * `P25`: Frontend Design System & Layout
  * `P26`: Executive Overview & Security Metrics
  * `P27`: Live Event Explorer & Filter Engine
  * `P28`: Alert Center & Triage Views
  * `P29`: Attack-Chain Visualizer (React Flow) & Source Profiles
  * `P30`: ATT&CK Matrix Explorer & Health Monitor
* **PHASE 7 — Security Operations & Defensive Response**
  * `P31`: Role-Based Access Control & User Auth
  * `P32`: Analyst Investigation Notes & IOC Exporters
  * `P33`: Approval-Gated Lab Response Simulation
  * `P34`: Security Hardening, Privacy Controls & Audit Trails
* **PHASE 8 — Verification, Testing & Threat Simulation**
  * `P35`: Comprehensive Unit, Integration & UI Test Suites
  * `P36`: Controlled Lab Attack Simulation & Detection Verification
  * `P37`: Network Isolation, Stress & Acceptance Testing
* **PHASE 9 — Delivery, Documentation & Final Review**
  * `P38`: Comprehensive System Documentation & Runbooks
  * `P39`: Local Deployment, Backup & Disaster Recovery
  * `P40`: Final Security Review & Executive Project Delivery
