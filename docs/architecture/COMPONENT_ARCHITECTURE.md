# SnareSight: Component & Module Architecture Specification
**Document ID:** ARCH-002  
**Status:** Approved Component Specification  

---

## 1. Overview

This document details the responsibilities, boundaries, interfaces, inputs, and outputs of the 12 functional modules comprising the SnareSight backend and frontend subsystems.

---

## 2. Module Specifications

### Module 1: Honeypot Management (`app.honeypots`)
* **Purpose:** Manages registration, lifecycle, metadata, and operational status of honeypot decoys.
* **Responsibilities:**
  * Register active and simulated decoy instances (web-login portal, future Cowrie SSH).
  * Maintain decoy configuration (ports, protocols, decoy profile names, mock environments).
  * Monitor decoy heartbeat and reachability metrics.
* **Inputs:** Decoy registration payloads, heartbeat pings.
* **Outputs:** Decoy inventory, health status records, telemetry ingestion tokens.
* **Database Entities:** `honeypots`, `honeypot_heartbeats`.
* **Security:** Decoy tokens are cryptographic bearer secrets used solely to authenticate telemetry ingestion.

### Module 2: Event Collection & Ingestion (`app.ingestion`)
* **Purpose:** Safely ingests raw interaction telemetry from decoys and simulation generators.
* **Responsibilities:**
  * Authenticate telemetry forwarders via restricted API tokens.
  * Validate JSON payload syntax against strict Pydantic schemas.
  * Sanitize and redact high-risk values (e.g. truncate huge exploit strings, redact submitted plaintext passwords).
  * Record data provenance tags (`live_honeypot`, `synthetic_demo`, `controlled_simulation`).
  * Enforce separate `event_timestamp` (occurrence) and `ingested_at` (intake).
* **Inputs:** Raw JSON telemetry over HTTP POST (`/api/v1/ingest/events`).
* **Outputs:** Normalized event queue objects; raw event log entries.
* **Database Entities:** `raw_events`, `event_sources`.

### Module 3: Event Normalization & Database Storage (`app.services.event_service`)
* **Purpose:** Normalizes disparate decoy schemas into the canonical SnareSight security event schema.
* **Responsibilities:**
  * Map source-specific attributes to unified fields (`session_id`, `source_ip`, `event_type`, `target_decoy_id`, `action`, `payload_summary`).
  * Deduplicate repeated identical requests within sliding temporal windows.
  * Persist relational event entities while maintaining foreign key integrity.
* **Inputs:** Raw event objects.
* **Outputs:** Persisted `security_events` database records.
* **Database Entities:** `security_events`, `sessions`.

### Module 4: Threat Detection Engine (`app.detection`)
* **Purpose:** Evaluates incoming normalized events against deterministic, explainable security rules.
* **Responsibilities:**
  * Evaluate behavioral conditions (e.g., repeated failed logins > threshold, decoy authentication success, directory traversal patterns, suspicious command injections).
  * Generate structured alert objects with full evidence references.
  * Maintain rule versioning and rule execution telemetry.
* **Inputs:** Stream of normalized `security_events`.
* **Outputs:** Generated `alerts` with bound `alert_evidence`.
* **Database Entities:** `detection_rules`, `alerts`, `alert_evidence`.

### Module 5: Correlation Engine (`app.correlation`)
* **Purpose:** Groups temporally and behaviorally related events into multi-stage attack chains.
* **Responsibilities:**
  * Correlate events sharing sessions, source fingerprints, or short-window temporal clusters.
  * Formulate sequential graph models representing intruder progression (Reconnaissance -> Probe -> Credential Access).
  * Calculate correlation confidence scores.
* **Inputs:** Uncorrelated alerts and normalized events.
* **Outputs:** Graph-structured attack chains (`attack_chains`, `attack_chain_events`).
* **Database Entities:** `attack_chains`, `attack_chain_events`.

### Module 6: MITRE ATT&CK Mapping (`app.intelligence.mitre`)
* **Purpose:** Maps verified security alerts and evidence to official MITRE ATT&CK techniques.
* **Responsibilities:**
  * Maintain a versioned static library of MITRE ATT&CK v15 Enterprise tactics and techniques.
  * Map supported decoy interactions (e.g., `T1110.001 - Password Guessing`, `T1078 - Valid Accounts`, `T1059 - Command and Scripting Interpreter`).
  * Ensure every mapping is backed by explicit event evidence records.
* **Inputs:** Alerts and attack chain nodes.
* **Outputs:** Structured ATT&CK technique associations.
* **Database Entities:** `attack_techniques`, `technique_mappings`.

### Module 7: Observed Source Activity Profiling (`app.intelligence.profiler`)
* **Purpose:** Tracks pseudonymous behavior patterns of interacting source IP entities.
* **Responsibilities:**
  * Aggregate interaction statistics per source IP (total sessions, targeted decoys, observed tool signatures, first/last seen timestamps).
  * Record behavior classification (e.g., Automated Scanner, Targeted Probe, Brute-Forcer).
  * Preserve attribution caveats (avoiding claims of physical individual identity).
* **Inputs:** Session records and normalized events.
* **Outputs:** Source profile records.
* **Database Entities:** `observed_sources`, `iocs`.

### Module 8: SOC Dashboard (`frontend/src`)
* **Purpose:** Provides a professional, distraction-free analyst interface.
* **Responsibilities:**
  * Real-time metrics, decoy status overview, and live event feed.
  * Interactive attack-chain graph visualization using React Flow.
  * Alert triage center, MITRE ATT&CK coverage matrix explorer, and case investigation screens.
* **Inputs:** REST API data and Server-Sent Events (SSE).
* **Outputs:** User actions, analyst triage selections, investigation cases.

### Module 9: Investigation & Response (`app.investigations`)
* **Purpose:** Enables security analysts to manage cases, document findings, and record defensive guidance.
* **Responsibilities:**
  * Create investigation cases linked to alerts and attack chains.
  * Store timestamped analyst notes and triage labels.
  * Generate defensive recommendations (e.g. firewall block suggestions, credential rotation alerts).
* **Inputs:** Analyst inputs, alert references.
* **Outputs:** Case files, status updates, audit records.
* **Database Entities:** `investigations`, `investigation_notes`.

### Module 10: Security Reporting & Export (`app.reporting`)
* **Purpose:** Generates executive and technical incident reports.
* **Responsibilities:**
  * Compile forensic summaries, event timelines, and IOC lists into structured JSON and Markdown/PDF exports.
  * Guarantee data provenance labels appear prominently on every generated export.
* **Inputs:** Investigation records, attack chains, and event logs.
* **Outputs:** Structured report documents and IOC export packages.

### Module 11: Security & Access Control (`app.core.security`)
* **Purpose:** Enforces application identity, authorization, and administrative auditing.
* **Responsibilities:**
  * Secure password hashing using `bcrypt`.
  * Stateless API authentication via signed JWT (JSON Web Tokens).
  * Role-Based Access Control (`Analyst`, `Admin`, `Read-Only`).
  * Immutable administrative audit trail for sensitive configuration changes.
* **Inputs:** Authentication credentials, API requests.
* **Outputs:** Validated user principals, audit logs.
* **Database Entities:** `users`, `audit_logs`.

### Module 12: Platform Health & Decoy Monitoring (`app.core.health`)
* **Purpose:** Continuously verifies service availability and pipeline latency.
* **Responsibilities:**
  * Monitor database connection pools, ingestion latency, and worker availability.
  * Track decoy heartbeat pings and alert on decoy reachability failures.
* **Inputs:** System telemetry, heartbeat timestamps.
* **Outputs:** `/api/v1/health` status endpoints and UI health widget indicators.
* **Database Entities:** `system_health`.

