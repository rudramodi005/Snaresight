# SnareSight: End-to-End Data Flow Specification
**Document ID:** ARCH-003  
**Status:** Approved Data Flow Baseline  

---

## 1. Primary Data Flows

This document specifies the exact sequential progression of security data across the platform, from decoy interaction to analyst investigation.

---

### Flow A: Honeypot Event Ingestion & Normalization

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as Adversary / Probe
    participant Decoy as Web-Login Decoy
    participant Shipper as Log Shipper / Agent
    participant Ingestion as Ingestion API (POST /ingest)
    participant Normalizer as Event Normalizer
    participant DB as PostgreSQL Database
    participant Pipeline as Event Bus / Stream

    Attacker->>Decoy: POST /admin/login (username="admin", password="password123")
    Decoy->>Decoy: Log interaction, compute hash, mask password
    Decoy->>Shipper: Local syslog / JSON payload
    Shipper->>Ingestion: HTTPS POST /api/v1/ingest/events (Bearer Token)
    Ingestion->>Ingestion: Validate token & Pydantic schema
    Ingestion->>Ingestion: Sanitize & redact sensitive values
    Ingestion->>Normalizer: Enforce canonical schema & assign Provenance (live_honeypot)
    Normalizer->>DB: INSERT into raw_events
    Normalizer->>DB: INSERT into security_events
    Normalizer->>Pipeline: Dispatch normalized event
```

---

### Flow B: Deterministic Threat Detection & Alert Generation

```mermaid
sequenceDiagram
    autonumber
    participant Pipeline as Event Bus / Stream
    participant RuleEngine as Rule Detection Engine
    participant Scorer as Severity & Confidence Scorer
    participant DB as PostgreSQL Database
    participant SSE as SSE Broadcast Hub
    participant UI as SOC Dashboard

    Pipeline->>RuleEngine: Process normalized security_event
    RuleEngine->>RuleEngine: Check rule condition (e.g., Rule: BRUTE_FORCE_BURST > 5 attempts in 60s)
    RuleEngine->>Scorer: Evaluate impact & certainty
    Scorer->>Scorer: Severity: HIGH (Cred Access), Confidence: HIGH (Exact match)
    RuleEngine->>DB: INSERT into alerts & alert_evidence
    RuleEngine->>SSE: Publish AlertNotification event
    SSE->>UI: Stream new alert to connected analysts
    UI->>UI: Update Alert Center counter & trigger audio/visual indicator
```

---

### Flow C: Temporal & Session Correlation (Attack Chain Construction)

```mermaid
sequenceDiagram
    autonumber
    participant DB as PostgreSQL Database
    participant Correlator as Correlation Engine
    participant GraphBuilder as Attack-Chain Builder

    DB->>Correlator: Query unlinked alerts within window (Delta T <= 300s, shared source_ip/session)
    Correlator->>Correlator: Identify stage progression: Recon -> Discovery -> Brute Force -> Success
    Correlator->>GraphBuilder: Generate DAG nodes (React Flow structure)
    GraphBuilder->>DB: INSERT / UPDATE attack_chains & attack_chain_events
```

---

### Flow D: Evidence-Backed MITRE ATT&CK Mapping

```mermaid
sequenceDiagram
    autonumber
    participant Alert as Security Alert
    participant Mapper as MITRE ATT&CK Mapper
    participant Catalogue as ATT&CK v15 Matrix Store
    participant DB as PostgreSQL Database

    Alert->>Mapper: Trigger mapping evaluation
    Mapper->>Catalogue: Match rule tags (e.g. tag: "credential_stuffing") -> T1110.004
    Mapper->>Mapper: Validate supporting event evidence exists
    Mapper->>DB: INSERT into technique_mappings (alert_id, technique_id, evidence_id)
```

---

### Flow E: Analyst Investigation & Triage Workflow

```mermaid
sequenceDiagram
    autonumber
    participant Analyst as SOC Analyst
    participant UI as Dashboard Interface
    participant CaseService as Investigation Service
    participant DB as PostgreSQL Database

    Analyst->>UI: Select Alert -> Click "Escalate to Investigation"
    UI->>CaseService: POST /api/v1/investigations (alert_ids, title, severity)
    CaseService->>DB: INSERT into investigations & audit_logs
    Analyst->>UI: Append forensic note & tag as "Compromised Decoy"
    UI->>CaseService: POST /api/v1/investigations/{id}/notes
    CaseService->>DB: INSERT into investigation_notes
    Analyst->>UI: Request Export -> Generate PDF/JSON Incident Report
```

---

### Flow F: Real-Time SSE Dashboard Synchronization

```mermaid
sequenceDiagram
    autonumber
    participant UI as Frontend React App
    participant SSEHub as FastAPI SSE Hub
    participant DB as PostgreSQL Database

    UI->>SSEHub: GET /api/v1/events/stream (Authorization: Bearer <Token>)
    SSEHub->>SSEHub: Register active client connection
    loop Keep-Alive & Event Dispatch
        SSEHub->>UI: ping (every 15s)
        Note over SSEHub,UI: When new alert or event is committed
        SSEHub->>UI: event: "NEW_ALERT", data: {id, severity, rule_name, timestamp}
        UI->>UI: Update live tables without full page reload
    end
```

---

## 2. Failure & Edge Case Handling

1. **Collector Disconnection / Network Glitch:**
   * Log forwarder maintains an in-memory disk-backed spool buffer (up to 50 MB) inside the isolated VM.
   * On reconnection, batched events are shipped with original occurrence timestamps (`event_timestamp`).
2. **Malformed Payload Injection:**
   * Payloads failing Pydantic validation are rejected with HTTP 422, logged to an ingestion error counter, and dropped without crashing the pipeline.
3. **Duplicate Event Transmissions:**
   * Normalizer calculates an event signature hash `SHA256(source_ip + timestamp + event_type + payload_summary)`.
   * Duplicate signatures within a 10-second sliding window are ignored.
4. **SSE Client Reconnection:**
   * If the browser loses network connectivity, the EventSource API automatically re-establishes the connection and requests a delta backfill via standard REST endpoints.

