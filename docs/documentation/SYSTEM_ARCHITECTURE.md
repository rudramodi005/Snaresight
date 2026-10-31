# SnareSight: System Architecture & Design Specification

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Status:** COMPLETE & AUTHORITATIVE  

---

## 1. Architectural Philosophy & Principles

SnareSight is designed as a **Modular Monolith** web application. This architecture balances domain separation, maintainability, and operational simplicity without the operational overhead of microservices, distributed queues (e.g., Kafka, RabbitMQ), or caching clusters (e.g., Redis).

### Core Architectural Decisions:
1. **Single Deployable Process:** The backend runs as a single FastAPI Python process containing well-defined domain modules.
2. **Relational Consistency:** PostgreSQL 16 acts as the authoritative single source of truth for telemetry, detections, sessions, audit records, and operational state.
3. **Real-Time Reactive Push via SSE:** Server-Sent Events (SSE) provide lightweight, unidirectional streaming over standard HTTP without WebSockets overhead.
4. **Decoupled Frontend:** React 18 single-page application built with TypeScript, Tailwind CSS, Lucide React, and React Flow.
5. **Strict Boundary Defense:** Decoy honeypots run in isolated subnets with zero direct access to production or corporate networks.

---

## 2. Overall Component Architecture

The diagram below details the primary subsystems, communication boundaries, and data storage layers across the SnareSight platform:

```mermaid
flowchart TB
    subgraph Decoy_Layer["Decoy Honeypot Layer (Isolated Subnet)"]
        HTTP_DECOY["Web Login Decoy<br/>(Port 8080)"]
        SSH_DECOY["Cowrie SSH Decoy<br/>(Port 2222)"]
        FORWARDER["Sensor Forwarder Agent<br/>(HTTP Client with Token Auth)"]
    end

    subgraph SnareSight_Backend["SnareSight Backend Core (FastAPI Modular Monolith)"]
        direction TB
        
        subgraph Ingestion_Module["1. Ingestion & Preprocessing"]
            INGEST_API["/api/v1/events Ingest Endpoint"]
            AUTH_CHECK["Sensor Token Validator<br/>(X-Sensor-Key)"]
            REDACTOR["Data Protection & Password Hasher<br/>(Zero-Password Invariant)"]
            NORMALIZER["Schema Normalizer<br/>(EventNormalizer)"]
        end

        subgraph Detection_Module["2. Detection & Scoring Engine"]
            RULE_REG["Rule Registry<br/>(10 Catalogue Rules)"]
            SESSION_EVAL["Session Evaluator"]
            SCORER["Dual-Metric Scorer<br/>(Severity & Confidence)"]
            ALERT_GEN["Alert Generator & Deduplicator"]
        end

        subgraph Correlation_Module["3. Correlation & Graph Engine"]
            SESSION_MGR["Temporal Session Correlator"]
            CHAIN_MGR["Attack Chain Builder<br/>(React Flow Directed Acyclic Graph)"]
            MITRE_MAP["Evidence MITRE ATT&CK Mapper"]
            INTEL_MGR["Threat Actor / Source Profiler"]
            CAMP_MGR["Campaign Intelligence Clustered"]
        end

        subgraph Ops_Module["4. SOC Ops & Resilience"]
            CASE_MGR["Incident Case Management"]
            FIREWALL_GEN["Containment / Firewall Rule Gen"]
            HEALTH_MON["Sensor Health & Heartbeat Monitor"]
            RESILIENCE["Self-Monitoring & Auto-Backup"]
            DEMO_LAB["Demonstration Lab Harness (/demo)"]
            SSE_HUB["SSE Broadcaster Hub"]
        end
    end

    subgraph Database_Layer["Authoritative Relational Store"]
        DB[("PostgreSQL 16 Database<br/>(SQLAlchemy 2.0 / Alembic)")]
    end

    subgraph Frontend_Layer["SOC Web Dashboard (React 18 + TypeScript + Vite)"]
        SPA["Vite Single Page Application<br/>(Tailwind CSS + Recharts + React Flow)"]
        SSE_CLIENT["SSE EventSource Stream Receiver"]
    end

    HTTP_DECOY --> FORWARDER
    SSH_DECOY --> FORWARDER
    FORWARDER -->|"POST /api/v1/events (Bearer Token)"| INGEST_API
    INGEST_API --> AUTH_CHECK
    AUTH_CHECK --> REDACTOR
    REDACTOR --> NORMALIZER
    NORMALIZER --> RULE_REG
    RULE_REG --> SESSION_EVAL
    SESSION_EVAL --> SCORER
    SCORER --> ALERT_GEN
    
    ALERT_GEN --> SESSION_MGR
    SESSION_MGR --> CHAIN_MGR
    CHAIN_MGR --> MITRE_MAP
    MITRE_MAP --> INTEL_MGR
    INTEL_MGR --> CAMP_MGR

    ALERT_GEN -->|"Persist Alerts"| DB
    NORMALIZER -->|"Persist Events"| DB
    SESSION_MGR -->|"Persist Sessions"| DB
    CASE_MGR <--> DB
    HEALTH_MON <--> DB
    RESILIENCE <--> DB

    ALERT_GEN -->|"Push Notification"| SSE_HUB
    HEALTH_MON -->|"Push Heartbeat"| SSE_HUB
    SSE_HUB -->|"HTTP SSE Stream (/api/v1/stream)"| SSE_CLIENT
    SSE_CLIENT --> SPA
    SPA <-->|"REST API Requests (/api/v1/*)"| SnareSight_Backend
```

---

## 3. Telemetry Ingestion & Normalization Lifecycle

The ingestion pipeline guarantees that incoming decoy interactions are strictly validated, authenticated, sanitized, and stored with immutable provenance:

```mermaid
sequenceDiagram
    autonumber
    participant Sensor as Decoy Sensor / Forwarder
    participant Ingest as Telemetry Ingestion API
    participant Redactor as Data Protection Redactor
    participant Normalizer as Event Normalizer
    participant DB as PostgreSQL Database
    participant Detection as Detection Engine

    Sensor->>Ingest: POST /api/v1/events (Event Payload + X-Sensor-Key)
    alt Invalid Sensor Key
        Ingest-->>Sensor: 401 Unauthorized (Rejected)
    else Valid Sensor Key
        Ingest->>Redactor: Process Raw Payload
        Note over Redactor: Check for password / secret fields
        Redactor->>Redactor: Hash plaintext password with SHA-256 + Salt
        Redactor->>Normalizer: Clean Payload + Provenance Tag
        Normalizer->>Normalizer: Validate Pydantic EventCreateSchema
        Normalizer->>DB: INSERT into events (id, timestamp, src_ip, honeypot_type, payload_hash...)
        Normalizer->>Detection: Forward NormalizedEvent to Rule Registry
        Ingest-->>Sensor: 201 Created (event_id, status: "INGESTED")
    end
```

---

## 4. Detection Engine, Scoring, and Alert Lifecycle

SnareSight evaluates normalized events against 10 explainable catalogue rules using stateful temporal session evaluation:

```mermaid
sequenceDiagram
    autonumber
    participant Normalizer as Event Normalizer
    participant Registry as Rule Registry
    participant Evaluator as Session Evaluator
    participant Scorer as Dual-Metric Scorer
    participant AlertModule as Alert Manager
    participant DB as PostgreSQL Database
    participant SSE as SSE Hub
    participant SOC as Analyst Dashboard

    Normalizer->>Registry: Dispatch NormalizedEvent
    Registry->>Evaluator: Match Active Rules against Session History
    Note over Evaluator: Query rolling event window for matching IP/Session
    alt Threshold Conditions Not Met
        Evaluator-->>Registry: No detection triggered
    else Threshold Breached (e.g. 5 failed logins within 60s)
        Evaluator->>Scorer: Calculate Severity & Confidence
        Note over Scorer: Severity = Base impact + Target weight<br/>Confidence = Evidence count + Pattern fidelity
        Scorer->>AlertModule: Emit Alert Candidates
        AlertModule->>AlertModule: Check Deduplication & Suppression Window
        alt Deduplication Active
            AlertModule->>DB: UPDATE alerts SET count = count + 1, last_seen = NOW()
        else New Alert
            AlertModule->>DB: INSERT into alerts (title, severity, confidence, rule_id, status: "NEW")
            AlertModule->>SSE: Broadcast alert_created event
            SSE->>SOC: Push Live Alert to UI Toast & Queue
        end
    end
```

---

## 5. Session Correlation, Attack-Chain Graphing & Case Workflow

Correlated detections are assembled into visual graph structures and analyst-driven incident cases:

```mermaid
flowchart LR
    subgraph Raw_Detections["Detection Stage"]
        E1["Event 1: Port Scan"]
        E2["Event 2: Path Traversal"]
        E3["Event 3: Brute Force"]
        E4["Event 4: Command Injection"]
    end

    subgraph Correlation_Stage["Temporal & Session Correlation"]
        SESS["Session Grouper<br/>(Source IP + Decoy Session Cookie)"]
        E1 --> SESS
        E2 --> SESS
        E3 --> SESS
        E4 --> SESS
    end

    subgraph Graph_Stage["Attack Chain Builder (DAG)"]
        N1["Phase 1: Reconnaissance<br/>(T1595.002)"]
        N2["Phase 2: Discovery<br/>(T1083)"]
        N3["Phase 3: Credential Access<br/>(T1110)"]
        N4["Phase 4: Execution<br/>(T1059)"]
        SESS --> N1
        N1 --> N2
        N2 --> N3
        N3 --> N4
    end

    subgraph Analyst_Stage["Analyst Case Workspace"]
        CASE["Incident Case #104<br/>Status: INVESTIGATING"]
        N4 --> CASE
        ACT1["Action 1: Tag MITRE Techniques"]
        ACT2["Action 2: Generate iptables Block"]
        ACT3["Action 3: Export Forensic Dossier"]
        CASE --> ACT1
        CASE --> ACT2
        CASE --> ACT3
    end
```

---

## 6. Sensor-to-Backend Communication & Health Monitoring

The sensor management subsystem continuously assesses sensor health and detects packet-loss or dropped connections:

```mermaid
sequenceDiagram
    autonumber
    participant Sensor as Decoy Sensor (HTTP / SSH)
    participant API as Sensor Management API
    participant Monitor as Health & Reliability Service
    participant DB as PostgreSQL Database
    participant SSE as SSE Hub
    participant UI as Sensor Status Dashboard

    loop Every 30 Seconds
        Sensor->>API: POST /api/v1/sensors/{id}/heartbeat (Metrics: CPU, Memory, Queue)
        API->>DB: UPDATE sensors SET last_heartbeat = NOW(), status = 'HEALTHY'
    end

    loop Every 60 Seconds
        Monitor->>DB: SELECT * FROM sensors WHERE last_heartbeat < NOW() - INTERVAL '90 seconds'
        alt Stale Sensor Detected
            Monitor->>DB: UPDATE sensors SET status = 'OFFLINE'
            Monitor->>DB: INSERT into operational_alerts (type: 'SENSOR_OFFLINE', sensor_id)
            Monitor->>SSE: Broadcast sensor_status_change
            SSE->>UI: Update UI Badge to OFFLINE (Red Alert)
        end
    end
```

---

## 7. Database Architecture & Alembic Evolution

The persistence layer is managed by SQLAlchemy 2.0 ORM with Alembic schema versioning:

* **Strict Migration Lineage:** Migrations form an unbroken chain from baseline schema `p01_initial_schema` to `p34_operational_resilience`.
* **Zero Orphan Tables:** Every relationship uses explicit foreign keys with appropriate cascade or `RESTRICT` rules.
* **Audit Trail Immutability:** Audit log tables are append-only; updates and deletions are programmatically rejected.
* **Retention Holds:** Investigative cases and forensic evidence can be flagged with a `retention_hold = True` boolean, preventing automated pruning policies from deleting records during compliance or legal holds.

