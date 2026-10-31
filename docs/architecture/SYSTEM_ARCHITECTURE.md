# SnareSight: System Architecture Specification
**Document ID:** ARCH-001  
**Status:** Approved Architecture Baseline  
**Classification:** Internal Technical Architecture  

---

## 1. Executive Summary & Objective

SnareSight is a deception-driven cybersecurity threat detection and Security Operations Center (SOC) platform. Its primary objective is to deploy controlled, isolated decoy services (honeypots), monitor adversary interactions, ingest and normalize raw security telemetry, evaluate deterministic behavioral detection rules, correlate related activity into attack chains, map verified observations to MITRE ATT&CK techniques, and present high-integrity security intelligence to analysts via a real-time SOC dashboard.

---

## 2. High-Level Context Diagram (C4 Level 1)

```mermaid
graph TD
    subgraph Adversary_Zone["Untrusted Network / Internal Lab Subnet"]
        Attacker["Adversary / Probe Entity"]
    end

    subgraph Honeypot_Isolation_Zone["Zone 3: Isolated Decoy Environment (Linux VM / Container)"]
        DecoyApp["Web-Login Decoy Service<br/>(Simulated Admin Portal)"]
        DecoyLogger["Telemetry Collector & Forwarder"]
    end

    subgraph SnareSight_Core["Zone 2: SnareSight Core Platform (Modular Monolith)"]
        IngestionAPI["Restricted Telemetry Ingestion API"]
        EventPipeline["Normalization & Validation Engine"]
        DetectionEngine["Explainable Detection Engine"]
        CorrelationEngine["Session & Attack-Chain Correlation"]
        PostgreSQL[("PostgreSQL 16 DB<br/>Events, Alerts, Chains, Models")]
        AppAPI["FastAPI Application & REST Endpoints"]
        SSEHub["Server-Sent Events (SSE) Broadcast Hub"]
    end

    subgraph Analyst_Zone["Zone 1: Windows Host & SOC Analyst"]
        SOCDashboard["React / TypeScript / Vite Dashboard"]
        SecurityAnalyst["Security Operations Analyst"]
    end

    %% Interactions
    Attacker -->|"Interacts / Credential Stuffing"| DecoyApp
    DecoyApp -->|"Local syslog / JSON lines"| DecoyLogger
    DecoyLogger -->|"Restricted HTTP/TLS Telemetry<br/>Internal Bridge Only"| IngestionAPI
    IngestionAPI -->|"Sanitize & Validate"| EventPipeline
    EventPipeline -->|"Store Raw & Normalized"| PostgreSQL
    EventPipeline -->|"Stream Events"| DetectionEngine
    DetectionEngine -->|"Generate Alerts"| CorrelationEngine
    CorrelationEngine -->|"Persist Chains & ATT&CK Mappings"| PostgreSQL
    PostgreSQL -->|"Query Data"| AppAPI
    DetectionEngine -->|"Trigger Live Notification"| SSEHub
    SSEHub -->|"Live Stream (SSE)"| SOCDashboard
    AppAPI -->|"REST API (JSON)"| SOCDashboard
    SOCDashboard -->|"Triage, Investigate, Report"| SecurityAnalyst
```

---

## 3. Detailed Component-Level Diagram (C4 Level 2)

```mermaid
graph LR
    subgraph Decoy_Host["Zone 3: Isolated VM"]
        DecoyWeb["Web Login Decoy<br/>(Port 8080)"]
        DecoySSH["Modular Cowrie SSH Decoy<br/>(Port 2222 - Post MVP)"]
        LogShipper["Secure Log Forwarder<br/>(Token Authenticated)"]
    end

    subgraph Backend_Modular_Monolith["Zone 2: FastAPI Backend Engine"]
        subgraph Ingestion_Subsystem["Ingestion & Validation"]
            IngestEndpoint["POST /api/v1/ingest/events"]
            SchemaValidator["Pydantic Ingestion Contract"]
            Sanitizer["Payload Sanitizer & Redactor"]
        end

        subgraph Processing_Subsystem["Pipeline Processing"]
            Normalizer["Event Normalizer"]
            ProvenanceTagger["Provenance Tagger (Live/Demo/Sim)"]
            Deduplicator["Deduplication Cache"]
        end

        subgraph Intelligence_Subsystem["Detection & Analytics"]
            RuleEngine["Deterministic Rule Engine"]
            ScoringService["Severity & Confidence Scorer"]
            CorrelationService["Temporal & Session Correlator"]
            AttackChainBuilder["React Flow Graph Generator"]
            MitreMapper["ATT&CK Technique Mapper"]
        end

        subgraph Core_Services["Core & Delivery Services"]
            AuthService["JWT / RBAC Service"]
            InvestigationService["Investigation Case Manager"]
            ReportService["Evidence Exporter & Reporter"]
            HealthService["Decoy & Pipeline Health Monitor"]
            LiveBroadcaster["SSE Event Channel"]
        end
    end

    subgraph Database_Tier["Data Persistence Layer"]
        DB_Raw[("raw_events")]
        DB_Norm[("security_events")]
        DB_Alerts[("alerts & alert_evidence")]
        DB_Chains[("attack_chains")]
        DB_Mitre[("attack_techniques")]
        DB_Cases[("investigations & notes")]
    end

    subgraph UI_Tier["Zone 1: React Frontend (Vite)"]
        View_Overview["Executive Overview Page"]
        View_Explorer["Live Event Explorer"]
        View_Alerts["Alert Center"]
        View_Graph["Attack-Chain Visualizer (React Flow)"]
        View_Mitre["ATT&CK Matrix Explorer"]
        View_Health["System & Decoy Health View"]
    end

    %% Wiring
    DecoyWeb --> LogShipper
    DecoySSH -.-> LogShipper
    LogShipper --> IngestEndpoint
    IngestEndpoint --> SchemaValidator --> Sanitizer --> Normalizer
    Normalizer --> ProvenanceTagger --> Deduplicator
    Deduplicator --> DB_Raw & DB_Norm
    Normalizer --> RuleEngine
    RuleEngine --> ScoringService --> CorrelationService
    CorrelationService --> AttackChainBuilder --> MitreMapper
    MitreMapper --> DB_Alerts & DB_Chains & DB_Mitre
    DB_Norm & DB_Alerts & DB_Chains --> Core_Services
    Core_Services --> View_Overview & View_Explorer & View_Alerts & View_Graph & View_Mitre & View_Health
    LiveBroadcaster -->|SSE Push| View_Explorer & View_Alerts
```

---

## 4. Architectural Style: Modular Monolith

SnareSight adopts a **Modular Monolith** architecture for its core backend services:
* **Single Deployment Unit:** Deployed as a unified Python FastAPI service running within Windows development or containerized environments.
* **Strict Logical Boundaries:** Internal subsystems (`ingestion`, `detection`, `correlation`, `intelligence`, `investigations`, `reporting`) interact exclusively through explicit Python interfaces and dependency injection.
* **No Premature Microservice Overhead:** Eliminates network serialization delays, distributed transaction failure modes, and service orchestration complexity, ensuring rapid, reliable execution on standard development hardware.

