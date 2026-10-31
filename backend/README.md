# SnareSight Backend Engine
### Modular Monolith Threat Detection & Ingestion Engine

---

## 1. Overview
The SnareSight backend is a high-performance **FastAPI** modular monolith designed for sub-millisecond telemetry ingestion, deterministic behavioral threat detection, temporal session correlation, and Server-Sent Events (SSE) notification streaming.

---

## 2. Technical Stack
* **Framework:** FastAPI (Python 3.14 compatible)
* **ASGI Server:** Uvicorn
* **Data Validation:** Pydantic v2
* **Database & ORM:** PostgreSQL 16 via SQLAlchemy 2.0 (Typed Declarative Models)
* **Database Driver:** `psycopg` (v3) / `psycopg2`
* **Database Migrations:** Alembic
* **Security & Auth:** Stateless JWT with bcrypt password hashing
* **Real-Time Streaming:** `sse-starlette`
* **Test Suite:** Pytest / Unittest with isolated test fixtures

---

## 3. Directory Layout
```
backend/
├── app/
│   ├── __init__.py
│   ├── api/             # REST endpoints (auth, events, alerts, chains, investigations)
│   ├── core/            # Config, security tokens, logging, and database settings
│   ├── db/              # SQLAlchemy Base, session factory, and declarative models
│   │   ├── base.py      # DeclarativeBase with strict PostgreSQL naming conventions
│   │   ├── session.py   # Engine, connection pooling, and get_db dependency
│   │   └── models/      # 12 relational models implementing P11 data contracts
│   │       ├── honeypot.py     # HoneypotModel, EventSourceModel
│   │       ├── event.py        # RawEventModel, SecurityEventModel
│   │       ├── session.py      # SessionModel
│   │       ├── rule.py         # DetectionRuleModel
│   │       ├── alert.py        # AlertModel, AlertEvidenceModel
│   │       └── intelligence.py # AttackTechniqueModel, TechniqueMappingModel, etc.
│   ├── schemas/         # Pydantic request and response contracts
│   ├── services/        # Business logic services
│   ├── ingestion/       # Telemetry intake, sanitization, and normalization
│   ├── detection/       # Deterministic rule engine and rule definitions
│   ├── correlation/     # Session grouping and attack-chain graph generator
│   └── monitoring/      # System health and pipeline latency monitors
├── migrations/          # Alembic database migration environment
├── tests/               # Pytest/Unittest test suites
│   └── test_models.py   # SQLAlchemy model, constraint, and sensitive field tests
├── pyproject.toml       # Build configuration and dependency definitions
└── README.md
```

---

## 4. Database Architecture & Operational Governance

### 4.1 Persistence Model
SnareSight uses a **Hybrid Relational-Document Pattern**:
- Relational columns for high-cardinality indexing (`UUID` primary keys, `TIMESTAMPTZ` observed times, enums, foreign keys).
- Native `JSONB` for flexible service metadata (`sanitized_metadata`, `provenance`, `recommendations`).
- Many-to-many `alert_evidence` junction table for forensic traceability.

### 4.2 Database Security Rules
1. **Loopback Binding:** PostgreSQL binds strictly to `127.0.0.1:5432`; no external exposure.
2. **Role Separation:**
   - `postgres`: Superuser administration only.
   - `snaresight_migrator`: Schema DDL migrations via Alembic.
   - `snaresight_app`: Least-privilege runtime DML (`SELECT`, `INSERT`, `UPDATE`); zero DDL rights.
3. **Zero Password Persistence:** Relational models strictly forbid columns storing raw credentials, derived hashes, or authentication tokens.

### 4.3 Running Database Unit Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest discover tests -v
```

---

## 5. Event Ingestion & Validation Engine (Phase 3 — P13)

### 5.1 Ingestion Modalities
The backend supports two safe intake channels:
1. **Offline File Importer (`JsonlTelemetryImporter`):** Streams JSONL audit logs with path-traversal safeguards, 10MB size ceiling, and line-by-line parsing.
2. **Authenticated REST Gateway (`POST /api/v1/ingestion/events/batch`):** Batch API secured via `X-API-Key` authentication.

### 5.2 Core Security Invariants
- **Zero Password Persistence:** All telemetry is inspected by `SensitiveDataInspector`. Prohibited credential keys (`password`, `auth_token`, `private_key`) or synthetic canaries (`CanaryPass`) are immediately rejected.
- **Idempotency Guarantee:** Events are fingerprinted using SHA-256 over 7 immutable fields. Duplicate resubmissions produce zero duplicate database records.
- **Strict Decoupling:** Honeypot decoys hold zero network access or database drivers to PostgreSQL.

### 5.3 Ingestion Endpoints
- `POST /api/v1/ingestion/events/batch` - Ingest an authenticated batch of events.
- `GET /api/v1/ingestion/status` - Live ingestion engine observability metrics.

### 5.4 Running Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest discover tests -v
```

---

## 6. Event Normalization, Deduplication & Retention (Phase 3 — P14)

### 6.1 Normalization Architecture
- **Centralized Normalization Engine (`EventNormalizer`):** Coordinates modular micro-services (`EventClassifier`, `TimestampNormalizer`, `SourceNormalizer`, `MetadataNormalizer`, `SchemaRegistry`).
- **Cross-Source Adapter Pattern:** Decouples sensor formats via `WebDecoyAdapter` (`WEB-001`) and prepared `CowrieDecoyAdapter` (`COWRIE-SSH`) without altering core schemas.
- **Strict Timezone Handling:** ISO-8601 UTC parsing with clock-skew tolerance (300s) and late-arriving event detection.

### 6.2 Layered Deduplication & Collision Handling
- **Layer 1:** Stable `raw_event_id` (UUIDv4).
- **Layer 2:** Source-scoped ID (`source_id:decoy_id:raw_event_id`).
- **Layer 3:** SHA-256 deterministic fingerprint over immutable canonical attributes.
- **Collision Discrimination:** Distinguishes exact duplicates, identifier collisions, and distinct legitimate interactions.

### 6.3 Retention Policies & Evidence Preservation
- **Configurable Retention Windows:** Managed by `RetentionPolicyConfig` (`RAW_EVENTS`: 90d, `NORMALIZED_EVENTS`: 180d, `ALERTS`: 365d, `SIMULATION`: 14d, `AUDIT`: 730d).
- **Trusted Reference Timestamps:** Expiry calculations use server-recorded timestamps (`received_at`, `created_at`), neutralizing attacker-controlled timestamp manipulation.
- **Preservation Holds:** Investigation holds managed by `EvidencePreservationService` override ordinary retention.
- **Dry-Run by Default:** Destructive deletion requires explicit `dry_run=False` and authorization token (`CONFIRM_RETENTION_DELETION`).

---

## 7. Live Event Streaming & Centralized Pipeline Health Monitoring (Phase 3 — P15)

### 7.1 Server-Sent Events (SSE) Engine
- **Streaming Protocol:** Standard W3C Server-Sent Events (`text/event-stream`) via `GET /api/v1/stream/events`.
- **Strict Post-Commit Notifications:** Events are broadcast strictly after database commit; failure to deliver to clients never rolls back database transactions.
- **Stateless Cursor-Based Reconnection:** Clients reconnect using `Last-Event-ID` or `?cursor=` (<ISO8601>:<UUID>). Missed events are queried directly from `SecurityEventModel` without in-memory cache reliance.
- **Resource Protection:** Enforces a maximum of 50 global concurrent connections, 5 connections per user, bounded subscriber queues of 100 messages, and automatic eviction of slow or stalling consumers.
- **Zero Password Persistence:** Credential fields and secrets are permanently stripped prior to publishing frames.

### 7.2 Centralized Operational Health Probes
- `GET /api/v1/health/live` - Process liveness check (`UP` / `DOWN`).
- `GET /api/v1/health/ready` - Persistent dependency readiness check (`SELECT 1` against PostgreSQL).
- `GET /api/v1/health/pipeline` - Aggregated ingestion, persistence, and streaming metrics.
- `GET /api/v1/health/components` - Detailed module-level status breakdown.
- `GET /api/v1/stream/status` - Live subscriber and notification health audit.

### 7.3 Running Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest tests.test_streaming_and_health -v
```

---

## 8. Configurable Rule-Based Threat Detection Engine (Phase 4 — P16)

### 8.1 Detection Engine Architecture
- **Deterministic Evaluation:** Rule evaluation is strictly declarative and deterministic; dynamic code execution (`eval()`, `exec()`, arbitrary SQL, shell execution) is permanently prohibited.
- **Controlled Field Registry:** Inspects only allowlisted normalized event fields (`FieldRegistry`). Prohibited sensitive attributes (`password`, `token`, `secret_key`) are strictly forbidden.
- **Immutable Rule Versions:** Historical rule versions are immutable. Rule updates create explicit version increments, guaranteeing verifiable historical audits.
- **Idempotency & Deduplication:** Evaluation is keyed on `event_id:rule_id:rule_version`. Reprocessing an event returns cached results without duplicate alerts or audit records.
- **Session & Time-Window Foundations:** Built-in bounded sliding windows (`TimeWindowEvaluator`) and ordered session evaluations (`SessionEvaluator`) without cross-session pollution or unbounded historical scanning.
- **Post-Commit Non-Blocking Execution:** Hooked into `EventProcessor` downstream of `db.commit()`. Rule evaluation failure never rolls back or deletes persisted security events.

### 8.2 Running Detection Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest tests.test_detection -v
```

---

## 9. Severity & Confidence Scoring Engine (Phase 4 — P17)

### 9.1 Scoring Architecture & Principles
- **Strict Independence:** Severity (threat significance: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and Confidence (evidence reliability: 0–100, `VERY_LOW` to `VERY_HIGH`) are strictly orthogonal. High severity may have low confidence and vice-versa.
- **Evidence-Based Evaluation:** Assesses event validity, collector source reliability, provenance, session consistency, and timestamp quality. Duplicate telemetry cannot inflate confidence.
- **Evidence Strength:** Categorized into four tiers (`INSUFFICIENT`, `LIMITED`, `MODERATE`, `STRONG`).
- **Explainable Assessments:** Dynamically generates human-readable rationales citing real contributing factors without making deceptive real-world compromise claims.
- **Declarative Policies:** Centralized, versioned scoring policies (`ScoringPolicyDefinition`) enforcing immutable policy parameters.
- **Dual-Track Review:** Supports manual analyst review without overwriting automated assessments.

### 9.2 Running Scoring Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest tests.test_scoring -v
```

---

## 10. Concrete Threat Detection Scenarios & Alert Lifecycle (Phase 4 — P18)

### 10.1 Scenario Architecture & Catalogue
- **10 Concrete Behavioral Scenarios:**
  - `AUTH-001`: Repeated Authentication Failures (Session / Windowing Threshold)
  - `AUTH-002`: Decoy Authentication Acceptance (Simulated trap account login, not real system access)
  - `AUTH-003`: Username Enumeration Probing (Counting distinct one-way SHA-256 fingerprints)
  - `WEB-001`: Web Path Enumeration Probing (Counting distinct normalized requested paths)
  - `WEB-002`: Suspicious Directory Traversal Request (Passive matching of `../`, `..%2f`, `%2e%2e/`; never executed)
  - `CMD-001`: Command Discovery Interaction (**DEFERRED**: HTTP decoy produces no shell commands; commands never executed)
  - `FILE-001`: File-Transfer Attempts (**DEFERRED**: HTTP decoy accepts no uploads; files never opened or executed)
  - `WEB-003`: Repeated Suspicious Request Patterns (Session threshold of suspicious indicators)
  - `BEHAV-001`: Multi-Category Suspicious Interaction (Session spanning $\ge 2$ distinct security categories)
  - `BEHAV-002`: Unusual HTTP Method Interaction (Detecting `TRACE`, `PROPFIND`, `DEBUG`, etc.)
- **Operational Invariants:**
  - **Decoy Interaction Truth:** Honeypot activity is explicitly documented as simulated deception; never confused with production breach.
  - **Zero Execution:** Command strings, uploaded files, and traversal paths are never executed or resolved against the host filesystem.
  - **Zero Credential Exposure:** Plaintext usernames and passwords are never processed or retained in alert records.
  - **Auditable False-Positive Suppression:** Cooldown suppression (300s window) and explicit suppression rules prevent alert floods without deleting or hiding underlying security events.

### 10.2 Alert Generation & Post-Commit Streaming Integration
- **Persistent Storage:** Alerts and their supporting normalized events are persisted into `alerts` (`AlertModel`) and `alert_evidence` (`AlertEvidenceModel`) junction tables.
- **SSE Notification Broadcast:** Post-commit broadcast over Server-Sent Events (`event: security_alert`) notifying authorized SOC clients without blocking ingestion or rolling back database records.

### 10.3 Running Detection Scenario Tests
```powershell
cd c:\Projects\SnareSight\backend
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest tests.test_scenarios -v
```

---

## 11. MITRE ATT&CK Versioned Data Integration (Phase 4 — P19)

### 11.1 Architecture & Official Data Source
- **Official Source:** `https://github.com/mitre-attack/attack-stix-data` (Domain: `enterprise-attack`, STIX 2.1).
- **Core Modules (`app/modules/mitre/`):**
  - `StixValidator`: Payload size caps (35MB ceiling, 10,000 objects), STIX ID regex compliance, XSS script sanitization.
  - `StixParser`: Deterministic parsing of tactics (`x-mitre-tactic`), techniques/subtechniques (`attack-pattern`), and relationships (`subtechnique-of`).
  - `MitreVersioningEngine`: Cryptographic SHA-256 fingerprinting, version activation, release diffing, and rollback.
  - `MitreImporter`: Transactional imports with ACID rollback on error, dry-run diff preview, and idempotent caching.
  - `MitreRepository` & `MitreService`: Paginated techniques queries, tactic grouping, and catalogue health checks.
  - `routes.py`: Read-only catalogue APIs and authorized administrator import endpoints under `/api/v1/mitre`.

### 11.2 Safety Invariants
- **Zero Dynamic Execution:** Invariant protection forbidding `eval`, `exec`, or command subprocesses during bundle ingestion.
- **XSS Sanitization:** Neutralization of embedded HTML tags and script payloads in adversary technique descriptions.
- **Transactional Protection:** Incomplete or corrupted bundle imports trigger automatic database rollback without affecting the currently active catalogue.

### 11.3 Running MITRE ATT&CK Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest discover -s tests/modules/mitre -v
```

---

## 12. Evidence-Based MITRE ATT&CK Mapping (Phase 4 — P20)

### 12.1 Mapping Architecture & Curated Registry
- **Conceptual Pipeline:** Honeypot Decoy Event -> Normalized Security Event -> Detection Rule -> Detection Result / Alert -> Mapping Evaluator -> Evidence-Backed ATT&CK Association -> Analyst Investigation.
- **Core Modules (`app/modules/mitre/mapping/`):**
  - `MappingDefinitionRegistry`: Curated catalogue defining evidential criteria connecting detection scenarios to ATT&CK techniques.
  - `MappingConfidenceEngine`: Computes independent mapping confidence scores (0–100) and categorical levels (`LOW`, `MODERATE`, `HIGH`) with factor explanations.
  - `MappingEvaluator`: Deterministic, idempotent evaluation triggered post-commit; validates required telemetry fields, checks exclusion conditions, and queries authoritative ATT&CK catalogue.
  - `MappingService`: Service facade managing mapping records, paginated filtering, audit history, operational statistics, and analyst reviews.
  - `routes.py`: REST endpoints mounted under `/api/v1/mitre/mappings...` and `/api/v1/detections/{id}/mitre-mappings`.

### 12.2 Scenario Mapping Summary
- `AUTH-001` -> `T1110` (Brute Force) & `T1110.001` (Password Guessing) [`DIRECTLY_SUPPORTED`]
- `AUTH-002` -> `T1078` (Valid Accounts) [`REQUIRES_ANALYST_REVIEW` with Decoy Simulation Warning]
- `AUTH-003` -> `T1087` (Account Discovery) [`PARTIALLY_SUPPORTED`]
- `WEB-001` -> `T1083` (File and Directory Discovery) [`PARTIALLY_SUPPORTED`]
- `WEB-002` -> `T1190` (Exploit Public-Facing Application) [`PARTIALLY_SUPPORTED`]
- `CMD-001`, `FILE-001`, `WEB-003`, `BEHAV-001`, `BEHAV-002` -> [`NOT_MAPPED`] (Deferred or lacking specificity)

### 12.3 Running Mapping Tests
```powershell
cd c:\Projects\SnareSight\backend
python -m unittest discover -s tests/modules/mitre -v
```

---

## 13. Session-Based Event Correlation & Investigation Timelines (Phase 5 — P21)

### 13.1 Correlation Architecture & Subsystem
- **Core Concept:** Groups discrete, validated honeypot telemetry into continuous `ActivitySession` interaction lifecycles and provides unified, chronological `SessionTimeline` investigation sequences.
- **Layered Identity Resolution Hierarchy (`app/correlation/identity.py`):**
  - **Level 1 (Explicit Session ID):** High-confidence compound key `{decoy_id}:{honeypot_type}:{explicit_session_id}`.
  - **Level 2 (Explicit Connection ID):** High-confidence connection key `{decoy_id}:conn:{connection_id}`.
  - **Level 3 (Controlled Fallback Key):** Contextual tuple `{source_address}:{decoy_id}:{target_service}`. Source IP alone is NEVER sufficient to merge sessions.
  - **Level 4 (Standalone Isolation):** Insufficient signals or `0.0.0.0` isolate into a dedicated single-event session (`standalone:{event_id}`).
- **Temporal Boundaries & Policy (`app/correlation/policy.py`):**
  - Inactivity window: 1800s (30 minutes). Exceeding idle threshold closes session as `TIMED_OUT` and spawns a new session.
  - Max duration: 43200s (12 hours) total session lifetime ceiling.
  - Clock skew tolerance: 300s (5 minutes) for out-of-order / late-arriving event attachments.
- **Investigation Timeline Builder (`app/correlation/timeline.py`):**
  - Chronological assembly of telemetry events, detection alerts, and evidence-backed ATT&CK mappings.
  - Deterministic tie-breaking: timestamp ascending -> telemetry events -> detection findings -> intelligence mappings.
- **REST Endpoints (`app/correlation/routes.py`):**
  - `GET /api/v1/sessions` - Paginated activity sessions with filtering.
  - `GET /api/v1/sessions/statistics` - Aggregated operational and lifecycle metrics.
  - `GET /api/v1/sessions/{session_id}` - Detailed session information.
  - `GET /api/v1/sessions/{session_id}/timeline` - Chronological investigation timeline.
  - `GET /api/v1/sessions/{session_id}/events` - Correlated security events.
  - `GET /api/v1/sessions/{session_id}/detections` - Associated alerts and severity findings.
  - `GET /api/v1/sessions/{session_id}/mitre-mappings` - Associated MITRE ATT&CK technique mappings.

### 13.2 Running Session Correlation Tests
```powershell
cd c:\Projects\SnareSight\backend
$env:PYTHONPATH = "c:\Projects\SnareSight\backend"
python -m unittest discover -s tests/modules/correlation -v
```

---

## 14. Multi-Session Behavioral Sequences & Attack-Chain Analysis (Phase 5 — P22)

### 14.1 Behavioral Progression Subsystem (`app/modules/correlation/`)
- **Core Concept:** Groups discrete honeypot activity sessions into explainable `BehavioralSequence` candidates and models progression across multiple interaction sessions.
- **Strict Scope Guardrails:** A behavioral sequence is an analytical hypothesis. It does NOT establish human identity, prove malicious intent, demonstrate causation, or confirm compromise. IP address alone is NEVER sufficient to merge sessions into an attack chain.
- **Recognized Multi-Session Patterns (`sequence_policy.py`):**
  - `REPEATED_AUTHENTICATION`: Multi-session credential brute-forcing.
  - `AUTH_THEN_ENUMERATION`: Authentication attempts preceding directory or account discovery.
  - `ENUMERATION_THEN_EXPLOIT`: Discovery scanning followed by targeted exploit probes.
  - `MULTI_TECHNIQUE_PROGRESSION`: Sequential progression across ATT&CK techniques (`T1110` -> `T1083` -> `T1190`).
  - `RECURRING_HONEYPOT_TARGET`: Recurring interaction sequences against a specific decoy instance.
  - `CROSS_PROTOCOL_INTERACTION`: Coordinated activity across distinct honeypots (Web + SSH) with detections.
- **Dual Scoring Model (`sequence_scoring.py`):**
  - `correlation_confidence`: Evidential linkage strength across sessions (0–100).
  - `sequence_relevance`: Operational SOC investigation priority (0–100).
  - Independent from event severity and detection confidence.
- **Lifecycle & Assessment (`sequence_service.py`):**
  - Controlled lifecycle states: `NEW`, `OBSERVING`, `UNDER_REVIEW`, `REVIEWED`, `CLOSED`, `DISMISSED`.
  - Structured analyst assessment: `CONFIRMED_PROGRESSION`, `DISMISSED_COINCIDENCE`, `INCONCLUSIVE`.
- **REST Endpoints (`sequence_routes.py`):**
  - `GET /api/v1/sequences` - Paginated sequence list with server-side filters.
  - `GET /api/v1/sequences/statistics` - Aggregate operational metrics across patterns and severities.
  - `GET /api/v1/sequences/{id}` - Full sequence details with members, edges, and evidence.
  - `GET /api/v1/sequences/{id}/timeline` - Multi-session chronological investigation timeline.
  - `GET /api/v1/sequences/{id}/evidence` - Field-level evidence traces justifying links.
  - `GET /api/v1/sequences/{id}/sessions` - Linked ActivitySession records.
  - `GET /api/v1/sequences/{id}/detections` - Associated Alert findings.
  - `GET /api/v1/sequences/{id}/mitre` - Relevant ATT&CK technique mappings.
  - `POST /api/v1/sequences/{id}/assessment` - Record authorized analyst assessment with required justification.
  - `POST /api/v1/sequences/{id}/status` - Transition sequence lifecycle state.

### 14.2 Running Behavioral Sequence Tests
```powershell
cd c:\Projects\SnareSight\backend
$env:PYTHONPATH = "c:\Projects\SnareSight\backend"
python -m unittest discover -s tests/modules/sequence -v
```

---

## 15. Formal Architecture, Security & Detection Documentation
- [P22_EXISTING_PROJECT_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/correlation/P22_EXISTING_PROJECT_ASSESSMENT.md)
- [BEHAVIORAL_SEQUENCE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/correlation/BEHAVIORAL_SEQUENCE_ARCHITECTURE.md)
- [CROSS_SESSION_CORRELATION_POLICY.md](file:///c:/Projects/SnareSight/docs/correlation/CROSS_SESSION_CORRELATION_POLICY.md)
- [SEQUENCE_DATA_MODEL.md](file:///c:/Projects/SnareSight/docs/correlation/SEQUENCE_DATA_MODEL.md)
- [SEQUENCE_EVIDENCE_AND_EXPLAINABILITY.md](file:///c:/Projects/SnareSight/docs/correlation/SEQUENCE_EVIDENCE_AND_EXPLAINABILITY.md)
- [SEQUENCE_SCORING.md](file:///c:/Projects/SnareSight/docs/correlation/SEQUENCE_SCORING.md)
- [SEQUENCE_API.md](file:///c:/Projects/SnareSight/docs/correlation/SEQUENCE_API.md)
- [P22_TEST_REPORT.md](file:///c:/Projects/SnareSight/docs/correlation/P22_TEST_REPORT.md)
- [P21_EXISTING_PROJECT_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/correlation/P21_EXISTING_PROJECT_ASSESSMENT.md)
- [SESSION_CORRELATION_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/correlation/SESSION_CORRELATION_ARCHITECTURE.md)
- [CORRELATION_POLICY.md](file:///c:/Projects/SnareSight/docs/correlation/CORRELATION_POLICY.md)
- [SESSION_DATA_MODEL.md](file:///c:/Projects/SnareSight/docs/correlation/SESSION_DATA_MODEL.md)
- [INVESTIGATION_TIMELINE.md](file:///c:/Projects/SnareSight/docs/correlation/INVESTIGATION_TIMELINE.md)
- [TIMESTAMP_AND_LATE_EVENT_HANDLING.md](file:///c:/Projects/SnareSight/docs/correlation/TIMESTAMP_AND_LATE_EVENT_HANDLING.md)
- [SESSION_API.md](file:///c:/Projects/SnareSight/docs/correlation/SESSION_API.md)
- [P21_TEST_REPORT.md](file:///c:/Projects/SnareSight/docs/correlation/P21_TEST_REPORT.md)
- [P20_EXISTING_PROJECT_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/mitre/P20_EXISTING_PROJECT_ASSESSMENT.md)
- [P20_MAPPING_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/mitre/P20_MAPPING_ARCHITECTURE.md)
- [MAPPING_REGISTRY.md](file:///c:/Projects/SnareSight/docs/mitre/MAPPING_REGISTRY.md)
- [MAPPING_EVIDENCE_POLICY.md](file:///c:/Projects/SnareSight/docs/mitre/MAPPING_EVIDENCE_POLICY.md)
- [MAPPING_CONFIDENCE_POLICY.md](file:///c:/Projects/SnareSight/docs/mitre/MAPPING_CONFIDENCE_POLICY.md)
- [ANALYST_REVIEW_WORKFLOW.md](file:///c:/Projects/SnareSight/docs/mitre/ANALYST_REVIEW_WORKFLOW.md)
- [MAPPING_VERSIONING.md](file:///c:/Projects/SnareSight/docs/mitre/MAPPING_VERSIONING.md)
- [P20_TEST_REPORT.md](file:///c:/Projects/SnareSight/docs/mitre/P20_TEST_REPORT.md)
- [P19_EXISTING_PROJECT_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/mitre/P19_EXISTING_PROJECT_ASSESSMENT.md)
- [MITRE_INTEGRATION.md](file:///c:/Projects/SnareSight/docs/mitre/MITRE_INTEGRATION.md)
- [DATA_MODEL.md](file:///c:/Projects/SnareSight/docs/mitre/DATA_MODEL.md)
- [DATA_IMPORT_RUNBOOK.md](file:///c:/Projects/SnareSight/docs/mitre/DATA_IMPORT_RUNBOOK.md)
- [DATA_UPDATE_AND_ROLLBACK.md](file:///c:/Projects/SnareSight/docs/mitre/DATA_UPDATE_AND_ROLLBACK.md)
- [DATA_PROVENANCE.md](file:///c:/Projects/SnareSight/docs/mitre/DATA_PROVENANCE.md)
- [DETECTION_SCENARIO_CATALOGUE.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_SCENARIO_CATALOGUE.md)
- [AUTHENTICATION_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/AUTHENTICATION_DETECTION.md)
- [DECOY_AUTHENTICATION_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/DECOY_AUTHENTICATION_DETECTION.md)
- [USERNAME_ENUMERATION_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/USERNAME_ENUMERATION_DETECTION.md)
- [WEB_PATH_ENUMERATION_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/WEB_PATH_ENUMERATION_DETECTION.md)
- [DIRECTORY_TRAVERSAL_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/DIRECTORY_TRAVERSAL_DETECTION.md)
- [COMMAND_DISCOVERY_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/COMMAND_DISCOVERY_DETECTION.md)
- [FILE_TRANSFER_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/FILE_TRANSFER_DETECTION.md)
- [SUSPICIOUS_REQUEST_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/SUSPICIOUS_REQUEST_DETECTION.md)
- [MULTI_CATEGORY_BEHAVIOR_DETECTION.md](file:///c:/Projects/SnareSight/docs/detection/MULTI_CATEGORY_BEHAVIOR_DETECTION.md)
- [FALSE_POSITIVE_HANDLING.md](file:///c:/Projects/SnareSight/docs/detection/FALSE_POSITIVE_HANDLING.md)
- [DETECTION_THRESHOLD_CONFIGURATION.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_THRESHOLD_CONFIGURATION.md)
- [DETECTION_SCENARIO_TEST_PLAN.md](file:///c:/Projects/SnareSight/docs/testing/DETECTION_SCENARIO_TEST_PLAN.md)
- [DETECTION_SCENARIO_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/DETECTION_SCENARIO_TEST_RESULTS.md)
- [DETECTION_QUALITY_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/testing/DETECTION_QUALITY_ASSESSMENT.md)
- [DETECTION_RULE_SECURITY_REVIEW.md](file:///c:/Projects/SnareSight/docs/security/DETECTION_RULE_SECURITY_REVIEW.md)
- [SEVERITY_CLASSIFICATION.md](file:///c:/Projects/SnareSight/docs/detection/SEVERITY_CLASSIFICATION.md)
- [CONFIDENCE_SCORING.md](file:///c:/Projects/SnareSight/docs/detection/CONFIDENCE_SCORING.md)
- [EVIDENCE_STRENGTH_MODEL.md](file:///c:/Projects/SnareSight/docs/detection/EVIDENCE_STRENGTH_MODEL.md)
- [SCORING_POLICY_CONFIGURATION.md](file:///c:/Projects/SnareSight/docs/detection/SCORING_POLICY_CONFIGURATION.md)
- [SCORING_EXPLANATIONS.md](file:///c:/Projects/SnareSight/docs/detection/SCORING_EXPLANATIONS.md)
- [ASSESSMENT_HISTORY.md](file:///c:/Projects/SnareSight/docs/detection/ASSESSMENT_HISTORY.md)
- [ANALYST_REVIEW_MODEL.md](file:///c:/Projects/SnareSight/docs/detection/ANALYST_REVIEW_MODEL.md)
- [THREAT_ASSESSMENT_DATABASE.md](file:///c:/Projects/SnareSight/docs/database/THREAT_ASSESSMENT_DATABASE.md)
- [SCORING_ENGINE_SECURITY.md](file:///c:/Projects/SnareSight/docs/security/SCORING_ENGINE_SECURITY.md)
- [EVIDENCE_INTEGRITY.md](file:///c:/Projects/SnareSight/docs/security/EVIDENCE_INTEGRITY.md)
- [SCORING_TEST_PLAN.md](file:///c:/Projects/SnareSight/docs/testing/SCORING_TEST_PLAN.md)
- [SCORING_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/SCORING_TEST_RESULTS.md)
- [SCORING_CALIBRATION_LIMITATIONS.md](file:///c:/Projects/SnareSight/docs/testing/SCORING_CALIBRATION_LIMITATIONS.md)
- [DETECTION_ENGINE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_ENGINE_ARCHITECTURE.md)
- [DETECTION_RULE_SCHEMA.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_RULE_SCHEMA.md)
- [RULE_VALIDATION.md](file:///c:/Projects/SnareSight/docs/detection/RULE_VALIDATION.md)
- [RULE_REGISTRY.md](file:///c:/Projects/SnareSight/docs/detection/RULE_REGISTRY.md)
- [DETECTION_EVALUATION.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_EVALUATION.md)
- [SESSION_EVALUATION.md](file:///c:/Projects/SnareSight/docs/detection/SESSION_EVALUATION.md)
- [TIME_WINDOW_EVALUATION.md](file:///c:/Projects/SnareSight/docs/detection/TIME_WINDOW_EVALUATION.md)
- [DETECTION_RESULT_MODEL.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_RESULT_MODEL.md)
- [DETECTION_EXECUTION_HISTORY.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_EXECUTION_HISTORY.md)
- [DETECTION_TESTING.md](file:///c:/Projects/SnareSight/docs/detection/DETECTION_TESTING.md)
- [DETECTION_DATABASE_DESIGN.md](file:///c:/Projects/SnareSight/docs/database/DETECTION_DATABASE_DESIGN.md)
- [DETECTION_ENGINE_SECURITY.md](file:///c:/Projects/SnareSight/docs/security/DETECTION_ENGINE_SECURITY.md)
- [RULE_EXECUTION_SAFETY.md](file:///c:/Projects/SnareSight/docs/security/RULE_EXECUTION_SAFETY.md)
- [DETECTION_EVIDENCE_INTEGRITY.md](file:///c:/Projects/SnareSight/docs/security/DETECTION_EVIDENCE_INTEGRITY.md)
- [REALTIME_EVENT_STREAMING.md](file:///c:/Projects/SnareSight/docs/architecture/REALTIME_EVENT_STREAMING.md)
- [SSE_EVENT_LIFECYCLE.md](file:///c:/Projects/SnareSight/docs/architecture/SSE_EVENT_LIFECYCLE.md)
- [EVENT_RECONNECTION_AND_REPLAY.md](file:///c:/Projects/SnareSight/docs/architecture/EVENT_RECONNECTION_AND_REPLAY.md)
- [SSE_AUTHENTICATION_AND_AUTHORIZATION.md](file:///c:/Projects/SnareSight/docs/security/SSE_AUTHENTICATION_AND_AUTHORIZATION.md)
- [STREAMING_RESOURCE_PROTECTION.md](file:///c:/Projects/SnareSight/docs/security/STREAMING_RESOURCE_PROTECTION.md)
- [PIPELINE_HEALTH_MONITORING.md](file:///c:/Projects/SnareSight/docs/operations/PIPELINE_HEALTH_MONITORING.md)
- [COMPONENT_HEALTH_STANDARDS.md](file:///c:/Projects/SnareSight/docs/operations/COMPONENT_HEALTH_STANDARDS.md)
- [OPERATIONAL_DIAGNOSTICS.md](file:///c:/Projects/SnareSight/docs/operations/OPERATIONAL_DIAGNOSTICS.md)
- [SSE_TEST_PLAN.md](file:///c:/Projects/SnareSight/docs/testing/SSE_TEST_PLAN.md)
- [SSE_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/SSE_TEST_RESULTS.md)
- [PIPELINE_HEALTH_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/PIPELINE_HEALTH_TEST_RESULTS.md)
- [EVENT_NORMALIZATION_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/architecture/EVENT_NORMALIZATION_ARCHITECTURE.md)
- [CROSS_SOURCE_EVENT_ADAPTERS.md](file:///c:/Projects/SnareSight/docs/architecture/CROSS_SOURCE_EVENT_ADAPTERS.md)
- [EVENT_REPROCESSING.md](file:///c:/Projects/SnareSight/docs/architecture/EVENT_REPROCESSING.md)
- [EVENT_DEDUPLICATION.md](file:///c:/Projects/SnareSight/docs/database/EVENT_DEDUPLICATION.md)
- [EVENT_RETENTION_POLICY.md](file:///c:/Projects/SnareSight/docs/database/EVENT_RETENTION_POLICY.md)
- [DATA_LIFECYCLE_MANAGEMENT.md](file:///c:/Projects/SnareSight/docs/database/DATA_LIFECYCLE_MANAGEMENT.md)
- [EVIDENCE_PRESERVATION.md](file:///c:/Projects/SnareSight/docs/database/EVIDENCE_PRESERVATION.md)
- [DATABASE_ARCHIVAL.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_ARCHIVAL.md)
- [EVENT_DATA_PRESERVATION.md](file:///c:/Projects/SnareSight/docs/security/EVENT_DATA_PRESERVATION.md)
- [RETENTION_SECURITY.md](file:///c:/Projects/SnareSight/docs/security/RETENTION_SECURITY.md)
- [DATA_DELETION_AUDIT.md](file:///c:/Projects/SnareSight/docs/security/DATA_DELETION_AUDIT.md)
- [NORMALIZATION_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/NORMALIZATION_TEST_RESULTS.md)
- [DEDUPLICATION_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/DEDUPLICATION_TEST_RESULTS.md)
- [RETENTION_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/RETENTION_TEST_RESULTS.md)
- [EVENT_INGESTION_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/architecture/EVENT_INGESTION_ARCHITECTURE.md)
- [TELEMETRY_TRANSFER_GUIDE.md](file:///c:/Projects/SnareSight/docs/architecture/TELEMETRY_TRANSFER_GUIDE.md)
- [EVENT_NORMALIZATION_FLOW.md](file:///c:/Projects/SnareSight/docs/architecture/EVENT_NORMALIZATION_FLOW.md)
- [EVENT_PERSISTENCE.md](file:///c:/Projects/SnareSight/docs/database/EVENT_PERSISTENCE.md)
- [INGESTION_DATABASE_MAPPING.md](file:///c:/Projects/SnareSight/docs/database/INGESTION_DATABASE_MAPPING.md)
- [INGESTION_IDEMPOTENCY.md](file:///c:/Projects/SnareSight/docs/database/INGESTION_IDEMPOTENCY.md)
- [INGESTION_SECURITY.md](file:///c:/Projects/SnareSight/docs/security/INGESTION_SECURITY.md)
- [EVENT_VALIDATION_POLICY.md](file:///c:/Projects/SnareSight/docs/security/EVENT_VALIDATION_POLICY.md)
- [SENSITIVE_DATA_REJECTION.md](file:///c:/Projects/SnareSight/docs/security/SENSITIVE_DATA_REJECTION.md)
- [INGESTION_ACCESS_CONTROL.md](file:///c:/Projects/SnareSight/docs/security/INGESTION_ACCESS_CONTROL.md)
- [INGESTION_TEST_PLAN.md](file:///c:/Projects/SnareSight/docs/testing/INGESTION_TEST_PLAN.md)
- [INGESTION_TEST_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/INGESTION_TEST_RESULTS.md)
- [END_TO_END_INGESTION_RESULTS.md](file:///c:/Projects/SnareSight/docs/testing/END_TO_END_INGESTION_RESULTS.md)
- [POSTGRESQL_SETUP.md](file:///c:/Projects/SnareSight/docs/database/POSTGRESQL_SETUP.md)
- [DATABASE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_ARCHITECTURE.md)
- [DATABASE_TABLES.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_TABLES.md)
- [DATABASE_RELATIONSHIPS.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_RELATIONSHIPS.md)
- [DATABASE_INDEXING.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_INDEXING.md)
- [DATABASE_SECURITY.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_SECURITY.md)
- [DATABASE_MIGRATIONS.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_MIGRATIONS.md)
- [DATABASE_BACKUP_RECOVERY.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_BACKUP_RECOVERY.md)
- [DATABASE_TESTING.md](file:///c:/Projects/SnareSight/docs/database/DATABASE_TESTING.md)
- [SOURCE_INTELLIGENCE_README.md](file:///c:/Projects/SnareSight/docs/source-intelligence/README.md)
- [SOURCE_INTELLIGENCE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/source-intelligence/architecture.md)
- [SOURCE_PROFILE_DATA_MODEL.md](file:///c:/Projects/SnareSight/docs/source-intelligence/profile-data-model.md)
- [SOURCE_ASSOCIATION_POLICY.md](file:///c:/Projects/SnareSight/docs/source-intelligence/association-policy.md)
- [BEHAVIORAL_FEATURES.md](file:///c:/Projects/SnareSight/docs/source-intelligence/behavioral-features.md)
- [SIMILARITY_METHOD.md](file:///c:/Projects/SnareSight/docs/source-intelligence/similarity-method.md)
- [PRIORITIZATION_POLICY.md](file:///c:/Projects/SnareSight/docs/source-intelligence/prioritization-policy.md)
- [SOURCE_INTELLIGENCE_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/source-intelligence/api-reference.md)
- [SOURCE_INTELLIGENCE_SECURITY_AND_PRIVACY.md](file:///c:/Projects/SnareSight/docs/source-intelligence/security-and-privacy.md)
- [SOURCE_INTELLIGENCE_TESTING.md](file:///c:/Projects/SnareSight/docs/source-intelligence/testing.md)
- [CAMPAIGN_INTELLIGENCE_README.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/README.md)
- [CAMPAIGN_INTELLIGENCE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/architecture.md)
- [CAMPAIGN_INTELLIGENCE_DATA_MODEL.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/data-model.md)
- [CAMPAIGN_CLUSTERING_METHODOLOGY.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/clustering-methodology.md)
- [CAMPAIGN_SCORING_POLICY.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/scoring-policy.md)
- [CAMPAIGN_LIFECYCLE_STATE_MACHINE.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/lifecycle.md)
- [CAMPAIGN_MERGE_AND_SPLIT.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/merge-and-split.md)
- [CAMPAIGN_INVESTIGATION_TIMELINE.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/investigation-timeline.md)
- [CAMPAIGN_INTELLIGENCE_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/api-reference.md)
- [CAMPAIGN_SECURITY_AND_PRIVACY.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/security-and-privacy.md)
- [CAMPAIGN_INTELLIGENCE_TESTING.md](file:///c:/Projects/SnareSight/docs/campaign-intelligence/testing.md)
- [SECURITY_EVENTS_README.md](file:///c:/Projects/SnareSight/docs/security-events/README.md)
- [SECURITY_EVENTS_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/security-events/architecture.md)
- [SECURITY_EVENTS_SEARCH_AND_FILTERS.md](file:///c:/Projects/SnareSight/docs/security-events/search-and-filters.md)
- [SECURITY_EVENTS_DETAIL.md](file:///c:/Projects/SnareSight/docs/security-events/event-detail.md)
- [SECURITY_EVENTS_RELATIONSHIPS.md](file:///c:/Projects/SnareSight/docs/security-events/relationships.md)
- [SECURITY_EVENTS_TIMELINE.md](file:///c:/Projects/SnareSight/docs/security-events/timeline.md)
- [SECURITY_EVENTS_EVIDENCE_PROVENANCE.md](file:///c:/Projects/SnareSight/docs/security-events/evidence-provenance.md)
- [SECURITY_EVENTS_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/security-events/api-reference.md)
- [SECURITY_EVENTS_SECURITY_AND_PRIVACY.md](file:///c:/Projects/SnareSight/docs/security-events/security-and-privacy.md)
- [SECURITY_EVENTS_TESTING.md](file:///c:/Projects/SnareSight/docs/security-events/testing.md)
- [ALERT_MANAGEMENT_README.md](file:///c:/Projects/SnareSight/docs/alert-management/README.md)
- [ALERT_MANAGEMENT_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/alert-management/architecture.md)
- [ALERT_MANAGEMENT_LIFECYCLE.md](file:///c:/Projects/SnareSight/docs/alert-management/alert-lifecycle.md)
- [ALERT_MANAGEMENT_TRIAGE_WORKFLOW.md](file:///c:/Projects/SnareSight/docs/alert-management/triage-workflow.md)
- [ALERT_MANAGEMENT_PRIORITIZATION.md](file:///c:/Projects/SnareSight/docs/alert-management/prioritization.md)
- [ALERT_MANAGEMENT_EVIDENCE_AND_CONTEXT.md](file:///c:/Projects/SnareSight/docs/alert-management/evidence-and-context.md)
- [ALERT_MANAGEMENT_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/alert-management/api-reference.md)
- [ALERT_MANAGEMENT_AUDIT_AND_SECURITY.md](file:///c:/Projects/SnareSight/docs/alert-management/audit-and-security.md)
- [ALERT_MANAGEMENT_TESTING.md](file:///c:/Projects/SnareSight/docs/alert-management/testing.md)

- [MITRE_ATTACK_README.md](file:///c:/Projects/SnareSight/docs/mitre-attack/README.md)
- [MITRE_ATTACK_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/mitre-attack/architecture.md)
- [MITRE_ATTACK_CATALOGUE.md](file:///c:/Projects/SnareSight/docs/mitre-attack/catalogue.md)
- [MITRE_ATTACK_MATRIX.md](file:///c:/Projects/SnareSight/docs/mitre-attack/matrix.md)
- [MITRE_ATTACK_MAPPING_METHODOLOGY.md](file:///c:/Projects/SnareSight/docs/mitre-attack/mapping-methodology.md)
- [MITRE_ATTACK_EVIDENCE_TRACEABILITY.md](file:///c:/Projects/SnareSight/docs/mitre-attack/evidence-traceability.md)
- [MITRE_ATTACK_COVERAGE_METRICS.md](file:///c:/Projects/SnareSight/docs/mitre-attack/coverage-metrics.md)
- [MITRE_ATTACK_REVIEW_WORKFLOW.md](file:///c:/Projects/SnareSight/docs/mitre-attack/review-workflow.md)
- [MITRE_ATTACK_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/mitre-attack/api-reference.md)
- [MITRE_ATTACK_SECURITY_AND_TESTING.md](file:///c:/Projects/SnareSight/docs/mitre-attack/security-and-testing.md)

- [ANALYTICS_README.md](file:///c:/Projects/SnareSight/docs/analytics/README.md)
- [ANALYTICS_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/analytics/architecture.md)
- [ANALYTICS_METRIC_DEFINITIONS.md](file:///c:/Projects/SnareSight/docs/analytics/metric-definitions.md)
- [ANALYTICS_EVENT_AND_ALERT.md](file:///c:/Projects/SnareSight/docs/analytics/event-and-alert-analytics.md)
- [ANALYTICS_DETECTION.md](file:///c:/Projects/SnareSight/docs/analytics/detection-analytics.md)
- [ANALYTICS_SESSION_AND_INVESTIGATION.md](file:///c:/Projects/SnareSight/docs/analytics/session-and-investigation-analytics.md)
- [ANALYTICS_ATTACK_COVERAGE.md](file:///c:/Projects/SnareSight/docs/analytics/attack-coverage.md)
- [ANALYTICS_SENSOR_AND_PIPELINE_HEALTH.md](file:///c:/Projects/SnareSight/docs/analytics/sensor-and-pipeline-health.md)
- [ANALYTICS_REPORT_GENERATION.md](file:///c:/Projects/SnareSight/docs/analytics/report-generation.md)
- [ANALYTICS_SECURITY_AND_TESTING.md](file:///c:/Projects/SnareSight/docs/analytics/security-and-testing.md)

- [SECURITY_HARDENING_README.md](file:///c:/Projects/SnareSight/docs/security/README.md)
- [SECURITY_THREAT_MODEL.md](file:///c:/Projects/SnareSight/docs/security/threat-model.md)
- [SECURITY_AUTHENTICATION.md](file:///c:/Projects/SnareSight/docs/security/authentication.md)
- [SECURITY_AUTHORIZATION_RBAC.md](file:///c:/Projects/SnareSight/docs/security/authorization.md)
- [SECURITY_API_CONTROLS.md](file:///c:/Projects/SnareSight/docs/security/api-security.md)
- [SECURITY_FRONTEND_CONTROLS.md](file:///c:/Projects/SnareSight/docs/security/frontend-security.md)
- [SECURITY_DATABASE_CONTROLS.md](file:///c:/Projects/SnareSight/docs/security/database-security.md)
- [SECURITY_HONEYPOT_ISOLATION.md](file:///c:/Projects/SnareSight/docs/security/honeypot-isolation.md)
- [SECURITY_SSE_CONTROLS.md](file:///c:/Projects/SnareSight/docs/security/sse-security.md)
- [SECURITY_AUDIT_LOGGING.md](file:///c:/Projects/SnareSight/docs/security/audit-logging.md)
- [SECURITY_DEPLOYMENT_HARDENING.md](file:///c:/Projects/SnareSight/docs/security/deployment-hardening.md)
- [SECURITY_SECRETS_MANAGEMENT.md](file:///c:/Projects/SnareSight/docs/security/secrets-management.md)
- [SECURITY_DEPENDENCY_AUDIT.md](file:///c:/Projects/SnareSight/docs/security/dependency-security.md)
- [SECURITY_TESTING_SUITE.md](file:///c:/Projects/SnareSight/docs/security/security-testing.md)

- [DEFENSIVE_RESPONSE_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/defensive-response/implementation-assessment.md)
- [DEFENSIVE_RESPONSE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/defensive-response/architecture.md)
- [DEFENSIVE_RESPONSE_CASE_LIFECYCLE.md](file:///c:/Projects/SnareSight/docs/defensive-response/response-case-lifecycle.md)
- [DEFENSIVE_RESPONSE_RECOMMENDATION_ENGINE.md](file:///c:/Projects/SnareSight/docs/defensive-response/recommendation-engine.md)
- [DEFENSIVE_RESPONSE_PLAYBOOKS.md](file:///c:/Projects/SnareSight/docs/defensive-response/playbooks.md)
- [DEFENSIVE_RESPONSE_APPROVAL_WORKFLOW.md](file:///c:/Projects/SnareSight/docs/defensive-response/approval-workflow.md)
- [DEFENSIVE_RESPONSE_EVIDENCE_PRESERVATION.md](file:///c:/Projects/SnareSight/docs/defensive-response/evidence-preservation.md)
- [DEFENSIVE_RESPONSE_SECURITY_CONTROLS.md](file:///c:/Projects/SnareSight/docs/defensive-response/security-controls.md)
- [DEFENSIVE_RESPONSE_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/defensive-response/api-reference.md)
- [DEFENSIVE_RESPONSE_TESTING.md](file:///c:/Projects/SnareSight/docs/defensive-response/testing.md)
- [DEFENSIVE_RESPONSE_P32_COMPLETION_REPORT.md](file:///c:/Projects/SnareSight/docs/defensive-response/P32-completion-report.md)

- [SENSOR_MANAGEMENT_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/sensor-management/implementation-assessment.md)
- [SENSOR_MANAGEMENT_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/sensor-management/architecture.md)
- [SENSOR_REGISTRATION.md](file:///c:/Projects/SnareSight/docs/sensor-management/sensor-registration.md)
- [SENSOR_AUTHENTICATION.md](file:///c:/Projects/SnareSight/docs/sensor-management/authentication.md)
- [SENSOR_HEALTH_MONITORING.md](file:///c:/Projects/SnareSight/docs/sensor-management/health-monitoring.md)
- [SENSOR_TELEMETRY_RELIABILITY.md](file:///c:/Projects/SnareSight/docs/sensor-management/telemetry-reliability.md)
- [SENSOR_CONFIGURATION_MANAGEMENT.md](file:///c:/Projects/SnareSight/docs/sensor-management/configuration-management.md)
- [SENSOR_OPERATIONAL_ALERTS.md](file:///c:/Projects/SnareSight/docs/sensor-management/operational-alerts.md)
- [SENSOR_SECURITY_BOUNDARIES.md](file:///c:/Projects/SnareSight/docs/sensor-management/security-boundaries.md)
- [SENSOR_API_REFERENCE.md](file:///c:/Projects/SnareSight/docs/sensor-management/api-reference.md)
- [SENSOR_TESTING.md](file:///c:/Projects/SnareSight/docs/sensor-management/testing.md)
- [SENSOR_P33_COMPLETION_REPORT.md](file:///c:/Projects/SnareSight/docs/sensor-management/P33-completion-report.md)

- [RESILIENCE_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/operational-resilience/implementation-assessment.md)
- [RESILIENCE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/operational-resilience/architecture.md)
- [RESILIENCE_INTERNAL_SECURITY_MONITORING.md](file:///c:/Projects/SnareSight/docs/operational-resilience/internal-security-monitoring.md)
- [RESILIENCE_HEALTH_CHECKS.md](file:///c:/Projects/SnareSight/docs/operational-resilience/health-checks.md)
- [RESILIENCE_BACKUP_POLICY.md](file:///c:/Projects/SnareSight/docs/operational-resilience/backup-policy.md)
- [RESILIENCE_BACKUP_VERIFICATION.md](file:///c:/Projects/SnareSight/docs/operational-resilience/backup-verification.md)
- [RESILIENCE_DISASTER_RECOVERY.md](file:///c:/Projects/SnareSight/docs/operational-resilience/disaster-recovery.md)
- [RESILIENCE_AUDIT_RESILIENCE.md](file:///c:/Projects/SnareSight/docs/operational-resilience/audit-resilience.md)
- [RESILIENCE_LOGGING.md](file:///c:/Projects/SnareSight/docs/operational-resilience/logging.md)
- [RESILIENCE_INCIDENT_WORKFLOWS.md](file:///c:/Projects/SnareSight/docs/operational-resilience/incident-workflows.md)
- [RESILIENCE_SECURITY_TESTING.md](file:///c:/Projects/SnareSight/docs/operational-resilience/security-testing.md)
- [RESILIENCE_P34_COMPLETION_REPORT.md](file:///c:/Projects/SnareSight/docs/operational-resilience/P34-completion-report.md)

- [TESTING_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/testing/project-test-assessment.md)
- [TESTING_STRATEGY.md](file:///c:/Projects/SnareSight/docs/testing/test-strategy.md)
- [TESTING_DEFECT_REGISTER.md](file:///c:/Projects/SnareSight/docs/testing/defect-register.md)
- [TESTING_BACKEND.md](file:///c:/Projects/SnareSight/docs/testing/backend-testing.md)
- [TESTING_API.md](file:///c:/Projects/SnareSight/docs/testing/api-testing.md)
- [TESTING_FRONTEND.md](file:///c:/Projects/SnareSight/docs/testing/frontend-testing.md)
- [TESTING_END_TO_END.md](file:///c:/Projects/SnareSight/docs/testing/end-to-end-testing.md)
- [TESTING_SECURITY.md](file:///c:/Projects/SnareSight/docs/testing/security-testing.md)
- [TESTING_PERFORMANCE.md](file:///c:/Projects/SnareSight/docs/testing/performance-testing.md)
- [TESTING_EXECUTION_REPORT.md](file:///c:/Projects/SnareSight/docs/testing/test-execution-report.md)
- [TESTING_P35_COMPLETION_REPORT.md](file:///c:/Projects/SnareSight/docs/testing/P35-completion-report.md)

- [DEMO_READINESS_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/demo/DEMO_READINESS_ASSESSMENT.md)
- [DEMONSTRATION_SCENARIO.md](file:///c:/Projects/SnareSight/docs/demo/DEMONSTRATION_SCENARIO.md)
- [DETECTION_EVALUATION_METHODOLOGY.md](file:///c:/Projects/SnareSight/docs/demo/DETECTION_EVALUATION_METHODOLOGY.md)
- [DEMONSTRATION_RESULTS.md](file:///c:/Projects/SnareSight/docs/demo/DEMONSTRATION_RESULTS.md)
- [KNOWN_LIMITATIONS.md](file:///c:/Projects/SnareSight/docs/demo/KNOWN_LIMITATIONS.md)
- [DEMONSTRATION_RUNBOOK.md](file:///c:/Projects/SnareSight/docs/demo/DEMONSTRATION_RUNBOOK.md)
- [DEMO_P36_COMPLETION_REPORT.md](file:///c:/Projects/SnareSight/docs/demo/P36_COMPLETION_REPORT.md)

- [P37_INTEGRATION_AUDIT.md](file:///c:/Projects/SnareSight/docs/release/P37_INTEGRATION_AUDIT.md)
- [RELEASE_CANDIDATE_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/release/RELEASE_CANDIDATE_ARCHITECTURE.md)
- [DATABASE_RELEASE_CHECKLIST.md](file:///c:/Projects/SnareSight/docs/release/DATABASE_RELEASE_CHECKLIST.md)
- [REPRODUCIBLE_SETUP.md](file:///c:/Projects/SnareSight/docs/release/REPRODUCIBLE_SETUP.md)
- [RELEASE_SECURITY_REVIEW.md](file:///c:/Projects/SnareSight/docs/release/RELEASE_SECURITY_REVIEW.md)
- [RELEASE_PERFORMANCE_REPORT.md](file:///c:/Projects/SnareSight/docs/release/RELEASE_PERFORMANCE_REPORT.md)
- [OPERATIONAL_RESILIENCE_CHECKLIST.md](file:///c:/Projects/SnareSight/docs/release/OPERATIONAL_RESILIENCE_CHECKLIST.md)
- [P37_RELEASE_CANDIDATE_REPORT.md](file:///c:/Projects/SnareSight/docs/release/P37_RELEASE_CANDIDATE_REPORT.md)
