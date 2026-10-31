# SnareSight: Architecture Decision Records (ADRs)
**Document ID:** ARCH-010  
**Status:** Approved Architectural Decisions  

---

## Index of Records

* [ADR-001: Modular Monolith Architecture for Backend](#adr-001-modular-monolith-architecture-for-backend)
* [ADR-002: React and TypeScript for Frontend](#adr-002-react-and-typescript-for-frontend)
* [ADR-003: PostgreSQL as Primary Relational Database](#adr-003-postgresql-as-primary-relational-database)
* [ADR-004: SQLAlchemy ORM and Alembic Migrations](#adr-004-sqlalchemy-orm-and-alembic-migrations)
* [ADR-005: REST APIs and Server-Sent Events (SSE)](#adr-005-rest-apis-and-server-sent-events-sse)
* [ADR-006: Adapter-Based Honeypot Decoy Integration](#adr-006-adapter-based-honeypot-decoy-integration)
* [ADR-007: Separately Isolated Virtual Machine / Lab for Decoys](#adr-007-separately-isolated-virtual-machine--lab-for-decoys)
* [ADR-008: Explainable Rule-Based Threat Detection](#adr-008-explainable-rule-based-threat-detection)
* [ADR-009: Evidence-Backed MITRE ATT&CK Mapping](#adr-009-evidence-backed-mitre-attck-mapping)
* [ADR-010: Event Provenance & Source Classification](#adr-010-event-provenance--source-classification)
* [ADR-011: Strict Separation of Severity and Confidence](#adr-011-strict-separation-of-severity-and-confidence)
* [ADR-012: Controlled Simulation & Reproducible Test Harnesses](#adr-012-controlled-simulation--reproducible-test-harnesses)

---

### ADR-001: Modular Monolith Architecture for Backend
* **Context:** SnareSight requires multiple subsystems (ingestion, normalizer, detection, correlation, intelligence, case management).
* **Decision:** Build a single FastAPI modular monolith rather than microservices.
* **Alternatives Considered:** Distributed microservices (Kafka + individual services).
* **Advantages:** Minimal memory footprint (<300 MB), ultra-fast development, transactional integrity, no distributed network latency.
* **Disadvantages:** Modules share a single runtime process.
* **Security Implications:** Subsystems must enforce internal layer boundaries to prevent untrusted telemetry from accessing administrative services directly.
* **Status:** **APPROVED**.

### ADR-002: React and TypeScript for Frontend
* **Context:** The SOC dashboard requires high interactivity, dynamic graphs, and type safety.
* **Decision:** Use React with TypeScript, Vite, and Tailwind CSS.
* **Alternatives Considered:** Vanilla JavaScript, Vue, Angular, server-rendered templates (Jinja2).
* **Advantages:** Rich ecosystem for graph visualization (`React Flow`) and metrics (`Recharts`), strict compile-time type validation matching backend schemas.
* **Disadvantages:** Requires Node/npm build toolchain.
* **Status:** **APPROVED**.

### ADR-003: PostgreSQL as Primary Relational Database
* **Context:** Security events, alerts, and attack chains have complex relational hierarchies requiring foreign keys, indexing, and transactional ACID guarantees.
* **Decision:** Use PostgreSQL 16 as the primary datastore.
* **Alternatives Considered:** MongoDB (NoSQL), SQLite (embedded), Elasticsearch.
* **Advantages:** Robust JSONB support for raw event payloads combined with relational tables for alerts, attack chains, and case management.
* **Disadvantages:** Requires a running database process (container or service).
* **Status:** **APPROVED**.

### ADR-004: SQLAlchemy ORM and Alembic Migrations
* **Context:** Database models must be maintained in Python code with rigorous version-controlled schema migrations.
* **Decision:** Use SQLAlchemy 2.0 (async/sync) paired with Alembic migrations.
* **Alternatives Considered:** Raw SQL scripts, Tortoise ORM, Peewee.
* **Advantages:** Industry standard, type-annotated models, reproducible database migrations, strong security against SQL injection.
* **Status:** **APPROVED**.

### ADR-005: REST APIs and Server-Sent Events (SSE)
* **Context:** The frontend needs on-demand data retrieval (REST) and real-time alerts without high socket overhead.
* **Decision:** Use REST for query/command APIs and Server-Sent Events (SSE) for unidirectional live telemetry streaming.
* **Alternatives Considered:** WebSockets, Polling, gRPC.
* **Advantages:** SSE is natively supported by browsers via `EventSource`, automatically reconnects, operates seamlessly over standard HTTP/TLS, and does not require complex bidirectional state management.
* **Disadvantages:** Unidirectional (server-to-client only), which perfectly fits telemetry streaming.
* **Status:** **APPROVED**.

### ADR-006: Adapter-Based Honeypot Decoy Integration
* **Context:** SnareSight must support web decoys initially, followed by Cowrie SSH or other honeypots in future phases.
* **Decision:** Implement an adapter pattern. Decoys convert interaction logs into a unified Ingestion Schema before shipping to the API.
* **Alternatives Considered:** Hardcoding the API to specific web decoy logs.
* **Advantages:** Future honeypots (SSH, FTP, SMB) can be attached simply by implementing an adapter without changing backend detection or database logic.
* **Status:** **APPROVED**.

### ADR-007: Separately Isolated Virtual Machine / Lab for Decoys
* **Context:** Running deceptive services directly on the host machine risks local port contamination, unintended service interactions, or malware exposure.
* **Decision:** Operational honeypots must run inside an isolated virtual machine or private container network with zero bridged networking.
* **Alternatives Considered:** Running decoys natively on Windows host ports.
* **Advantages:** Complete network and process isolation; protects host OS and LAN.
* **Disadvantages:** Requires virtualization support (WSL 2 or VM).
* **Security Implications:** Eliminates host escape vector and prevents accidental exposure to physical LAN.
* **Status:** **APPROVED**.

### ADR-008: Explainable Rule-Based Threat Detection
* **Context:** Security analysts must understand exactly why an alert was triggered.
* **Decision:** Build deterministic, rule-based detection logic as the primary detection mechanism.
* **Alternatives Considered:** Opaque Machine Learning / Deep Learning anomaly models.
* **Advantages:** 100% explainable, zero false-positive hallucination, predictable execution time, direct evidentiary traceability.
* **Disadvantages:** Rules must be explicitly authored for supported attack patterns.
* **Status:** **APPROVED**.

### ADR-009: Evidence-Backed MITRE ATT&CK Mapping
* **Context:** Mappings to ATT&CK tactics and techniques must be credible and grounded in real telemetry.
* **Decision:** Only map techniques supported by concrete, verified event evidence.
* **Alternatives Considered:** Blanket speculative mappings based on decoy type.
* **Advantages:** High analytical integrity; prevents deceptive over-claiming of threat detection coverage.
* **Status:** **APPROVED**.

### ADR-010: Event Provenance & Source Classification
* **Context:** The system will process real honeypot interactions, seeded demonstration data, and synthetic test traffic.
* **Decision:** Every event must carry a mandatory `provenance` field (`live_honeypot`, `synthetic_demo`, `controlled_simulation`).
* **Alternatives Considered:** Implicit assumptions or unmarked mixing of test data.
* **Advantages:** Eliminates confusion between test runs and actual decoy hits; ensures absolute auditability.
* **Status:** **APPROVED**.

### ADR-011: Strict Separation of Severity and Confidence
* **Context:** A high-impact event (e.g. root authentication) might have low confidence (unverified scanner), while a low-impact event (ping scan) might have high confidence.
* **Decision:** Store and calculate `severity` (impact) and `confidence` (certainty) as two separate, independent metrics on all alerts.
* **Alternatives Considered:** A single blended risk score.
* **Advantages:** Empowers analysts to filter for high-confidence alerts during active triage while still preserving high-severity edge cases.
* **Status:** **APPROVED**.

### ADR-012: Controlled Simulation & Reproducible Test Harnesses
* **Context:** Decoys may not receive continuous live traffic during local development.
* **Decision:** Build offline, reproducible simulation scripts that inject realistic attack sequences (brute force, directory traversal) into the ingestion endpoint.
* **Alternatives Considered:** Manually attacking the decoy with external penetration tools.
* **Advantages:** Safe, repeatable, deterministic testing of the entire detection and visualization pipeline without external network tools.
* **Status:** **APPROVED**.

