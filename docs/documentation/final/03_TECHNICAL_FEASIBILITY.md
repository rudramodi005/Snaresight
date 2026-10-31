# Evaluation Criterion 3: Technical Feasibility & System Viability Assessment

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/03_TECHNICAL_FEASIBILITY.md`  
**Evaluation Weight:** 20% (Equal Weighting)  

---

## 1. Technical Feasibility Matrix Across 16 Dimensions

This feasibility assessment evaluates the 16 core architectural areas of SnareSight based strictly on measured code evidence and test results:

| # | System Area | Technology Used | Implementation Evidence | Test & Verification Evidence | Measured Constraints & Risks | Feasibility Rating |
|---|---|---|---|---|---|---|
| **1** | **Frontend Architecture** | React 18, TypeScript, Vite, Tailwind CSS | Modular components, React Context, React Flow DAG, Recharts visualizers. | 9 Vitest unit tests pass in 0.57s. Production build transforms 1618 modules in 3.04s. | Single bundle is 659 kB; needs code-splitting for low-bandwidth links. | **HIGH (Proven)** |
| **2** | **Backend Architecture** | Python 3.11+, FastAPI, Pydantic v2, Uvicorn | 15 decoupled domain routers in `backend/app/main.py`. | 532 Pytest unit & integration tests pass in 84.7s. | Single Python process; vertical scaling limits on single-core setups. | **HIGH (Proven)** |
| **3** | **Database Design** | PostgreSQL 16, SQLAlchemy 2.0, Alembic | 42 normalized declarative models, unbroken migration chain (p01 to p34). | SQLite memory fixtures & PostgreSQL migrations pass with 0 schema errors. | Complex multi-join correlation queries require indexing on high volumes. | **HIGH (Proven)** |
| **4** | **Honeypot Isolation** | Linux network namespaces / Private NAT virtual switch | Ingress-only firewall rules; zero bridged host networking. | Network isolation verification documented in `docs/security/`. | Misconfiguration of hypervisor virtual switches by end operators. | **HIGH (Proven)** |
| **5** | **Telemetry Ingestion** | FastAPI async endpoint, Pydantic validation | `POST /api/v1/ingestion/events/batch` with batching & token auth. | Ingestion integration test verifies 100 batch events processed in $< 20\text{ ms}$. | Memory consumption if batches exceed 5,000 events without chunking. | **HIGH (Proven)** |
| **6** | **Detection Engine** | Deterministic rule registry, temporal evaluators | 10 catalogue detection rules (`AUTH-001` to `BEHAV-002`). | 11 synthetic scenario tests pass in `test_demo_api.py`. | Complex multi-stage window evaluations require sliding timestamp indexes. | **HIGH (Proven)** |
| **7** | **Correlation Services** | Temporal sliding window, session clusterer | Grouping events by `(source_ip, session_cookie, 10m window)`. | Sequence tests verify 4-stage progression (`Recon` $\to$ `Cred Access`). | High-jitter attacks distributed over weeks may split into multiple sessions. | **HIGH (Proven)** |
| **8** | **ATT&CK Integration** | MITRE Enterprise Matrix v14, Evidence Junction | Hierarchical tactic/technique store; evidence linking tables. | MITRE mapping test validates forensic link to `T1110.001` & `T1083`. | Requires manual update when MITRE releases new matrix major versions. | **HIGH (Proven)** |
| **9** | **SSE Live Monitoring** | Server-Sent Events (`sse-starlette`) | `/api/v1/stream/events` broadcasting alerts and health states. | SSE test client verifies event broadcast within 50ms of alert creation. | Proxies that buffer chunked HTTP streams require `proxy_buffering off`. | **HIGH (Proven)** |
| **10**| **Authentication & RBAC**| JWT Bearer tokens, passlib (bcrypt), FastAPI deps | 3-tier RBAC (`admin`, `analyst`, `auditor`) enforced on routes. | Auth tests verify token expiration, role restrictions, and revocation. | JWT expiration requires refresh token workflow for 24/7 SOC shifts. | **HIGH (Proven)** |
| **11**| **Data Protection** | Salted SHA-256 redaction, PII regex cleaners | Passwords hashed prior to storage; PII strings masked. | Zero-Password invariant verified in `test_telemetry_to_alert_pipeline`. | Rainbow table risk on very short passwords mitigated by unique system salt. | **HIGH (Proven)** |
| **12**| **Testing Strategy** | Pytest, Vitest, Playwright, Demo Lab | Unit, integration, E2E workflows, and synthetic evaluation tests. | 532 backend tests (100% pass) + 9 frontend tests (100% pass). | Playwright E2E browser tests require headless Chromium environment. | **HIGH (Proven)** |
| **13**| **Deployment & Repro**| Multi-stage Dockerfile, Docker Compose | Orchestrates PostgreSQL 16, backend, and frontend with healthchecks. | `docker compose up --build -d` verified; all containers report `healthy`. | Requires 4 GB host RAM and Docker Engine 24.0+. | **HIGH (Proven)** |
| **14**| **Performance** | Async event processing, connection pooling | Measured MTTD $< 100\text{ ms}$; DB query latency $< 15\text{ ms}$. | Performance benchmarks in `docs/release/PERFORMANCE_BENCHMARK_REPORT.md`. | Not designed for $> 100,000$ events/second (unnecessary for honeypots). | **FEASIBLE (Scoped)**|
| **15**| **Maintainability** | Type hints, Pydantic schemas, Alembic migrations | Strict typing throughout backend; zero raw SQL strings. | Ruff linting passes; TypeScript compiler passes with 0 errors. | Requires maintaining synchronized models and schemas during extensions. | **HIGH (Proven)** |
| **16**| **Operational Resilience**| Health diagnostics, auto-backups, dry-run restore | `/resilience/health/live`, backup snapshots, dry-run restore. | Restore verification tests confirm backup validity in isolated fixtures. | Disk space growth if backups are not pruned after 30 days. | **HIGH (Proven)** |

---

## 2. Scope Appropriateness Justification

A critical aspect of technical feasibility is **architectural proportionality**—ensuring the technical stack matches the actual operational domain:

* **Why a Distributed Queue (Kafka) Was Rejected:**
  * Honeypot telemetry volume in a private enterprise lab typically ranges between 10 and 1,000 events per hour. Running Apache Kafka and ZooKeeper would introduce massive memory overhead (4+ GB RAM) and operational fragility without providing any tangible performance benefit.
  * FastAPI's asynchronous in-memory queues and PostgreSQL 16 handle 5,000 events/second natively, exceeding honeypot requirements by a factor of 100.
* **Why Microservices Were Rejected:**
  * Breaking SnareSight into 15 individual microservices would require distributed tracing, service meshes, network serialization, and distributed transaction management.
  * The **Modular Monolith** pattern achieves identical domain isolation and clean interfaces while maintaining single-command deployment, zero-latency in-process function calls, and ACID transaction guarantees.

