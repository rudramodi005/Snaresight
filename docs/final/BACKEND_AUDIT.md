# SnareSight Backend Architecture & API Audit

**Framework:** FastAPI 0.115, Uvicorn 0.32, Pydantic V2, SQLAlchemy 2.0  
**Target:** `http://127.0.0.1:8000/`  
**Date:** November 1, 2026  
**Auditor:** Principal Backend Architect & Cybersecurity Engineer  
**Status:** **VERIFIED**

---

## 1. Backend Architecture & Runtime Environment

The backend functions as an asynchronous security gateway, telemetry ingestion pipeline, and detection orchestration engine.
- **Entrypoint:** `backend/app/main.py`
- **Application Lifespan & Startup:**
  - Database schema initialization (`Base.metadata.create_all`).
  - MITRE ATT&CK Enterprise catalogue auto-initialization.
  - Scenario detection rule catalogue registration.
  - Default administrative and analyst user credential seeding (`bcrypt`).
- **Security Middlewares:**
  - `SecurityHeadersMiddleware`: Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, and CSP.
  - `RequestSizeLimitMiddleware`: Rejects oversized payloads exceeding 10MB to mitigate DoS attacks.
  - `CORSMiddleware`: Whitelists frontend origins `http://localhost:5173` and `http://127.0.0.1:5173`.

---

## 2. API Route & Contract Audit

All 16 functional subsystems mounted under `/api/v1` were audited and verified:

| Subsystem Router | Prefix | Endpoints Tested | Contract Status |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/v1/auth` | `/login`, `/me`, `/logout`, `/change-password` | **VERIFIED** |
| **Ingestion** | `/api/v1/ingestion` | `/events`, `/batch`, `/heartbeat` | **VERIFIED** (API Key Protected) |
| **Stream (SSE)** | `/api/v1/stream` | `/events` | **VERIFIED** (Non-buffering SSE) |
| **Dashboard** | `/api/v1/dashboard` | `/overview`, `/search` | **VERIFIED** |
| **Security Events** | `/api/v1/events` | `/`, `/{id}`, `/summary`, `/compare` | **VERIFIED** |
| **Alerts** | `/api/v1/alerts` | `/`, `/{id}`, `/summary`, `/triage` | **VERIFIED** |
| **MITRE ATT&CK** | `/api/v1/attack` | `/techniques`, `/summary`, `/matrix`, `/coverage`, `/traceability` | **VERIFIED** |
| **Source Intelligence** | `/api/v1/source-profiles` | `/`, `/{id}`, `/sessions`, `/behavior` | **VERIFIED** |
| **Campaign Investigations**| `/api/v1/investigations` | `/`, `/{id}`, `/timeline`, `/merge` | **VERIFIED** |
| **Correlation & Sequences**| `/api/v1/correlation` | `/sessions`, `/sequences`, `/chains` | **VERIFIED** |
| **Defensive Response** | `/api/v1/response` | `/cases`, `/playbooks`, `/approvals`, `/holds` | **VERIFIED** |
| **Sensors Operations** | `/api/v1/sensors` | `/`, `/{id}`, `/credentials`, `/config` | **VERIFIED** |
| **Operational Resilience** | `/api/v1/resilience` | `/health/diagnostics`, `/backups`, `/audit/verify` | **VERIFIED** |
| **Analytics & Reports** | `/api/v1/analytics` | `/overview`, `/trends`, `/executive`, `/reports` | **VERIFIED** |
| **Demonstration Lab** | `/api/v1/demo` | `/scenarios`, `/execute`, `/cleanup` | **VERIFIED** |
| **System Audit** | `/api/v1/audit` | `/logs`, `/verify` | **VERIFIED** |

---

## 3. Database Connection & Driver Normalization

### Psycopg Driver Normalization:
- In `backend/app/db/session.py`, PostgreSQL driver configuration was standardized across local and containerized environments.
- SQLAlchemy connection strings utilizing `postgresql+psycopg://` and `postgresql+psycopg2://` are automatically detected and mapped to the appropriate driver instance without throwing dialect initialization exceptions.

---

## 4. MITRE ATT&CK Explorer & Detail Schema Audit

### Issue Remediated:
- In `dashboard_schemas.py`, `AttackTechniqueExplorerItem` was missing the `platforms: List[str]` attribute expected by the frontend.
- `AttackTechniqueDetailResponse` schema lacked aliases for `configured_mappings` / `mappings` and `supporting_evidence` / `live_evidence`.
- **Fix:** Added `platforms: List[str] = Field(default_factory=list)` to the schema and updated `dashboard_service.py` to extract platforms from catalogue technique metadata. Added schema property aliases to maintain bidirectional compatibility.

---

## 5. Demonstration Lab Isolation & Cascade Integrity

### Issue Remediated:
- In `backend/app/modules/demo/service.py`, executing demonstration scenario cleanup previously generated an HTTP 500 error due to `ForeignKeyViolation` on `activity_session_events` when deleting `SecurityEventModel` records before their associated session events.
- **Fix:** Implemented sequential cascade deletion:
  1. Purge `ActivitySessionEventModel` references.
  2. Purge `ActivitySessionModel` records.
  3. Purge associated synthetic `SecurityEventModel` and `AlertModel` entities.
- Result: Scenario cleanup completes with HTTP 200 and zero orphaned records.

