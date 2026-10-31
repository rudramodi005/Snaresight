# SnareSight Detailed Bug Fix Report

**Audit Date:** November 1, 2026  
**Auditor:** Principal Software Architect & QA Automation Lead  

---

## 1. BUG-001: Backend Dockerfile uv Virtualenv Configuration

- **Subsystem:** `backend/Dockerfile`
- **Root Cause:** Line 13 invoked `uv pip install --no-cache -r pyproject.toml` without specifying target virtual environment path or adding `/opt/venv/bin` to `PATH`.
- **Files Modified:** `backend/Dockerfile`
- **Fix Applied:** Configured `ENV PATH="/opt/venv/bin:$PATH"` and invoked `uv pip install --python /opt/venv/bin/python --no-cache -r pyproject.toml`.
- **Verification:** Docker image builds cleanly; Python interpreter in final runner stage successfully imports all FastAPI and SQLAlchemy dependencies.

---

## 2. BUG-002: Frontend Docker Health Check IPv4/IPv6 Binding

- **Subsystem:** `compose.yaml` / `docker-compose.yml`
- **Root Cause:** Nginx in the frontend container listened on IPv4 (`127.0.0.1:5173`). The Docker health check used `http://localhost:5173/`, which resolved to IPv6 `[::1]:5173` and was refused by Nginx.
- **Files Modified:** `compose.yaml`, `docker-compose.yml`
- **Fix Applied:** Updated the health check test URL to `http://127.0.0.1:5173/`.
- **Verification:** Frontend container transitions to `healthy` within 15 seconds of startup.

---

## 3. BUG-003: Blank-Screen `.toFixed()` TypeError on MITRE Page

- **Subsystem:** `frontend/src/features/mitre/MitreAttackDashboardPage.tsx`, `frontend/src/utils/format.ts`
- **Root Cause:** Missing or null values from API responses for technique coverage were directly invoking `.toFixed()`, throwing an unhandled `TypeError` that crashed React rendering at `/mitre`.
- **Files Modified:**
  - `frontend/src/utils/format.ts`
  - `frontend/src/features/mitre/MitreAttackDashboardPage.tsx`
  - `frontend/src/components/common/ErrorBoundary.tsx`
- **Fix Applied:** Created `isValidNumber()`, `formatNumber()`, and `formatPercent()`. Implemented defensive fallback checks with a styled React Error Boundary.
- **Verification:** Unit tests in `format.test.ts` pass; `/app/mitre` renders matrix and coverage KPIs without errors.

---

## 4. BUG-006: Demo Scenario Cleanup ForeignKeyViolation 500 Error

- **Subsystem:** `backend/app/modules/demo/service.py`
- **Root Cause:** Deleting synthetic `SecurityEventModel` records before deleting related `ActivitySessionEventModel` and `ActivitySessionModel` records triggered PostgreSQL foreign key constraint violations.
- **Files Modified:** `backend/app/modules/demo/service.py`
- **Fix Applied:** Implemented sequential cascade deletion: delete session event joins, then sessions, then security events and alerts.
- **Verification:** Executed Scenario A, B, and cleanup routines; cleanup responds with HTTP 200 and zero database integrity errors.

---

## 5. BUG-007 & BUG-008: Technique Explorer Schema Mismatch & platforms.slice Error

- **Subsystem:**
  - `backend/app/modules/mitre/dashboard_schemas.py`
  - `backend/app/modules/mitre/dashboard_service.py`
  - `frontend/src/features/mitre/MitreAttackDashboardPage.tsx`
- **Root Cause:** Frontend called `tech.platforms.slice(0, 3)` on `AttackTechniqueExplorerItem`, but the backend schema omitted `platforms`. Detail modal expected `live_evidence` where schema provided `supporting_evidence`.
- **Files Modified:**
  - `backend/app/modules/mitre/dashboard_schemas.py`
  - `backend/app/modules/mitre/dashboard_service.py`
  - `frontend/src/features/mitre/MitreAttackDashboardPage.tsx`
- **Fix Applied:** Added `platforms: List[str]` to explorer item schema and extracted from catalogue technique metadata. Added defensive `Array.isArray(tech.platforms)` check and property aliases.
- **Verification:** Technique Explorer tab loads all 12 enterprise techniques with platform badges; detail drawer opens with complete rule and evidence counts.

---

## 6. BUG-009: Unstamped Alembic Version Table

- **Subsystem:** PostgreSQL Database & Alembic Migration Engine
- **Root Cause:** Tables were created by metadata reflection, but `alembic_version` table was missing. Running `alembic upgrade head` attempted to recreate baseline tables, failing with `relation "honeypots" already exists`.
- **Fix Applied:** Stamped database revision at head: `alembic stamp head` (`p34_operational_resilience`).
- **Verification:** `alembic current` confirms `p34_operational_resilience (head)`. `alembic upgrade head` runs cleanly with no errors.

---

## 7. BUG-010 & BUG-011: Unsafe `.toLocaleString()` and Nested Array `.map()`

- **Subsystem:** `SecurityAnalyticsPage.tsx`, `SecurityEventsPage.tsx`, `MitreMappingsPage.tsx`, `SessionInvestigationPage.tsx`, `SourceIntelligencePage.tsx`
- **Root Cause:** Calling `.toLocaleString()` on undefined numbers and calling `.map()` on undefined nested array properties caused unhandled runtime exceptions when datasets were empty.
- **Files Modified:**
  - `frontend/src/utils/format.ts`
  - `frontend/src/features/analytics/SecurityAnalyticsPage.tsx`
  - `frontend/src/features/events/SecurityEventsPage.tsx`
  - `frontend/src/features/mitre/MitreMappingsPage.tsx`
  - `frontend/src/features/sessions/SessionInvestigationPage.tsx`
  - `frontend/src/features/source-intelligence/SourceIntelligencePage.tsx`
  - `frontend/src/features/sensors/SensorOperationsPage.tsx`
  - `frontend/src/features/resilience/PlatformSecurityHealthPage.tsx`
  - `frontend/src/features/response/DefensiveResponseCenterPage.tsx`
  - `frontend/tests/unit/format.test.ts`
- **Fix Applied:** Added `formatInteger()` and `formatDateTime()` in `format.ts`. Wrapped all nested collection iterations with `(array || []).map(...)`.
- **Verification:** Unit tests expanded to 26 passing tests; all views render empty and populated datasets safely.

---

## 8. BUG-012: Static Desktop Sidebar on Mobile Screens

- **Subsystem:** `frontend/src/App.tsx`, `frontend/src/features/landing/LandingPage.tsx`
- **Root Cause:** Fixed width 256px sidebar without a mobile toggle squeezed content down to 104px on 360px viewports.
- **Files Modified:** `frontend/src/App.tsx`, `frontend/src/features/landing/LandingPage.tsx`
- **Fix Applied:** Added responsive off-canvas drawer with touch backdrop, mobile hamburger menu toggle, and auto-close upon route navigation.
- **Verification:** Tested responsiveness across 360px, 390px, 768px, 1024px, and 1920px viewports.

