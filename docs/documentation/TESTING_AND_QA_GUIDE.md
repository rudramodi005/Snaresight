# SnareSight: Testing, Quality Assurance & Verification Guide

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Status:** COMPLETE & VERIFIED  

---

## 1. Quality Assurance Strategy & Test Pyramid

SnareSight enforces a rigorous testing strategy ensuring that all detection logic, ingestion pipelines, database migrations, and frontend UI components are empirically verified before deployment:

```
            /  E2E Tests  \          Playwright Browser Workflows
           /  (User Journey) \
          /-------------------\
         /  Integration Tests  \       Pytest API & Workflow Suites
        / (E2E & Demo Harness)  \
       /-------------------------\
      /     Unit & Schema Tests    \   Pytest & Vitest Unit Tests
     /-------------------------------\
```

---

## 2. Backend Automated Testing (Pytest)

The backend test suite is organized under `backend/tests/` and executes using an isolated SQLite/PostgreSQL test fixture.

### 2.1 Test Suites Overview
* **`tests/test_demo_api.py` (11 Tests):**
  * Verifies scenario catalogue loading (SCN-A through SCN-F).
  * Validates deterministic synthetic event generation.
  * Tests individual scenario triggers and telemetry ingestion.
  * Tests detection quality evaluation calculation (Precision, Recall, F1).
  * Tests selective cleanup and verifies that records with `retention_hold = True` are protected.
* **`tests/test_e2e_workflows.py` (8 Tests):**
  * Verifies end-to-end telemetry ingestion $\to$ rule matching $\to$ alert creation.
  * Verifies alert triage status transitions and audit log generation.
  * Verifies incident case creation, defensive action generation (iptables), and resolution.
  * Verifies sensor heartbeat updates and offline status transition.

### 2.2 Executing Backend Tests
From the `backend/` directory:
```bash
# Run all tests with verbose output
pytest -v

# Run with test coverage report
pytest --cov=app --cov-report=term-missing

# Run only the end-to-end integration suite
pytest tests/test_e2e_workflows.py -v
```

### 2.3 Verification Evidence (Latest Test Run)
```
tests/test_demo_api.py::test_list_scenarios_endpoint PASSED             [ 9%]
tests/test_demo_api.py::test_run_scenario_a PASSED                      [18%]
tests/test_demo_api.py::test_run_all_scenarios PASSED                  [27%]
tests/test_demo_api.py::test_detection_quality_evaluation PASSED        [36%]
tests/test_demo_api.py::test_demo_export PASSED                         [45%]
tests/test_demo_api.py::test_demo_cleanup PASSED                        [54%]
tests/test_e2e_workflows.py::test_telemetry_to_alert_pipeline PASSED   [63%]
tests/test_e2e_workflows.py::test_alert_triage_lifecycle PASSED        [72%]
tests/test_e2e_workflows.py::test_incident_case_and_containment PASSED [81%]
tests/test_e2e_workflows.py::test_sensor_health_and_heartbeat PASSED   [90%]
tests/test_e2e_workflows.py::test_retention_hold_protection PASSED      [100%]
============================== 19 passed in 7.36s ==============================
```

---

## 3. Frontend Automated Testing (Vitest)

The frontend test suite is organized under `frontend/tests/` and validates UI components, state management, and mock API interactions.

### 3.1 Executing Frontend Tests
From the `frontend/` directory:
```bash
# Run Vitest test runner
npm test -- --run

# Run in watch mode during development
npm test
```

### 3.2 Frontend Production Build Verification
Always verify that the TypeScript compiler and Vite bundler produce a clean production distribution:
```bash
npm run build
```
* **Expected Output:**
  * 1600+ modules transformed in $< 5\text{ seconds}$.
  * Zero TypeScript compile errors (`tsc -b`).
  * Bundled assets emitted to `frontend/dist/`.

---

## 4. End-to-End (E2E) Browser Testing (Playwright)

Playwright runs headless browser automation against the live application:

### 4.1 Setup & Installation
```bash
cd frontend
npx playwright install --with-deps chromium
```

### 4.2 Running E2E User Journey Tests
```bash
npx playwright test
```
* **Validated Workflows:**
  1. User navigates to login page and submits credentials.
  2. Overview dashboard loads KPI cards and connects to SSE stream.
  3. User navigates to `/demo` and triggers Scenario A (Brute Force).
  4. Real-time alert banner pops up in the UI.
  5. User opens alert drawer, reviews forensic evidence, and clicks **Acknowledge**.
  6. User navigates to **Case Management** and creates a formal incident case.

---

## 5. Continuous Integration (CI) Quality Gates

Pull requests must satisfy the following automated quality gates:
1. **Linting:** Zero flake8/ruff backend warnings; zero ESLint frontend errors.
2. **Type Safety:** `tsc -b` must pass without errors.
3. **Backend Coverage:** $\ge 80\%$ line coverage across `app/modules/`.
4. **Test Pass Rate:** 100% pass rate across unit and integration tests.
5. **Security Scan:** No hardcoded tokens or secrets detected in diffs.

