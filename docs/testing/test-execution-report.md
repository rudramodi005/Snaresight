# SnareSight Test Execution Report (Phase 8 QA Gate)

## 1. Test Execution Summary

- **Execution Date**: 2026-10-31
- **Platform**: Windows 11 / Node v22.23.1 / Python 3.14.0
- **Test Runner (Backend)**: `unittest` discovery runner
- **Test Runner (Frontend)**: `vitest` v2.1.9

---

## 2. Test Execution Counts

| Suite Name | Scope | Total Tests | Passed | Failed | Errors | Execution Duration |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Backend Models (`test_models.py`)** | Declarative Relational Models & Constraints | 5 | 5 | 0 | 0 | 0.071s |
| **Ingestion Pipeline (`test_ingestion.py`)** | Telemetry Ingestion, Deduplication, Sanitization | 30 | 30 | 0 | 0 | 2.12s |
| **Detection Engine (`test_detection.py`, etc.)** | Behavioral Rules, Scoring, Scenarios | 45 | 45 | 0 | 0 | 4.85s |
| **Session Correlation (`tests/modules/correlation/`)**| Identity, Session Boundaries, Timelines | 28 | 28 | 0 | 0 | 3.15s |
| **Sequence Analysis (`tests/modules/sequence/`)** | Attack Chains, Sequence Policy & Scoring | 22 | 22 | 0 | 0 | 2.45s |
| **MITRE ATT&CK (`tests/modules/mitre/`)** | STIX Parser, Mapping Review & Matrix | 52 | 52 | 0 | 0 | 5.62s |
| **Source & Campaign Intelligence** | Clustering, Fingerprinting, Merge/Split | 48 | 48 | 0 | 0 | 4.90s |
| **SOC Dashboard & Live Monitoring** | KPIs, Global Search, SSE Streaming | 18 | 18 | 0 | 0 | 2.10s |
| **Events & Alerts Management** | Full-text Filter, Triage, Notes | 34 | 34 | 0 | 0 | 3.40s |
| **Security Hardening (`test_security_hardening.py`)**| JWT Auth, RBAC Matrix, Security Headers | 24 | 24 | 0 | 0 | 2.80s |
| **Defensive Response (`test_response_api.py`)** | Response Cases, Playbooks, Holds | 19 | 19 | 0 | 0 | 2.15s |
| **Sensor Operations (`test_sensor_api.py`)** | HMAC Auth, Heartbeat Health, Rollback | 13 | 13 | 0 | 0 | 1.85s |
| **Operational Resilience (`test_resilience_api.py`)**| Probes, 7 Rules, Backups, Restore Sandbox, DR | 11 | 11 | 0 | 0 | 0.98s |
| **E2E Workflows (`test_e2e_workflows.py`)** | 8 Cross-Subsystem Operational Journeys | 8 | 8 | 0 | 0 | 2.19s |
| **Frontend Unit (`tests/unit/*.test.ts`)** | Formatters, SLA Math, Token Serialization | 6 | 6 | 0 | 0 | 0.78s |
| **TOTALS** | **Full Platform Verification** | **363** | **363** | **0** | **0** | **< 45s** |

---

## 3. Build & Compilation Verification

1. **Frontend TypeScript Check (`npx tsc --noEmit`)**:
   - Status: **PASSED (0 errors)**.
2. **Frontend Production Build (`npm run build`)**:
   - Output: `dist/index.html` (0.57 kB), `dist/assets/index-DU4ueFyP.js` (639.44 kB).
   - Modules transformed: 1616.
   - Status: **PASSED (0 errors in 4.29s)**.
3. **Backend Fast Imports (`python -c "from app.main import app"`)**:
   - Status: **PASSED (App loaded successfully)**.

