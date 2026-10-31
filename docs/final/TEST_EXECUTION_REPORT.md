# SnareSight Test Execution & Quality Assurance Report

**Test Scope:** Backend Pytest Suite, Frontend Vitest Suite, Docker Production Builds, Reverse-Proxy HTTP Probes  
**Date:** November 1, 2026  
**Auditor:** QA Automation Engineer  
**Overall Status:** **100% PASSED**

---

## 1. Backend Test Suite (Pytest)

- **Command:** `cd backend && uv run --dev pytest -q`
- **Result:** `535 passed, 28 warnings in 59.72s`
- **Pass Rate:** **100%** (535 / 535)

### Test Distribution by Module:
- `tests/api/`: Ingestion, stream, health, auth validation (48 tests)
- `tests/correlation/`: Activity sessions, behavioral sequences, attack chains (64 tests)
- `tests/detection/`: Scenario catalogue, rules engine, threshold evaluation (52 tests)
- `tests/modules/alerts/`: Triage center, escalation, status transitions, audit logs (58 tests)
- `tests/modules/analytics/`: Executive metrics, trends, timeline buckets, reports (42 tests)
- `tests/modules/campaign_intelligence/`: Investigation clusters, scoring, merge/split (56 tests)
- `tests/modules/demo/`: PRNG determinism, scenario generators, cascade purge (24 tests)
- `tests/modules/mitre/`: Enterprise catalogue, technique mapping, review workflow (68 tests)
- `tests/modules/resilience/`: Backups, DR checklists, audit hash chain verification (44 tests)
- `tests/modules/response/`: Response cases, containment playbooks, legal holds (46 tests)
- `tests/modules/sensors/`: Decoy inventory, credentials, configuration lifecycle (33 tests)

---

## 2. Frontend Test Suite (Vitest)

- **Command:** `npm test -- --run` (via builder container)
- **Result:** `4 test files passed, 26 tests passed in 892ms`
- **Pass Rate:** **100%** (26 / 26)

### Test Distribution:
1. `tests/unit/format.test.ts` (17 tests) - **PASSED**:
   - `isValidNumber`: finite numbers, null/undefined, NaN, string/object types.
   - `formatNumber`: default/custom decimal places, null/NaN fallbacks.
   - `formatPercent`: percentage suffixes, multiplier scaling, fallback handling.
   - `safeDivide`: zero denominators, null operands, NaN division protection.
   - `formatInteger`: integer thousands formatting, null/undefined protection.
   - `formatDateTime`: valid ISO strings, invalid dates, null/undefined fallbacks.
2. `tests/unit/components.test.ts` (3 tests) - **PASSED**:
   - ErrorBoundary rendering and error capture.
   - BrandLogo rendering and sizing.
   - Metric card fallback states.
3. `tests/unit/api_contracts.test.ts` (3 tests) - **PASSED**:
   - MITRE technique explorer data structures.
   - Analytics overview response parsing.
   - Event pagination parsing.
4. `tests/unit/demo.test.ts` (3 tests) - **PASSED**:
   - Scenario execution parameter validation.
   - Telemetry scale multipliers.
   - Deterministic PRNG seed propagation.

---

## 3. Reverse-Proxy & HTTP Endpoint Probes

Verified via PowerShell HTTP probes against `http://127.0.0.1:5173`:

| Endpoint Tested | Method | Status | Response Content |
| :--- | :--- | :--- | :--- |
| `http://127.0.0.1:5173/` | GET | **200 OK** | Landing Page SPA HTML |
| `http://127.0.0.1:5173/login` | GET | **200 OK** | Authentication Gateway HTML |
| `http://127.0.0.1:5173/app/overview` | GET | **200 OK** | SOC Operations HTML |
| `http://127.0.0.1:5173/app/mitre` | GET | **200 OK** | MITRE ATT&CK Matrix HTML |
| `http://127.0.0.1:5173/app/events` | GET | **200 OK** | Security Events Explorer HTML |
| `http://127.0.0.1:5173/api/v1/health` | GET | **200 OK** | `{"status":"UP","platform":"SnareSight"}` |
| `http://127.0.0.1:5173/api/v1/dashboard/overview?time_range=24h` | GET | **200 OK** | Aggregated SOC KPI payload |
| `http://127.0.0.1:5173/api/v1/events?limit=5` | GET | **200 OK** | Paginated security events |
| `http://127.0.0.1:5173/api/v1/alerts?limit=5` | GET | **200 OK** | Priority security alerts |
| `http://127.0.0.1:5173/api/v1/sensors` | GET | **200 OK** | Decoy sensors inventory |
| `http://127.0.0.1:5173/api/v1/attack/techniques` | GET | **200 OK** | 12 Enterprise ATT&CK techniques |
| `http://127.0.0.1:5173/api/v1/attack/summary` | GET | **200 OK** | Matrix coverage KPIs |
| `http://127.0.0.1:5173/api/v1/attack/matrix` | GET | **200 OK** | ATT&CK Matrix tactical columns |
| `http://127.0.0.1:5173/api/v1/attack/coverage` | GET | **200 OK** | Rule-to-technique coverage |
| `http://127.0.0.1:5173/api/v1/attack/traceability` | GET | **200 OK** | Telemetry alert traceability traces |
| `http://127.0.0.1:5173/api/v1/source-profiles` | GET | **200 OK** | Inbound actor profiles |
| `http://127.0.0.1:5173/api/v1/investigations` | GET | **200 OK** | Campaign investigation clusters |
| `http://127.0.0.1:5173/api/v1/analytics/overview` | GET | **200 OK** | Analytics overview & trends |
| `http://127.0.0.1:5173/api/v1/response/cases` | GET | **200 OK** | Defensive response cases |
| `http://127.0.0.1:5173/api/v1/resilience/health/diagnostics` | GET | **200 OK** | System diagnostics payload |
| `http://127.0.0.1:5173/api/v1/demo/scenarios` | GET | **200 OK** | 6 Synthetic benchmark scenarios |

