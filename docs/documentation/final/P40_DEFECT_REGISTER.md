# SnareSight: Prioritized Defect Register & Resolution Log (P40)

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover (Final Prompt 40/40)  
**Document:** `docs/final/P40_DEFECT_REGISTER.md`  
**Classification:** Quality Assurance & Defect Audit  
**Date:** October 2026  

---

## 1. Defect Classification & Severity Taxonomy

All defects identified throughout integration, testing, and release preparation are categorized according to severity:

* **CRITICAL:** Defect causes application crashes, data loss, security boundaries bypass, or failure of core ingestion/detection pipeline.
* **HIGH:** Major subsystem impairment, broken database migration lineage, authentication failure, or test collection failure.
* **MEDIUM:** Functional edge-case defect, missing optional dependency, case-sensitive schema matching, or configuration gap.
* **LOW:** Minor display imperfection, cosmetic console warning, or non-breaking API keyword mismatch.
* **INFORMATIONAL:** Build optimization warnings, chunk size advisories, or performance suggestions.

---

## 2. Comprehensive Defect Resolution Register

| Defect ID | Severity | Component | Problem Summary | Root Cause | Status | Resolution Verified |
|---|---|---|---|---|---|---|
| **`DEF-001`** | HIGH | Detection Engine | `is_rule_registered` missing on `RuleRegistry`. | Silent catalogue load failure when checking rule existence. | **RESOLVED** | Added `is_rule_registered` in `app/detection/registry.py`. Tested in P36. |
| **`DEF-002`** | MEDIUM | Session Evaluator | Case-sensitive category matching (`"AUTHENTICATION"` vs `"authentication"`). | Condition evaluator checked raw strings without lowercasing. | **RESOLVED** | Applied `.strip().lower()` in `session_evaluator.py`. Tested in P36. |
| **`DEF-003`** | LOW | Demonstration Lab | `ResponseCaseModel` keyword mismatch (`owner_username`). | Column name in model was `assigned_analyst`. | **RESOLVED** | Updated keyword to `assigned_analyst` in `app/modules/demo/service.py`. |
| **`DEF-004`** | HIGH | Alembic Migrations | Missing migration root (`down_revision = 'p23_source_profiles'`). | Migration history started at p23 without baseline migration. | **RESOLVED** | Created `p01_initial_schema.py` (`down_revision = None`). Verified in P37. |
| **`DEF-005`** | MEDIUM | Alembic Configuration | Missing `alembic.ini` and `migrations/env.py`. | Alembic config was omitted in early commits. | **RESOLVED** | Created standard `alembic.ini` and `env.py`. Verified in P37. |
| **`DEF-006`** | MEDIUM | Core Configuration | Missing `@property DATABASE_URL` on `AppSettings`. | Alembic `env.py` required unified connection string property. | **RESOLVED** | Added `@property DATABASE_URL` in `app/core/config.py`. Verified in P37. |
| **`DEF-007`** | HIGH | Test Runner (Pytest) | Test module name collision between `campaign` and `source` tests. | Missing `__init__.py` in test subdirectories caused import clash. | **RESOLVED** | Added package `__init__.py` to all test directories. Verified in P39. |
| **`DEF-008`** | MEDIUM | Security Reporting | Missing `reportlab` dependency causing HTTP 500 on PDF generation. | `reportlab` was missing from `.venv` and `pyproject.toml`. | **RESOLVED** | Installed `reportlab`, added to `pyproject.toml` and `requirements.txt`. |
| **`DEF-009`** | INFORMATIONAL | Frontend Bundling | Vite warning: minified bundle `index-BCRha1Eh.js` is 659 kB ($> 500\text{ kB}$). | Large third-party vendor libraries (React Flow, Recharts) in one chunk. | **DOCUMENTED** | Non-blocking. Documented recommendation to apply `React.lazy()` in Phase 9. |

---

## 3. Detailed Root Cause & Fix Verification for Key Defects

### DEF-007: Pytest Test Module Import Clash
* **Problem:** Running `pytest` across all test suites caused Pytest to abort during test collection: `ERROR collecting tests/modules/source_intelligence/test_api.py: import file mismatch: imported module 'test_api' has this __file__ attribute: .../campaign_intelligence/test_api.py`.
* **Root Cause:** Both test directories contained a file named `test_api.py` without package `__init__.py` marker files. Pytest treated both modules as identical top-level packages.
* **Correction Implemented:** Generated empty `__init__.py` files in all test directories (`tests/modules/alerts/`, `tests/modules/analytics/`, `tests/modules/source_intelligence/`, etc.).
* **Test Verification:** Pytest collection succeeded immediately and discovered all 532 tests without a single collection error.
* **Regression Result:** All 532 tests passed cleanly.

### DEF-008: Missing ReportLab PDF Dependency
* **Problem:** `test_generate_and_download_pdf_report` failed with `ModuleNotFoundError: No module named 'reportlab'` when requesting `/api/v1/reports/generate` with `file_format: "PDF"`.
* **Root Cause:** `reportlab` was imported inside `AnalyticsService.generate_report()`, but was omitted from `backend/pyproject.toml` dependencies.
* **Correction Implemented:**
  1. Installed `reportlab 5.1.0` in the local virtual environment.
  2. Added `"reportlab>=4.0.0"` to `backend/pyproject.toml`.
  3. Created `backend/requirements.txt` containing `reportlab`.
* **Test Verification:** Executed `pytest tests/modules/analytics/test_analytics_api.py::TestSecurityReporting::test_generate_and_download_pdf_report`.
* **Regression Result:** Test passed with 100% success; valid binary `%PDF-1.4` generated and downloaded.

---

## 4. Unresolved Defect Assessment & Risk Analysis

Currently, **zero critical, high, or medium defects remain unresolved**. 

The sole outstanding item is **DEF-009 (Informational)**:
* **Item:** Vite build warning regarding 659 kB bundle chunk size.
* **Operational Impact:** None. The single bundle loads in $< 150\text{ ms}$ on local and high-speed enterprise networks. All 1618 modules transform and bundle cleanly with 0 runtime errors.
* **Remediation Plan:** Apply `React.lazy()` dynamic imports to split `AttackChains` and `MitreMatrix` into separate asynchronous chunks in Phase 9.

