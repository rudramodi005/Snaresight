# SnareSight P20 Test Report: Evidence-Based MITRE ATT&CK Mapping

## 1. Test Suite Execution Overview

- **Test Suite Date:** 2026-10-31
- **Target Subsystem:** MITRE ATT&CK Detection Mapping & Analyst Review Workflow
- **Frameworks:** Python 3.14 `unittest` / FastAPI `TestClient`
- **Total Backend Tests Executed:** **276 tests**
- **Test Results:** **276 PASSED, 0 FAILED, 0 ERRED (100% Pass Rate)**
- **Total Execution Duration:** 8.516s

---

## 2. Dedicated P20 Test Suite Breakdown (21 Tests)

### 2.1 Mapping Definition Registry (`test_mapping_registry.py` - 4 Tests)
- `REG-01`: Verified default curated definitions for `AUTH-001`, `AUTH-002`, `AUTH-003`, `WEB-001`, and `WEB-002` are properly loaded. [PASS]
- `REG-02`: Verified unspecific and deferred scenarios (`CMD-001`, `FILE-001`, `WEB-003`, `BEHAV-001`, `BEHAV-002`) remain strictly `NOT_MAPPED`. [PASS]
- `REG-03`: Verified querying an unknown rule returns an empty definition list without error. [PASS]
- `REG-04`: Verified custom valid definition registration and retrieval. [PASS]

### 2.2 Mapping Confidence Engine (`test_mapping_confidence.py` - 3 Tests)
- `CONF-01`: Verified `DIRECTLY_SUPPORTED` mappings with corroborating telemetry receive `HIGH` confidence (>80). [PASS]
- `CONF-02`: Verified decoy simulation caveat reduction is applied to `AUTH-002` trap account acceptance. [PASS]
- `CONF-03`: Verified `NOT_MAPPED` definitions return 0 confidence score and `LOW` level. [PASS]

### 2.3 Mapping Evaluation Engine (`test_mapping_evaluator.py` - 5 Tests)
- `EVAL-01`: Verified end-to-end evaluation of `AUTH-001` finding creates `T1110` mapping and 3 evidence records. [PASS]
- `EVAL-02`: Verified repeated evaluation is strictly idempotent (zero duplicate database rows). [PASS]
- `EVAL-03`: Verified missing required evidence skips mapping generation. [PASS]
- `EVAL-04`: Verified exclusion condition (`outcome == "SUCCESS"` for brute force) prevents mapping. [PASS]
- `EVAL-05`: Verified security invariant: Prohibited password fields are omitted from mapping evidence. [PASS]

### 2.4 Analyst Review Workflow (`test_mapping_review.py` - 3 Tests)
- `REV-01`: Verified analyst `ACCEPT` review updates status to `ACCEPTED` and logs review and history entries. [PASS]
- `REV-02`: Verified analyst `REJECT` review updates status to `REJECTED`. [PASS]
- `REV-03`: Verified analyst `REQUEST_MORE_EVIDENCE` updates status to `NEEDS_MORE_EVIDENCE`. [PASS]

### 2.5 REST API Endpoints (`test_mapping_api.py` - 6 Tests)
- `API-MAP-01`: Verified `GET /api/v1/mitre/mappings` returns paginated mapping results. [PASS]
- `API-MAP-02`: Verified `GET /api/v1/mitre/mappings/{id}` returns mapping details with evidence items. [PASS]
- `API-MAP-03`: Verified `GET /api/v1/detections/{id}/mitre-mappings` returns associated mappings. [PASS]
- `API-MAP-04`: Verified `GET /api/v1/mitre/techniques/{id}/detections` returns mapped detections. [PASS]
- `API-MAP-05`: Verified `GET /api/v1/mitre/mappings/statistics` returns aggregate metrics. [PASS]
- `API-MAP-06`: Verified `POST /api/v1/mitre/mappings/{id}/review` enforces role authorization. [PASS]

---

## 3. Regression Test Coverage

- **P11/P12 Database Schema & Models:** 5/5 PASS
- **P13 Event Ingestion & Sanitization:** 30/30 PASS
- **P14 Normalization, Deduplication & Retention:** 35/35 PASS
- **P15 Real-Time Streaming & Health:** 35/35 PASS
- **P16 Detection Rule Engine:** 45/45 PASS
- **P17 Severity & Confidence Scoring:** 40/40 PASS
- **P18 Detection Scenarios & Alerts:** 43/43 PASS
- **P19 MITRE ATT&CK STIX Parser & Catalogue:** 22/22 PASS
- **P20 MITRE ATT&CK Evidence Mapping Suite:** 21/21 PASS
- **Total Backend Tests:** **276 / 276 PASS**

