# SnareSight P20 Existing Project Assessment: Detection & ATT&CK Mapping Foundation

## 1. Executive Summary

This assessment audits the existing SnareSight codebase (Phase 4, Tasks P16–P19) to establish the technical foundation for Task P20: **Evidence-Based MITRE ATT&CK Mapping for SnareSight Detections**.

Task P20 connects real SnareSight detection results to relevant MITRE ATT&CK techniques and sub-techniques based on verified event evidence, without fabricating attacker intent, compromising production systems, or confusing honeypot simulations with actual breaches.

---

## 2. Component Audits

### 2.1 P16 — Detection Engine
- **Engine Core:** [`app.detection.engine.DetectionEngine`](file:///c:/Projects/SnareSight/backend/app/detection/engine.py) provides deterministic, condition-based threat evaluation.
- **Rule Registry:** [`app.detection.registry.RuleRegistry`](file:///c:/Projects/SnareSight/backend/app/detection/registry.py) maintains versioned rule definitions in memory and validates uniqueness.
- **Evaluators:** Single-event matching via [`EventMatcher`](file:///c:/Projects/SnareSight/backend/app/detection/event_matcher.py), session aggregation via [`SessionEvaluator`](file:///c:/Projects/SnareSight/backend/app/detection/session_evaluator.py), and sliding-window evaluation via [`WindowEvaluator`](file:///c:/Projects/SnareSight/backend/app/detection/window_evaluator.py).
- **Execution Tracking:** [`app.detection.execution_tracker.ExecutionTracker`](file:///c:/Projects/SnareSight/backend/app/detection/execution_tracker.py) logs evaluations.
- **Detection Result Contract:** [`DetectionResult`](file:///c:/Projects/SnareSight/backend/app/schemas/detection.py) provides `detection_id`, `rule_id`, `rule_version`, `matched`, `evaluation_status`, `triggering_event_id`, `related_event_ids`, `execution_time_ms`, and `evidence_details`.

### 2.2 P17 — Severity and Confidence Scoring
- **Confidence Scorer:** [`app.detection.confidence_scorer.ConfidenceScorer`](file:///c:/Projects/SnareSight/backend/app/detection/confidence_scorer.py) calculates detection confidence (0–100) based on source reliability, condition specificity, and evidence volume.
- **Evidence Assessor:** [`app.detection.evidence_assessor.EvidenceAssessor`](file:///c:/Projects/SnareSight/backend/app/detection/evidence_assessor.py) evaluates corroborating events and session depth (`WEAK`, `MODERATE`, `STRONG`).
- **Severity Assessor:** [`app.detection.severity_assessor.SeverityAssessor`](file:///c:/Projects/SnareSight/backend/app/detection/severity_assessor.py) computes threat severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Critical Distinction:** Detection confidence evaluates how strongly observed telemetry supports the detection finding. It does **NOT** measure correlation with MITRE ATT&CK adversary behavior. Mapping confidence must be modeled independently.

### 2.3 P18 — Concrete Detection Scenarios
The official scenario catalogue in [`app.detection.scenario_catalogue.py`](file:///c:/Projects/SnareSight/backend/app/detection/scenario_catalogue.py) defines 10 concrete rules:

| Rule ID | Scenario Name | Status | Evaluation Mode | Key Telemetry Fields |
|---|---|---|---|---|
| `AUTH-001` | Repeated Authentication Failures | ACTIVE | SESSION | `event_category == "authentication"`, `outcome == "FAILURE"` |
| `AUTH-002` | Decoy Authentication Accepted | ACTIVE | EVENT | `event_category == "authentication"`, `outcome == "SUCCESS"` |
| `AUTH-003` | Username Enumeration Probing | ACTIVE | SESSION | `event_category == "authentication"`, `metadata.username_fingerprint` |
| `WEB-001` | Web Path Enumeration Probing | ACTIVE | SESSION | `event_category == "request"`, `metadata.http_path` |
| `WEB-002` | Suspicious Directory Traversal Request | ACTIVE | EVENT | `metadata.http_path` contains `../`, `..%2f`, `%2e%2e/` |
| `CMD-001` | Command Discovery Interaction | DRAFT / DISABLED | EVENT | `metadata.command_category` (Deferred: Web decoy has no shell) |
| `FILE-001` | File Transfer Interaction | DRAFT / DISABLED | EVENT | `metadata.transfer_direction` (Deferred: Web decoy has no file upload) |
| `WEB-003` | Repeated Suspicious Request Patterns | ACTIVE | SESSION | `metadata.request_pattern` |
| `BEHAV-001` | Multi-Category Suspicious Interaction | ACTIVE | SESSION | Distinct event categories in session |
| `BEHAV-002` | Unusual HTTP Method Interaction | ACTIVE | EVENT | `metadata.http_method` IN (`TRACE`, `TRACK`, `PROPFIND`, `DEBUG`) |

### 2.4 P19 — MITRE ATT&CK Framework Integration
- **Framework Domain:** `enterprise-attack`, STIX 2.1.
- **Authoritative Database Tables:**
  - `attack_dataset_versions`: Version releases, SHA-256 integrity, active status.
  - `attack_tactics`: 14 tactics (TA0001–TA0040).
  - `attack_techniques`: Enterprise techniques (e.g. T1110, T1078, T1087, T1083, T1190).
  - `attack_subtechniques`: Granular sub-techniques (e.g. T1110.001, T1110.003, T1087.001).
  - `attack_relationships`: Parent-child linkages (`subtechnique-of`).
  - `attack_import_runs`: Audit logging of all dry-runs and imports.
- **Read-Only API:** `/api/v1/mitre/status`, `/tactics`, `/techniques`, `/subtechniques`.

---

## 3. P20 Design Invariants & Scope Boundaries

1. **Conservative Mapping:**
   - Only map detection rules where the observed telemetry defensibly matches the adversary technique.
   - Rules with insufficient specificity (`WEB-003`, `BEHAV-002`), deferred rules (`CMD-001`, `FILE-001`), or cross-category correlations (`BEHAV-001`) must remain `NOT_MAPPED`.
2. **Decoy Simulation Truth:**
   - `AUTH-002` (Decoy Authentication Accepted) maps to `T1078` (Valid Accounts) strictly under `REQUIRES_ANALYST_REVIEW` with an explicit caveat: *The interaction occurred on a decoy trap; it does NOT demonstrate compromise of legitimate production systems or valid credentials on actual production services.*
3. **Decoupled Confidence:**
   - Mapping confidence (0–100) measures alignment between observed behavior and the ATT&CK technique specification. It is mathematically independent of detection confidence.
4. **Resilience Invariant:**
   - Detection evaluation and alert creation must succeed even if the MITRE catalogue is unpopulated or the mapping evaluation fails.

