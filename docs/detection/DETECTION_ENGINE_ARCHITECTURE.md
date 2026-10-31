# SnareSight Threat Detection Engine Architecture

## 1. Overview & Pipeline Placement

SnareSight's detection engine is a deterministic, rule-based behavioral analysis subsystem positioned strictly downstream of database persistence in the platform's core pipeline:

```
Honeypot Interaction
        ↓
Event Collection & Validation
        ↓
Event Normalization
        ↓
PostgreSQL Persistence (db.commit())
        ↓
[Detection Engine]
  ├─ Event Eligibility Verification
  ├─ Rule Registry Lookup (Active Enabled Rules)
  ├─ Idempotency Check (Cached Evaluation Lookup)
  ├─ Safe Condition Tree Evaluation (No eval/exec)
  ├─ Explainable Result Generation
  └─ Execution History Auditing
        ↓
[Future Services: Phase 4]
  ├─ Severity & Confidence Scoring (P17)
  ├─ Concrete Detection Scenarios (P18)
  └─ MITRE ATT&CK Mapping (P19 - P20)
```

## 2. Core Architectural Principles

1. **Transactional Decoupling**:
   - Detection evaluation is triggered strictly **post-commit**.
   - If evaluation encounters a syntax error or runtime glitch, the underlying persisted security event is **never rolled back or deleted**.
2. **Deterministic Evaluation**:
   - Condition evaluation relies on an explicit allowlist of safe operators (`EQUALS`, `NOT_EQUALS`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `GREATER_THAN`, `LESS_THAN`, `IN`, `NOT_IN`, `EXISTS`, `NOT_EXISTS`).
   - Dynamic code execution (`eval()`, `exec()`, shell commands, arbitrary SQL, dynamic regex) is permanently prohibited.
3. **Immutability of Rule Versions**:
   - Once registered, a rule version cannot be mutated. Updates require incrementing the rule version, preserving historical evaluation auditability.
4. **Idempotency & Deduplication**:
   - Evaluations are keyed on `event_id:rule_id:rule_version`. Reprocessing the same event produces identical result identifiers and prevents log inflation.
5. **Zero Credential Exposure**:
   - The field registry strictly enforces sensitive data filtering. Prohibited attributes (`password`, `token`, `secret_key`) cannot be queried by detection rules.

