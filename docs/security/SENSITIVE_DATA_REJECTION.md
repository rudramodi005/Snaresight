# Sensitive Data Rejection & Zero Password Persistence

**Document ID:** SEC-REJ-001  
**Classification:** Information Security Enforcement Standard  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Zero Password Persistence Mandate

Under the SnareSight Architecture Principles, honeypot decoys are designed to lure adversary interactions without collecting or retaining usable authentication secrets. Decoys record `username_attempted` and metadata regarding the interaction, but must **never capture, log, or persist plain-text passwords**.

To guard against misconfigured decoys or malicious payloads containing credential dumps, the Ingestion Pipeline implements a defense-in-depth gatekeeper: `SensitiveDataInspector`.

---

## 2. Forbidden Field Inspection

The `SensitiveDataInspector` performs a recursive traversal of incoming JSON objects and rejects any payload containing forbidden credential keys:

### Blacklisted Key Patterns:
- `password`, `passwd`, `pass`
- `auth_token`, `authorization`
- `bearer_token`, `jwt`
- `private_key`, `secret_key`
- `api_secret`, `credential`

### Forbidden String Sentinels:
The inspector also scans string values for synthetic canary password values used during testing:
- `CanaryPass`
- `TestPass123!`

---

## 3. Safe Diagnostic Generation

When a violation occurs, the engine generates an `IngestionErrorCode.FORBIDDEN_FIELD_PRESENT` diagnostic:
1. **Diagnostic Content:** Explains that prohibited authentication secret fields were detected in the telemetry payload.
2. **Secret Scrubbing:** The error response specifically omits the offending field's value or raw payload context to ensure that error logs themselves do not become accidental credential repositories.
3. **Database Guard:** Rejection occurs prior to any ORM instantiation or database session participation.

