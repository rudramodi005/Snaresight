# Event Retention Policy Specification

**Document ID:** DB-RET-001  
**Classification:** Policy and Governance Specification  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED (Provisional Defaults Documented)  

---

## 1. Centralized Retention Policy Matrix

SnareSight implements category-specific data retention windows configured in [`RetentionPolicyConfig`](file:///c:/Projects/SnareSight/backend/app/retention/config.py). Retention periods are never hardcoded in SQL queries or application logic.

| Category Identifier | Description | Provisional Default | Allowed Range (Min - Max) | Reference Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| `RAW_EVENTS` | Original sanitized sensor logs | **90 Days** | 7 - 730 Days | Server `received_at` / `created_at` |
| `NORMALIZED_EVENTS` | Structured security events | **180 Days** | 14 - 1095 Days | Server `received_at` / `created_at` |
| `ALERTS` | Detection findings & summaries | **365 Days** | 30 - 2555 Days | Server `generated_at` / `created_at` |
| `SIMULATION_EVENTS` | Synthetic benchmark test runs | **14 Days** | 1 - 90 Days | Server `started_at` / `created_at` |
| `IMPORT_HISTORY` | Records of file batch imports | **30 Days** | 7 - 180 Days | Server `created_at` |
| `OPERATIONAL_LOGS` | Engine processing diagnostics | **30 Days** | 3 - 90 Days | Server `created_at` |
| `AUDIT_RECORDS` | Legal & evidence access history | **730 Days** (2 Years) | 90 - 3650 Days | Server `created_at` |
| `INVESTIGATION_EVIDENCE` | Records linked to investigations | **1095 Days** (3 Years) | 180 - 3650 Days | Formal Preservation Hold |

---

## 2. Temporal Reference Invariant

**Attacker-Controlled Timestamps Are Strictly Prohibited from Driving Retention:**
- Honeypot interactions contain an `observed_at` timestamp reported by the collector. An adversary manipulating clock settings could forge timestamps years in the past to trigger premature data eviction.
- **Enforcement:** The [`RetentionCalculator`](file:///c:/Projects/SnareSight/backend/app/retention/calculator.py) calculates retention eligibility strictly using server-recorded UTC timestamps (`received_at`, `created_at`, or `generated_at`). Tested in `TEST RET-013`.

---

## 3. Configuration Modification Guardrails

Retention policy changes are guarded by strict programmatic bounds:
- Setting a duration below the category minimum or above the category maximum raises a `ValueError` (`TEST RET-014`).
- Automatic destructive deletion is **disabled by default**. Deletion operations require explicit administrative authorization tokens.

