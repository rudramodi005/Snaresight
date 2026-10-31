# SnareSight — Database Test Plan & Validation Specifications

**Document ID:** `SNARESIGHT-DB-TEST-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Cybersecurity QA Engineer & Database Test Specialist  

---

## 1. Scope & Test Environment

This document defines the 22 automated test scenarios designed to validate the PostgreSQL database tier, SQLAlchemy ORM models, constraints, and sensitive data protections.

All tests are implemented using `pytest` and executed against a dedicated disposable local test database (`snaresight_test`) to prevent pollution of operational records.

---

## 2. Test Catalog (TEST DB-001 to DB-022)

| Test ID | Test Name | Target Component | Expected Behavior |
| :--- | :--- | :--- | :--- |
| `DB-001` | Connection Verification | Engine Pool | Database connection to `127.0.0.1:5432` succeeds. |
| `DB-002` | Connection Failure Safety | Error Handler | Invalid connection string fails gracefully without leaking credentials. |
| `DB-003` | Metadata Definition | SQLAlchemy Base | All 12 tables and schemas load into `Base.metadata`. |
| `DB-004` | Honeypot Record Creation | `HoneypotModel` | Inserts and retrieves valid decoy record (`WEB-001`). |
| `DB-005` | Event Source Registration | `EventSourceModel`| Inserts and retrieves collector agent record. |
| `DB-006` | Raw Event Persistence | `RawEventModel` | Stores sanitized raw event with JSONB payload. |
| `DB-007` | Normalized Event Persistence | `SecurityEventModel`| Stores normalized security event with UTC timestamps. |
| `DB-008` | Session Relationship | `SessionModel` | Relates session ID to multiple normalized events. |
| `DB-009` | Alert Record Persistence | `AlertModel` | Stores security alert with independent severity & confidence. |
| `DB-010` | Alert Evidence Junction | `AlertEvidenceModel`| Links alert to supporting normalized security events. |
| `DB-011` | Unique Identifiers | Constraints | Duplicate UUID or decoy ID raises `IntegrityError`. |
| `DB-012` | Foreign Key Constraints | Constraints | Inserting event with non-existent `decoy_id` is rejected. |
| `DB-013` | Confidence Boundary Check | Check Constraint | Confidence `< 0` or `> 100` raises `CheckViolation`. |
| `DB-014` | Severity Restrictions | Check Constraint | Invalid severity string (e.g. `'EXTREME'`) is rejected. |
| `DB-015` | Provenance Restrictions | Check Constraint | Unsupported provenance string is rejected. |
| `DB-016` | Idempotent Upsert | Unique Index | Duplicate `deduplication_reference` triggers `ON CONFLICT DO NOTHING`. |
| `DB-017` | UTC Timestamp Storage | `TIMESTAMPTZ` | Timestamps stored and retrieved with correct UTC offset. |
| `DB-018` | Transaction Rollback | Session | Unhandled exception triggers complete rollback. |
| `DB-019` | Session Cleanup | Session Factory | Database sessions are closed cleanly after query execution. |
| `DB-020` | Sensitive Field Rejection | Schema Validation | Models reject dictionary containing `"password"` or `"secret"`. |
| `DB-021` | Runtime Role Restriction | PostgreSQL Privileges| `snaresight_app` role cannot execute `DROP TABLE`. |
| `DB-022` | Network Loopback Binding | Network Audit | Port 5432 is unreachable from outside `127.0.0.1`. |

