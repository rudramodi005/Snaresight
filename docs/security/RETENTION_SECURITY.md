# Retention Security Controls

**Document ID:** SEC-RET-001  
**Classification:** Operational Security & Access Control Spec  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED  

---

## 1. Threat Analysis of Data Purging

Automated retention and data deletion functionality presents significant security risks if subverted:
- **Threat A: Malicious Clock Tampering:** An attacker compromises a honeypot sensor or collector and injects events backdated to 2010 to trigger automated retention cleanup and immediate deletion.
  - *Mitigation:* `RetentionCalculator` evaluates expiration strictly using trusted server timestamps (`received_at`, `created_at`, `generated_at`), never attacker-supplied `observed_at`.
- **Threat B: Unauthorized Bulk Eviction:** A compromised service account or malicious script executes blanket deletions to destroy investigation traces.
  - *Mitigation:* Deletion requires an explicit authorization token (`CONFIRM_RETENTION_DELETION`) and administrative credentials. Dry-run mode is enforced by default.
- **Threat C: Database Deadlocks & Starvation:** Massive deletion queries locking critical tables.
  - *Mitigation:* Bounded batch execution (500 records per transaction chunk).

---

## 2. Least Privilege Database Permissions

Runtime application connections (`snaresight_app`) are granted `DELETE` privileges only where strictly necessary for retention execution, while migration roles (`snaresight_migrator`) handle structural DDL. Read-only analysts possess zero `DELETE` privileges.

