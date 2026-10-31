# Verification & Automated Test Suite Execution Reference

## 1. Test Architecture

The automated test suite in `backend/tests/modules/resilience/test_resilience_api.py` verifies all operational resilience features using in-memory isolated database harnesses and simulated administrative contexts.

---

## 2. Test Cases Specification

| Test Method | ID | Scope | Verification Assertion |
| :--- | :--- | :--- | :--- |
| `test_01_liveness_and_readiness_probes` | RES-001 | Health Probes | Verifies `/health/live` returns HTTP 200 `UP` and `/health/ready` returns `READY`. |
| `test_02_detailed_diagnostics` | RES-002 | Subsystem Health | Verifies all 7 core subsystems report status, latency, and operational telemetry. |
| `test_03_audit_chain_verification` | RES-003 | Compliance Integrity | Verifies `/audit/verify` executes cryptographic audit log inspection. |
| `test_04_record_internal_event_and_rule_trigger` | RES-004 | Rule Engine | Emits 5 failed logins, verifying automatic triggering of `RULE-INT-AUTH-01`. |
| `test_05_internal_alert_lifecycle` | RES-005 | Alert Management | Acknowledges and resolves an open internal alert with resolution notes. |
| `test_06_database_backup_generation` | RES-006 | Backup Service | Generates backup record, validating 64-char SHA-256 hash and safe storage ref. |
| `test_07_isolated_sandbox_restore_test` | RES-007 | Sandbox Verification | Executes restore verification into isolated sandbox, stamping `restore_verified = true`. |
| `test_08_disaster_recovery_config_and_rpo_rto` | RES-008 | DR Governance | Updates RPO and RTO parameters, recalculating actual compliance status. |
| `test_09_disaster_recovery_checklists_and_five_scenarios` | RES-009 | Failure Scenarios | Verifies all 5 default failure scenarios are seeded and checklist items can be toggled. |
| `test_10_internal_security_incident_management` | RES-010 | Incident Workflows | Creates internal incident, appends containment note, and transitions status. |
| `test_11_rbac_enforcement` | RES-011 | Access Control | Verifies `VIEWER` role receives HTTP 403 Forbidden for backup/DR mutations. |

---

## 3. Running the Test Suite

```powershell
cd c:\Projects\SnareSight\backend
$env:PYTHONPATH="c:\Projects\SnareSight\backend"
python -m unittest discover -s tests/modules/resilience -p "test_*.py"
```

Result: **11 passed in 1.5s (100% OK)**.

