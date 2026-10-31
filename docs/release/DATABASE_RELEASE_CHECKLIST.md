# SnareSight Database & Schema Migration Release Checklist

**Document ID:** CHK-P37-001  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Release Target:** v1.0.0-rc1  
**Date:** October 31, 2026  
**Status:** VERIFIED & READY FOR RELEASE  

---

## 1. Migration Lineage Verification

| Step | Revision ID | Down Revision | Description | Schema Changes |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `p23_source_profiles` | `<base>` | Core Baseline (P01–P23) | `honeypots`, `event_sources`, `raw_events`, `security_events`, `sessions`, `detection_rules`, `alerts`, `alert_evidence`, `attack_techniques`, `technique_mappings`, `source_profiles`. |
| **2** | `p24_campaign_clusters` | `p23_source_profiles` | Campaign Intelligence (P24) | `investigation_clusters`, `cluster_memberships`, `cluster_evidence`. |
| **3** | `p27_event_investigations` | `p24_campaign_clusters` | Event Investigations (P27) | `event_audit_logs`. |
| **4** | `p28_alert_triage_center` | `p27_event_investigations` | SOC Alert Triage (P28) | Extensions on `alerts`: `assigned_analyst`, `triage_decision`, `priority_score`, `priority_level`; `alert_notes`, `alert_audit_logs`. |
| **5** | `p30_security_reports` | `p28_alert_triage_center` | Security Reporting (P30) | `security_reports`. |
| **6** | `p31_security_hardening` | `p30_security_reports` | Security Hardening (P31) | `users`, `audit_logs`. |
| **7** | `p32_defensive_response` | `p31_security_hardening` | Defensive Response (P32) | `response_cases`, `case_notes`, `response_recommendations`, `playbook_definitions`, `playbook_executions`, `response_approvals`, `response_actions`, `evidence_preservation_holds`. |
| **8** | `p33_sensor_management` | `p32_defensive_response` | Sensor Operations (P33) | `sensors`, `sensor_heartbeats`, `sensor_configurations`, `operational_alerts`. |
| **9** | `p34_operational_resilience` | `p33_sensor_management` | Operational Resilience (P34) | `internal_security_events`, `internal_security_alerts`, `database_backups`, `restore_test_runs`, `disaster_recovery_configs`, `disaster_recovery_checklists`, `internal_incidents`, `internal_incident_notes`. |

---

## 2. Integrity & Constraint Verification Checklist

- [x] **Primary Key Standard:** All relational models use UUIDv4 primary keys (or explicit standard alphanumeric IDs like `decoy_id`, `rule_id`, `cluster_id`).
- [x] **Foreign Key Integrity:** Foreign keys use `ON DELETE CASCADE` for parent-child aggregates (e.g., `alert_notes`, `case_notes`) and `ON DELETE RESTRICT` for immutable telemetry evidence (`security_events`, `raw_events`).
- [x] **Timestamp Standards:** All timestamps are strictly `DateTime(timezone=True)` using UTC defaults (`datetime.now(timezone.utc)`). Clock skew tolerance is enforced to prevent future timestamp spoofing.
- [x] **JSON Validation:** Semi-structured evidence payloads use PostgreSQL `JSONB` for efficient querying and indexability with fallback to standard `JSON` on SQLite fixtures.
- [x] **Zero Password Invariant:** Schema models omit password columns; authentication interactions store only `password_present: Boolean` and irreversible SHA-256 username fingerprints.
- [x] **Forensic Hold Protection:** Records linked to active `EvidencePreservationHoldModel` entries are strictly protected from retention pruning and demonstration cleanup.
- [x] **Disaster Recovery Sandbox:** Isolated restore tests execute in a separate database namespace (`isolated_sandbox_db`) with zero mutation of active production tables.

---

## 3. Database Migration Execution Instructions

### Applying Migrations (Upgrade to Head)
```powershell
cd backend
uv run alembic upgrade head
```

### Checking Current Migration Revision
```powershell
cd backend
uv run alembic current
```

### Rollback Strategy (Emergency Only)
```powershell
cd backend
uv run alembic downgrade -1
```
> [!WARNING]
> Downgrading past `p31_security_hardening` drops user accounts and audit logs. In production environments, schema rollbacks must be accompanied by a full backup restore rather than live table drops.

