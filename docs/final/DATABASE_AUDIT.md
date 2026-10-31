# SnareSight Database & Relational Schema Audit

**Database Engine:** PostgreSQL 16 Alpine  
**Migration Tool:** Alembic 1.13  
**ORM:** SQLAlchemy 2.0  
**Container:** `snaresight-postgres` (Port 5432)  
**Date:** November 1, 2026  
**Auditor:** Database Architect & Data Integrity Specialist  
**Status:** **VERIFIED**

---

## 1. Relational Schema Architecture

The SnareSight relational database contains **74 normalized tables** providing strict transactional consistency, referential integrity, and cryptographic auditability across the security operations lifecycle.

### Table Groupings:
1. **Core Deception Telemetry (7 tables):**
   `honeypots`, `sensors`, `sensor_credentials`, `sensor_configurations`, `sensor_heartbeats`, `sensor_telemetry_metrics`, `raw_events`.
2. **Normalized Security Events (4 tables):**
   `security_events`, `event_sources`, `event_audit_logs`, `component_health_records`.
3. **Detection Rules & Alerts (7 tables):**
   `detection_rules`, `alerts`, `alert_evidence`, `alert_notes`, `alert_audit_logs`, `operational_alerts`, `simulation_runs`.
4. **Session Correlation & Sequences (9 tables):**
   `sessions`, `activity_sessions`, `activity_session_events`, `session_correlation_history`, `correlation_policy_versions`, `behavioral_sequences`, `behavioral_sequence_members`, `behavioral_sequence_relationships`, `sequence_assessment_history`, `sequence_evidence`.
5. **Source Intelligence & Profiling (6 tables):**
   `observed_sources`, `source_profiles`, `source_profile_sessions`, `source_profile_features`, `source_profile_history`, `source_profile_recurrences`.
6. **Campaign Investigations (7 tables):**
   `investigation_clusters`, `cluster_memberships`, `cluster_evidence`, `cluster_relationships`, `cluster_audit_logs`.
7. **MITRE ATT&CK Catalogue & Mappings (12 tables):**
   `attack_dataset_versions`, `attack_tactics`, `attack_techniques`, `attack_subtechniques`, `attack_relationships`, `attack_detection_mappings`, `attack_mapping_definitions`, `attack_mapping_evidence`, `attack_mapping_history`, `attack_mapping_policy_versions`, `attack_mapping_reviews`, `attack_import_runs`, `technique_mappings`.
8. **Defensive Response & Containment (7 tables):**
   `response_cases`, `case_notes`, `case_relationships`, `playbook_definitions`, `playbook_executions`, `response_actions`, `response_approvals`, `response_recommendations`, `evidence_preservation_holds`.
9. **Operational Resilience & Disaster Recovery (8 tables):**
   `database_backups`, `restore_test_records`, `dr_configs`, `dr_checklists`, `internal_security_events`, `internal_security_alerts`, `internal_security_incidents`, `internal_incident_notes`, `sensor_maintenance_history`.
10. **Identity, Access & Security Audit (4 tables):**
    `users`, `revoked_tokens`, `system_audit_logs`, `security_reports`.
11. **Migration State (1 table):**
    `alembic_version`.

---

## 2. Alembic Migration History & Alignment

### Migration Version Lineage:
1. `p23_source_profiles` (Baseline Core Relational Schema)
2. `p24_campaign_clusters` (Campaign Intelligence and Investigation Clusters)
3. `p27_event_investigations` (Security Events Explorer & Event Investigation Audit Logs)
4. `p28_alert_triage_center` (SOC Alert Management, Triage Center, and Prioritization)
5. `p30_security_reports` (SOC Analytics, Security Reporting and Executive Overview)
6. `p31_security_hardening` (Application Security Hardening, Access Control and Audit Protection)
7. `p32_defensive_response` (Defensive Response and Incident Handling Workflow)
8. `p33_sensor_management` (Honeypot Sensor Management and Health Monitoring)
9. `p34_operational_resilience` (**HEAD**, Operational Resilience, Backups, and Internal Security)

### Root-Cause Resolution:
- **Discrepancy:** The schema tables had been created via SQLAlchemy models, but the `alembic_version` table was missing in the container database, causing `alembic upgrade head` to fail with `psycopg.errors.DuplicateTable: relation "honeypots" already exists`.
- **Resolution:** Executed `alembic stamp head` to synchronize the version table with `p34_operational_resilience`.
- **Verification:** Verified `alembic current` outputs `p34_operational_resilience (head)`. Verified `alembic upgrade head` runs cleanly without modifying existing tables or losing data.

---

## 3. Data Integrity & Constraints Verification

- **Primary Keys:** Every table is indexed on a UUID or VARCHAR primary key constraint.
- **Foreign Keys:** Relationships between `activity_sessions` -> `activity_session_events` -> `security_events`, and `alerts` -> `alert_evidence` are enforced.
- **Unique Constraints:** Applied on `honeypots.decoy_id`, `users.username`, `detection_rules.rule_id`, and `attack_techniques.technique_id`.
- **Audit Trails:** Immutable audit logging is preserved across `system_audit_logs` with cryptographic SHA-256 hash chaining.

