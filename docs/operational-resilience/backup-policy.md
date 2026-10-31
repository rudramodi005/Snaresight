# Database Backup Strategy & Lifecycle Retention Policy

## 1. Backup Objectives & Governance

Database backups preserve the state of SnareSight: honeypot sensor configurations, threat session correlation graphs, MITRE ATT&CK mappings, active alerts, and tamper-resistant audit logs.

### Recovery Objectives
- **Target Recovery Point Objective (RPO)**: 60 minutes default (configurable down to 5 minutes).
- **Target Recovery Time Objective (RTO)**: 30 minutes default.
- **Backup Frequency**: Automated periodic runs every 24 hours, plus on-demand manual triggers.

---

## 2. Backup Types

1. **`FULL`**: Comprehensive point-in-time snapshot of all platform schemas, tables, sequences, and indexes.
2. **`PRE_MIGRATION`**: Snapshot triggered immediately before applying schema migrations via Alembic.
3. **`MANUAL`**: Operator-initiated backup before major administrative changes.

---

## 3. Cryptographic Verification & Safe Storage

- **SHA-256 Digest**: Every backup artifact calculates a canonical SHA-256 hash immediately upon creation.
- **Safe URI Masking**: Backups are referenced via sanitized tokens (e.g. `safe://backups/snaresight_BCK-20261031-ABCD.dump`). No filesystem passwords, database credentials, or secret keys are exposed.
- **Retention Policy**:
  - Hot Backups: Retained for 30 days (`backup_retention_days`).
  - Cold Archives: Retained for 365 days (`cold_archive_retention_days`).
  - **Retention Hold**: Backups flagged with `retention_hold = True` are exempted from automatic lifecycle pruning until manually released by an administrator.

