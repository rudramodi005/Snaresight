# SnareSight: Database Security Architecture & Isolation

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Network Exposure & Binding

PostgreSQL binds exclusively to the local loopback interface:
- **Host**: `127.0.0.1` (or internal container bridge network).
- **Port**: `5432`.
- **Public Exposure**: Strictly disabled. Database ports are blocked by host firewalls from any external interfaces or honeypot networks.

---

## 2. Least-Privilege Database Roles

Database access is segregated across dedicated PostgreSQL service roles:

| Role Name | Scope | Permissions Granted | Prohibited Actions |
| :--- | :--- | :--- | :--- |
| `postgres` | Maintenance | Superuser (local administration only) | Direct application runtime connections |
| `snaresight_migrator` | Schema Management | DDL operations (`CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`) | Direct ingestion data pipeline access |
| `snaresight_app` | Runtime Application | DML operations (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) | DDL operations, schema altering, table dropping |
| `Honeypots` | Perimeter Decoys | **NONE** (Zero database access) | Any connection or query to PostgreSQL |

---

## 3. Data Integrity & Transaction Safety

1. **Parameterized Queries**: All SQLAlchemy queries are compiled with bound parameters, preventing SQL injection vulnerabilities across all search and filtering paths.
2. **Atomic Transactions**: Complex state mutations (e.g. creating a user and recording the corresponding audit log entry) execute inside managed database transactions (`db.commit()`), rolling back cleanly on exceptions.
3. **Immutable Audit Preservation**: Audit tables (`system_audit_logs`, `alert_audit_logs`, `event_audit_logs`, `cluster_audit_logs`) are append-only. The application contains zero API endpoints or service methods for updating or deleting audit rows.

