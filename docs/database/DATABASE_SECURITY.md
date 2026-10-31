# SnareSight — Database Security & Access Control Policy

**Document ID:** `SNARESIGHT-DB-SEC-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Cybersecurity Database Security Specialist & Systems Administrator  

---

## 1. Threat Model & Security Boundaries

The SnareSight database holds valuable security intelligence, honeypot telemetry, and detection alert records. Protecting this database against unauthorized access, credential leakage, and privilege escalation is a primary engineering requirement.

```
[ Honeypot VM (Untrusted Lab) ]
               │
               ▼ (Isolated Virtual Network - 192.168.56.0/24)
  [ NO DIRECT DATABASE CONNECTION ]
               │
               ▼ (Tailed JSONL / Ingestion API)
[ SnareSight Ingestion Service (Host) ]
               │
               ▼ (Local Loopback 127.0.0.1:5432)
   +---------------------------------------+
   | PostgreSQL Database ('snaresight')    |
   | Authentication: SCRAM-SHA-256         |
   | Strict Role Separation (DML vs DDL)   |
   +---------------------------------------+
```

---

## 2. Principle of Least Privilege & Role Separation

Three distinct database roles are enforced to maintain a strict separation of administrative, migration, and application privileges:

### 2.1 Role 1: `postgres` (Superuser / System Administration)
- **Scope:** Reserved strictly for initial database creation, role provisioning, and system maintenance.
- **Access Rule:** Used only by the Windows administrator during manual installation. The SnareSight application code or CI/CD pipelines **NEVER connect as superuser**.

### 2.2 Role 2: `snaresight_migrator` (Schema DDL Role)
- **Scope:** Dedicated role for executing Alembic schema migrations.
- **Privileges:**
  - `CREATE`, `ALTER`, `DROP` on tables, indexes, constraints, and sequences within schema `public`.
  - Database ownership or full DDL rights on `snaresight`.
- **Usage:** Invoked strictly during migration commands (`alembic upgrade head`). Dormant during normal application runtime.

### 2.3 Role 3: `snaresight_app` (Application Runtime Role)
- **Scope:** Used by FastAPI API services, event ingestion workers, and detection engines during daily operations.
- **Privileges (Strict Least Privilege):**
  - `SELECT`, `INSERT`, `UPDATE` on tables in schema `public`.
  - `USAGE`, `SELECT` on sequences.
  - **PROHIBITED:** `DROP TABLE`, `ALTER TABLE`, `TRUNCATE`, `CREATE TABLE`. The runtime application cannot alter database schemas even if exploited via application vulnerability.

```sql
-- Privilege Enforcement Script
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO snaresight_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO snaresight_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO snaresight_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO snaresight_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO snaresight_app;
```

---

## 3. Network Hardening & Interface Binding

1. **Loopback Only:** In `postgresql.conf`, `listen_addresses = '127.0.0.1'`. Binding to wildcard `0.0.0.0` or public interfaces is strictly prohibited.
2. **Honeypot Decoy Isolation:** The honeypot VM (`192.168.56.0/24`) is strictly blocked from reaching host port 5432 by host firewall and default-deny policies.
3. **Client Authentication Hardening:** In `pg_hba.conf`:
   ```
   # TYPE  DATABASE        USER                  ADDRESS                 METHOD
   host    snaresight      snaresight_app        127.0.0.1/32            scram-sha-256
   host    snaresight      snaresight_migrator   127.0.0.1/32            scram-sha-256
   ```
   `trust` authentication is strictly prohibited.

---

## 4. Secret Management & Git Hygiene

1. **Ignored `.env` File:** Production and local database connection strings containing passwords are stored strictly in `backend/.env` which is excluded from Git via `.gitignore`.
2. **Template Sanitization:** `backend/.env.example` provides placeholder values only:
   ```bash
   DATABASE_URL=postgresql+psycopg://snaresight_app:CHANGE_ME_IN_LOCAL_ENV@127.0.0.1:5432/snaresight
   MIGRATION_DATABASE_URL=postgresql+psycopg://snaresight_migrator:CHANGE_ME_IN_LOCAL_ENV@127.0.0.1:5432/snaresight
   ```
3. **No Hardcoded Credentials:** Zero database credentials or connection strings exist in Python source files or frontend code.

