# SnareSight — PostgreSQL Deployment & Setup Specification

**Document ID:** `SNARESIGHT-PG-SETUP-001`  
**Phase:** 3 — Event Pipeline and Database  
**Task:** P12 — Configure PostgreSQL and Database Migrations  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Systems Administrator  

---

## 1. Executive Summary & Evaluation of Options

SnareSight requires an ACID-compliant, high-performance relational database with native JSONB, UUID, and `TIMESTAMPTZ` capabilities to serve as the persistence tier for normalized deception telemetry, detection alerts, and MITRE ATT&CK correlation.

Three deployment architectures were evaluated against the host baseline (Windows 11 Home, AMD Ryzen 7 7445HS, 16 GB RAM, 122 GB free disk, VirtualBox 7.2 active):

| Evaluation Criteria | Option A: Native PostgreSQL 16 on Windows | Option B: PostgreSQL in Docker | Option C: WSL2 / Guest Linux Database |
| :--- | :--- | :--- | :--- |
| **System Prerequisites** | Zero additional hypervisor requirements. | Requires Docker Desktop + WSL2 / Hyper-V backend. | Requires dedicated Linux guest or WSL2 instance. |
| **Host Interaction** | Minimal (~350 MB disk, 60 MB idle RAM). | High (~4 GB Docker Desktop footprint + Hyper-V). | Medium (~1.5 GB memory reservation). |
| **VirtualBox Compatibility**| 100% compatible with existing honeypot VM. | Potential coexistence overhead with VirtualBox. | Complex cross-network routing to Windows host. |
| **Security Boundary** | Binds strictly to `127.0.0.1:5432` (loopback). | Binds to localhost via Docker port publishing. | Crosses virtual network trust boundaries. |
| **Service Lifecycle** | Managed natively via Windows Service Control. | Managed via Docker daemon and compose files. | Managed via systemd inside VM. |
| **Recommendation** | **RECOMMENDED (Option A)** | Alternative (High Resource Consumption) | Disapproved (Violates P08 Lab Isolation) |

> **Architectural Selection:** **Option A (Native PostgreSQL 16 on Windows)** is selected. It avoids hypervisor conflicts with VirtualBox 7.2, minimizes memory consumption, keeps the database strictly inside the trusted Windows host environment, and enforces strict loopback-only binding (`127.0.0.1:5432`).

---

## 2. Selected Installation Details (Option A)

- **Target Package:** PostgreSQL 16 (Current stable: `PostgreSQL.PostgreSQL.16` / v16.x)
- **Official Source:** PostgreSQL Global Development Group / EnterpriseDB (`https://www.postgresql.org/download/windows/`)
- **Package Manager:** Windows Package Manager (`winget.exe install PostgreSQL.PostgreSQL.16`)
- **Target Installation Path:** `C:\Program Files\PostgreSQL\16`
- **Target Data Directory:** `C:\Program Files\PostgreSQL\16\data`
- **Default Listening Port:** `5432`
- **Network Interface Binding:** Strictly `127.0.0.1` (loopback only in `postgresql.conf`)
- **Default Windows Service:** `postgresql-x64-16` (Automatic startup)

---

## 3. System Changes & Security Hardening

1. **Firewall Invariant:** PostgreSQL port 5432 will NEVER be opened in Windows Firewall for public or local network traffic. Only local loopback sockets (`127.0.0.1`) are permitted.
2. **Honeypot Decoy Isolation:** The honeypot VM (`192.168.56.0/24`) will have ZERO direct network access to the database. Ingestion occurs exclusively via the future SnareSight event ingestion worker.
3. **Authentication Hardening:** `pg_hba.conf` configured for `scram-sha-256` password encryption; `trust` authentication is strictly prohibited.
4. **Recovery / Uninstallation Procedure:**
   - To stop service: `Stop-Service postgresql-x64-16`
   - To cleanly uninstall: `winget uninstall PostgreSQL.PostgreSQL.16` or Windows Settings > Installed Apps.

---

## 4. Operational Roles & Database Structure

Following approval, the following distinct roles and database entities will be provisioned:

1. **Database:** `snaresight` (UTF-8 encoding, UTC timezone).
2. **Administrative Superuser:** `postgres` (local system administration only; application never connects as superuser).
3. **Migration Role:** `snaresight_migrator` (schema DDL permissions for Alembic migrations; no public Internet access).
4. **Application Runtime Role:** `snaresight_app` (restricted DML permissions: `SELECT`, `INSERT`, `UPDATE` on tables; `USAGE` on sequences; strictly zero DDL privileges).

