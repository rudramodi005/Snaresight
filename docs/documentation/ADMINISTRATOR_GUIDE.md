# SnareSight: Platform Administrator & Maintenance Guide

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Audience:** Platform Administrators, Site Reliability Engineers (SREs), and Compliance Officers  

---

## 1. System Administration Overview

As an administrator of the SnareSight platform, your responsibilities include managing user access, registering and monitoring honeypot sensors, calibrating detection rules, enforcing compliance data retention policies, and verifying operational resilience through backups and disaster recovery validation.

---

## 2. Role-Based Access Control (RBAC) & User Management

SnareSight implements a three-tier Role-Based Access Control model enforced at the FastAPI dependency layer:

| Role | Permissions & Capabilities | Ideal Assignment |
|---|---|---|
| **`admin`** | Full administrative rights. Can create/delete users, register sensors, rotate API tokens, trigger backups, perform restore dry-runs, and toggle detection rules. | Lead Security Engineer, SRE, Platform Owner |
| **`analyst`** | Operational access. Can view alerts, triage incidents, claim cases, generate firewall rules, and download reports. Cannot modify system configurations or user accounts. | SOC Tier 1, 2, and 3 Analysts, Threat Hunters |
| **`auditor`** | Read-only inspection access. Can view immutable audit logs, reports, and compliance retention holds. Cannot modify alerts or generate firewall actions. | Compliance Auditors, External Reviewers, Mentors |

### 2.1 User Administration via CLI / API
To create a new user via API:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/users" \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "tier1_analyst@snaresight.local",
    "password": "TemporarySecurePassword2026!",
    "role": "analyst"
  }'
```

---

## 3. Sensor Fleet Administration & Token Rotation

Decoy honeypots must be registered in SnareSight before telemetry ingestion is permitted.

### 3.1 Provisioning a Decoy Sensor
1. Navigate to **Admin** > **Sensors** > **Register Sensor**.
2. Provide a descriptive hostname (e.g., `sensor-web-corp-01`) and select `web_login` or `cowrie_ssh`.
3. Save the returned `X-Sensor-Key`.
4. Configure the remote forwarder agent:
   ```json
   {
     "backend_url": "http://192.168.56.1:8000/api/v1",
     "sensor_id": "sensor-web-corp-01",
     "sensor_key": "YOUR_GENERATED_KEY",
     "heartbeat_interval_seconds": 30
   }
   ```

### 3.2 Key Revocation & Emergency De-Registration
If a decoy honeypot VM is compromised or suspected of pivoting:
1. Immediately invoke token revocation:
   ```bash
   curl -X POST "http://127.0.0.1:8000/api/v1/sensors/{sensor_id}/credentials/{key_id}/revoke" \
     -H "Authorization: Bearer <ADMIN_TOKEN>"
   ```
2. The backend immediately drops all subsequent incoming HTTP requests carrying that key with `401 Unauthorized`.

---

## 4. Detection Rule Management & Threshold Calibration

Administrators can toggle rules and tune sensitivity without restarting the backend service:

* **List Active Rules:** `GET /api/v1/attack/catalogue/metadata`
* **Disable/Enable Rule:** Toggle `is_enabled` on `detection_rules` table via administrative API.
* **Calibrate Thresholds:** Adjust `threshold` and `time_window_seconds` in the Rule definition to compensate for high-noise subnets.

---

## 5. Data Retention Policies & Retention Hold Enforcement

To optimize database storage while complying with regulatory requirements:

### 5.1 Automated Pruning Job
SnareSight enforces a default **90-day retention window** (`DATA_RETENTION_DAYS=90` in `backend/.env`). A periodic background task prunes raw telemetry older than the retention threshold:
```sql
DELETE FROM security_events 
WHERE timestamp < NOW() - INTERVAL '90 days'
  AND id NOT IN (
    SELECT event_id FROM alert_evidence
    JOIN alerts ON alert_evidence.alert_id = alerts.id
    JOIN response_cases ON alerts.case_id = response_cases.id
    WHERE response_cases.retention_hold = TRUE
  );
```

### 5.2 Legal & Forensic Retention Holds
* When a security incident is designated for legal proceedings, an analyst sets `retention_hold = TRUE` on the Case.
* The deletion engine **strictly bypasses** any events, alerts, or audit records associated with an active retention hold.

---

## 6. Database Backups & Isolated Dry-Run Restore

SnareSight features an automated backup and disaster recovery validation subsystem (`app.modules.resilience`).

### 6.1 Creating an Immediate Snapshot
Trigger an automated PostgreSQL backup:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/resilience/backups" \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
* Generates a compressed SQL dump in `backend/backups/`.
* Computes and records the cryptographic SHA-256 checksum in the `database_backups` table.

### 6.2 Performing an Isolated Dry-Run Restore Test
To verify backup viability without risking production data:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/resilience/backups/{backup_id}/restore-test" \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
* **Process:**
  1. The backend provisions an isolated, temporary SQLite or staging PostgreSQL instance.
  2. The backup archive is decompressed and restored into the isolated target.
  3. Integrity checks verify table count, migration version, and record checksums.
  4. The temporary instance is immediately torn down.
  5. The verification outcome (`SUCCESS` or `FAILURE`) and duration are logged in `restore_test_records`.

---

## 7. Operational Health Diagnostics & Logging

* **Kubernetes Liveness Probe:** `GET /api/v1/resilience/health/live`
* **Readiness Probe:** `GET /api/v1/resilience/health/ready`
* **Internal Diagnostics:** `GET /api/v1/resilience/health/diagnostics` returns:
  * Database connection pool status (active, idle, overflow).
  * Storage disk usage of telemetry and backup directories.
  * Ingestion queue latency and average event processing time.

