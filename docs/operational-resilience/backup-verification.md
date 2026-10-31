# Isolated Sandbox Restore Testing & Schema Verification

## 1. Principles of Non-Destructive Restore Testing

Untested backups provide zero recovery guarantees. However, restoring backups over a live production database causes data corruption, downtime, and telemetry loss.

To solve this, SnareSight implements **Isolated Sandbox Restore Testing**:

```mermaid
sequenceDiagram
    autonumber
    actor Admin as SOC Administrator
    participant API as /resilience/backups/{id}/restore-test
    participant Service as BackupService
    participant Sandbox as Isolated Sandbox DB (isolated_sandbox_db)
    participant LiveDB as Live Production PostgreSQL

    Admin->>API: POST /restore-test
    API->>Service: run_isolated_restore_test(backup_id)
    Note over Service,Sandbox: LiveDB is strictly protected and untouched
    Service->>Service: Validate Cryptographic SHA-256 Checksum
    Service->>Sandbox: Unpack schema & tables into isolated sandbox
    Service->>Sandbox: Verify Table Count (>= 25 core tables)
    Service->>Sandbox: Verify Primary & Foreign Key Constraints
    Service->>Sandbox: Run Integrity Verification Query
    Service->>LiveDB: Stamp backup.restore_verified = true
    Service->>LiveDB: Insert restore_test_records entry
    Service->>LiveDB: Log Audit Event (VERIFY_BACKUP_RESTORE_SANDBOX)
    Service-->>Admin: Return RestoreTestResponse (SUCCESS)
```

---

## 2. Verification Criteria

A backup is stamped `restore_verified = true` if and only if:
1. **Cryptographic Checksum**: File payload SHA-256 precisely matches `checksum_sha256`.
2. **Schema Compatibility**: Core tables (users, roles, permissions, security_events, attacker_sessions, honeypot_sensors, system_audit_logs, etc.) match current schema definitions.
3. **Table Count**: At least 25 core platform tables unpack cleanly.
4. **Data Integrity**: Integrity checks pass without foreign key constraint violations or orphaned records.

