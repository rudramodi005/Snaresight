# SnareSight — Database Backup & Disaster Recovery Guide

**Document ID:** `SNARESIGHT-DB-BACKUP-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Administrator & Disaster Recovery Specialist  

---

## 1. Objectives & Compliance

The SnareSight backup and recovery framework guarantees forensic data preservation and rapid recovery in the event of hardware failure, disk corruption, or accidental administrative error.

---

## 2. Backup Strategy & Frequency

| Backup Tier | Mechanism | Schedule | Retention | Target Directory |
| :--- | :--- | :--- | :--- | :--- |
| **Full Logical Backup** | `pg_dump` (Custom format `-Fc`) | Daily at 02:00 UTC | 30 days active, 365 days cold archive | `C:\SnareSight_Backups\daily\` |
| **Pre-Migration Snapshot** | `pg_dump` (Custom format `-Fc`) | Before every `alembic upgrade` | 90 days | `C:\SnareSight_Backups\pre_migration\` |

---

## 3. Backup Execution Procedures

### 3.1 Creating a Logical Backup
Using PostgreSQL's native `pg_dump` utility:
```powershell
# Execute backup to local encrypted backup directory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFile = "C:\SnareSight_Backups\snaresight_backup_$Timestamp.dump"

& "C:\Program Files\PostgreSQL\16\bin\pg_dump.exe" `
    --host=127.0.0.1 `
    --port=5432 `
    --username=postgres `
    --format=custom `
    --blobs `
    --verbose `
    --file=$BackupFile `
    snaresight
```

### 3.2 Backup Storage & Git Exclusion Rules
- Backup files (`*.dump`, `*.sql.gz`) MUST NEVER be stored in the project workspace or committed to Git.
- `c:\Projects\SnareSight\.gitignore` strictly ignores `*.dump`, `*.sql.gz`, and `db_backups/`.
- Backups are stored in an access-restricted directory on the host accessible only by Windows Administrators.

---

## 4. Database Recovery & Restore Procedure

In the event of database failure or testing recovery procedures:

### Step 1: Terminate Active Application Connections
```sql
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'snaresight' AND pid <> pg_backend_pid();
```

### Step 2: Restore from Backup Archive
Using `pg_restore`:
```powershell
& "C:\Program Files\PostgreSQL\16\bin\pg_restore.exe" `
    --host=127.0.0.1 `
    --port=5432 `
    --username=postgres `
    --dbname=snaresight `
    --clean `
    --if-exists `
    --verbose `
    "C:\SnareSight_Backups\snaresight_backup_YYYYMMDD_HHMMSS.dump"
```

### Step 3: Verify Integrity After Restore
Execute verification queries to validate that table row counts, indexes, and foreign key relationships are fully intact.

