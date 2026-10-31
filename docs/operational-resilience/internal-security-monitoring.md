# Internal Security Monitoring & Control-Plane Detection Rules

## 1. Internal Security Monitoring Principles

SnareSight implements real-time monitoring of its own administrative interface, authentication endpoints, and background workers. Internal security events are logged to the `internal_security_events` table and continuously evaluated by `InternalRuleEngine`.

---

## 2. Seven Core Internal Security Detection Rules

| Rule ID | Name | Trigger Condition | Severity | Recommended SOC Action |
| :--- | :--- | :--- | :--- | :--- |
| **`RULE-INT-AUTH-01`** | Repeated Internal Authentication Failures | $\ge 5$ failed administrative authentication attempts within 10 minutes | **HIGH** | Inspect source IP, temporarily lock targeted account if suspicious, and review audit trail. |
| **`RULE-INT-PRIV-02`** | Unauthorized Privilege Escalation Attempt | Attempt by non-admin or unauthorized actor to modify roles or permissions | **CRITICAL** | Terminate active user session immediately, freeze account, and audit user activity. |
| **`RULE-INT-AUTHZ-03`** | Access Denied Anomaly on Control Plane | $\ge 4$ HTTP 403 Forbidden outcomes within 15 minutes | **MEDIUM** | Review requested endpoints, check whether token is expired or unauthorized API probing occurred. |
| **`RULE-INT-CFG-04`** | Critical System Configuration Modification | Changes applied to system security settings, encryption policies, or DR retention | **MEDIUM** | Confirm change ticket authorization with security lead and inspect configuration diff. |
| **`RULE-INT-AUDIT-05`** | Audit Trail Integrity Anomaly / Failure | Audit persistence was disrupted, or cryptographic hash chain verification detected corrupted records | **CRITICAL** | Inspect database filesystem, verify audit table constraints, and initiate forensic integrity audit. |
| **`RULE-INT-BCK-06`** | Database Backup or Recovery Verification Failure | Scheduled or manual backup failed, or isolated sandbox restore test failed | **HIGH** | Examine storage space, check database dump permissions, and trigger an immediate isolated recovery test. |
| **`RULE-INT-INGEST-07`** | Honeypot Telemetry Ingestion Anomaly | Abnormal spike in rejected honeypot payloads or sensor authentication failures | **HIGH** | Inspect honeypot network connectivity, check sensor credentials, and verify telemetry parser health. |

---

## 3. Alert Lifecycle & Resolution Workflow

1. **Trigger**: When an internal event matches rule conditions, an `InternalSecurityAlertModel` is generated or correlated into an existing `OPEN` alert.
2. **Triage**: Analysts or administrators review the alert via `/api/v1/resilience/alerts` in the Platform Health workspace.
3. **Acknowledgment**: Calling `POST /alerts/{alert_id}/acknowledge` transitions state to `ACKNOWLEDGED` and stamps `acknowledged_by` and `acknowledged_at`.
4. **Remediation**: Corrective actions (e.g. session revocation, account lockout, or network rule adjustment) are executed.
5. **Resolution**: Calling `POST /alerts/{alert_id}/resolve` requires explicit `resolution_notes`, transitioning status to `RESOLVED`.

