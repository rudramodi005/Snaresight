# SnareSight: Role-Based Access Control (RBAC) Matrix

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. System Roles

SnareSight implements three hierarchical operational roles:
1. **`ADMIN` (Administrator)**: Complete system governance, user provisioning, role assignments, sensor lifecycle management, and detection rule configuration.
2. **`ANALYST` (Security Analyst)**: Core security operations, alert triage and assignment, campaign investigations, mapping reviews, report generation, and data export.
3. **`VIEWER` (Read-Only Auditor)**: Observability of dashboard, security events, and active alerts. Prohibited from mutating alerts, adding notes, modifying mappings, creating users, or viewing audit logs.

---

## 2. Permission Mapping Matrix

| Operational Permission | Description | `ADMIN` | `ANALYST` | `VIEWER` |
| :--- | :--- | :---: | :---: | :---: |
| `view_dashboard` | View SOC overview metrics & trends | **YES** | **YES** | **YES** |
| `view_events` | View normalized security events | **YES** | **YES** | **YES** |
| `view_sensitive_evidence` | View unmasked forensic payloads & headers | **YES** | **YES** | NO |
| `view_alerts` | View generated alerts | **YES** | **YES** | **YES** |
| `assign_alerts` | Assign alerts to analysts | **YES** | **YES** | NO |
| `acknowledge_alerts` | Transition alert status to ACKNOWLEDGED | **YES** | **YES** | NO |
| `resolve_alerts` | Transition alert status to RESOLVED | **YES** | **YES** | NO |
| `close_alerts` | Transition alert status to CLOSED | **YES** | **YES** | NO |
| `add_investigation_notes` | Post notes to alerts or campaigns | **YES** | **YES** | NO |
| `modify_mapping_review_status` | Approve or reject MITRE ATT&CK mappings | **YES** | **YES** | NO |
| `generate_reports` | Generate PDF and CSV security reports | **YES** | **YES** | NO |
| `export_data` | Export raw telemetry and investigation data | **YES** | **YES** | NO |
| `manage_sensors` | Register, reconfigure, or retire honeypot sensors | **YES** | NO | NO |
| `manage_detection_rules` | Enable, disable, or author detection rules | **YES** | NO | NO |
| `manage_users` | Provision users and adjust role permissions | **YES** | NO | NO |
| `view_audit_logs` | Inspect system security audit records | **YES** | **YES** | NO |
| `modify_system_configuration` | Mutate core system parameters and keys | **YES** | NO | NO |

---

## 3. Backend Enforcement Architecture

Permissions are enforced exclusively at the backend dependency injection level using `require_permission(permission)` and `require_role(role)` in `app.modules.security.dependencies`. 

Frontend UI button states (e.g., hidden or disabled buttons) serve as visual guidance only; the backend **denies by default** and returns `HTTP 403 Forbidden` if an unauthorized request is submitted.

