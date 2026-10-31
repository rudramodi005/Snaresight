# SnareSight: Security Audit Logging Architecture

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Audit Log Scope & Events Captured

The SnareSight audit logging engine records all security-relevant operational actions across the platform:

| Action Identifier | Description | Triggering Context |
| :--- | :--- | :--- |
| `LOGIN` | Successful user authentication | Correct credentials submitted |
| `FAILED_LOGIN` | Failed user authentication attempt | Incorrect password or non-existent user |
| `LOGIN_RATE_LIMITED` | Lockout triggered by excessive failed logins | Rate limit threshold exceeded (5 failures) |
| `LOGIN_DENIED` | Login blocked due to deactivated account | Inactive user attempted login |
| `LOGOUT` | User session terminated & token revoked | User initiated logout |
| `PASSWORD_CHANGE_SUCCESS`| Analyst password updated successfully | Current password validated and new hash written |
| `PASSWORD_CHANGE_FAILED` | Password update failed | Current password verification failed |
| `USER_CREATE` | New application user provisioned | Administrator created user account |
| `ALERT_STATUS` | Alert status transition | Analyst modified alert status (e.g. to RESOLVED) |
| `MAPPING_REVIEW` | MITRE ATT&CK mapping status change | Analyst approved or rejected mapping |
| `REPORT_GENERATE` | Security report compiled and exported | Analyst generated PDF or CSV report |

---

## 2. Audit Record Data Schema

Each audit record written to `system_audit_logs` contains:
- `id`: Unique UUID identifier.
- `actor_username`: Authenticated username (or `anonymous`).
- `actor_role`: System role of actor at time of event.
- `action`: Canonical action string.
- `resource_type`: Affected entity category (`AUTH`, `USER`, `ALERT`, `REPORT`, etc.).
- `resource_id`: Identifier of targeted resource (if applicable).
- `outcome`: `SUCCESS`, `DENIED`, or `FAILED`.
- `status_code`: Resulting HTTP response status code.
- `reason`: Explanation or justification.
- `ip_address`: Client remote IP address.
- `user_agent`: Client browser user agent string (truncated to 255 chars).
- `request_context`: Structured JSON containing metadata, with automatic sanitization of sensitive keys.
- `created_at`: UTC timestamp of event generation.

---

## 3. Immutability & Access Protection

- **Append-Only Invariant**: Audit records are strictly append-only. There are no API endpoints, service functions, or database triggers permitting updates or deletions of rows in `system_audit_logs`.
- **RBAC Governance**: Querying audit records (`GET /api/v1/audit/logs`) requires the `view_audit_logs` permission, restricted to `ADMIN` and `ANALYST` roles.

