# SnareSight: Comprehensive STRIDE Threat Model

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. System Assets & Trust Boundaries

### Critical Assets Requiring Protection
1. **User Credentials & JWT Sessions**: Passwords, session cookies, bearer tokens.
2. **Deception Telemetry & Forensic Evidence**: Raw events, normalized events, payload captures.
3. **Detection Rules & MITRE Mapping Definitions**: Detection logic, sensitivity weights, approved mappings.
4. **Investigation Campaigns & Analyst Notes**: Incident notes, campaign clusters, attribution tags.
5. **System Audit Logs**: Historical records of logins, configuration mutations, alert triage actions.
6. **Sensor Configurations & Telemetry Gateway Keys**: `X-API-Key` collector tokens.

### Trust Boundaries
- **Boundary 1 (External Untrusted / Honeypot Perimeter)**: Attackers interacting with decoys. Decoys have zero direct database access.
- **Boundary 2 (Telemetry Ingestion Gateway)**: Telemetry crossing from decoys into backend via authenticated `POST /api/v1/ingestion/events/batch`.
- **Boundary 3 (Analyst Web Browser / Frontend)**: Browser client interacting with REST API and SSE stream.
- **Boundary 4 (Application Service Tier)**: FastAPI application running business logic and correlation.
- **Boundary 5 (Data Storage Tier)**: PostgreSQL database isolated on loopback (`127.0.0.1:5432`).

---

## 2. STRIDE Threat Assessment Matrix

| Threat Category | Threat Scenario | Affected Component | Potential Impact | Existing Protection | Required Mitigation | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates analyst via forged JWT token | `/api/v1/*` | Unauthorized access to SOC operations | HS256 JWT signature verification | Enforce strong `JWT_SECRET_KEY` and reject expired/forged tokens | `test_06_unauthenticated_request_rejection` |
| **Spoofing** | Rogue honeypot submits fabricated events | `/ingestion/events/batch` | Telemetry pollution, alert storm | `X-API-Key` header verification | Validate collector key, reject invalid sources | `test_19_telemetry_isolation_and_auth` |
| **Tampering** | Operator attempts to modify historical audit records | `system_audit_logs` | Loss of non-repudiation in forensic investigations | Immutable SQLAlchemy schema | Prohibit UPDATE and DELETE routes on audit tables | `test_14_audit_logging_recorded` |
| **Tampering** | Parameter manipulation for SQL injection | `/api/v1/audit/logs`, alerts | Unauthorized data exfiltration or tampering | SQLAlchemy parameterized queries | Parameterize all filters, reject arbitrary SQL strings | `test_11_sql_injection_resistance` |
| **Repudiation** | Analyst denies performing sensitive alert closing | `/api/v1/alerts/{id}/status` | Lack of accountability | `alert_audit_logs` | Write transactional audit entries with actor username and IP | `test_14_audit_logging_recorded` |
| **Information Disclosure** | Credential leakage in URL query parameters | `GET /api/v1/auth/me?token=...` | Tokens stored in access logs, proxy caches | Query parameter inspection | Reject credentials in query string with HTTP 400 | `test_20_query_param_token_rejection` |
| **Information Disclosure** | Plaintext password leakage in user listings | `GET /api/v1/auth/users` | Credential theft | Pydantic response filtering | Ensure `hashed_password` is excluded from all response schemas | `test_02_plaintext_passwords_never_stored_or_leaked` |
| **Denial of Service** | Credential brute-force attacks on login endpoint | `POST /api/v1/auth/login` | Account lockout, CPU exhaustion from bcrypt | None initially | Implement sliding-window rate limiter (5 attempts / 15m) | `test_05_login_rate_limiting` |
| **Denial of Service** | Oversized JSON payload crashes memory | `POST /api/v1/*` | Application memory exhaustion | None initially | `RequestSizeLimitMiddleware` rejecting payloads $> 2$MB | `test_12_request_size_limits` |
| **Elevation of Privilege** | `VIEWER` role executes administrative user creation | `POST /api/v1/auth/users` | Full platform takeover | None initially | Backend `require_permission(Permission.MANAGE_USERS)` | `test_07_unauthorized_role_rejection` |

