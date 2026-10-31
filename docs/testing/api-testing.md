# SnareSight API Integration Testing

## 1. Overview & Test Coverage

All FastAPI REST endpoints across SnareSight are tested using `starlette.testclient.TestClient`. Tests exercise request validation, response schemas, HTTP status codes, authentication headers, permission checks, and error responses.

---

## 2. API Route Test Matrix

| Router Prefix | Subsystem | Authentication | Primary HTTP Statuses Tested |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth` | User Authentication & Tokens | Stateless JWT / Passwords | 200 OK, 401 Unauthorized, 403 Forbidden |
| `/api/v1/ingestion` | Telemetry Ingestion | `X-API-Key` Header | 200 OK, 400 Bad Request, 401 Unauthorized, 422 Unprocessable |
| `/api/v1/dashboard` | Aggregated SOC Dashboard | Bearer JWT (`view_dashboard`) | 200 OK, 401 Unauthorized |
| `/api/v1/events` | Security Events Explorer | Bearer JWT (`view_events`) | 200 OK, 401 Unauthorized |
| `/api/v1/alerts` | Alert Management & Triage | Bearer JWT (`view_alerts`, `resolve_alerts`) | 200 OK, 400 Bad Request, 404 Not Found |
| `/api/v1/mitre` | ATT&CK Mapping & Review | Bearer JWT (`modify_mapping_review_status`) | 200 OK, 403 Forbidden |
| `/api/v1/analytics` | Analytics & Executive Reports | Bearer JWT (`generate_reports`, `export_data`) | 200 OK, 403 Forbidden |
| `/api/v1/response` | Defensive Response Cases | Bearer JWT (`acknowledge_alerts`, `close_alerts`) | 200 OK, 201 Created, 400 Bad Request |
| `/api/v1/sensors` | Honeypot Sensor Operations | Sensor Key (`X-Sensor-Key`) / Admin JWT | 200 OK, 201 Created, 401 Unauthorized, 403 Forbidden |
| `/api/v1/resilience`| Health, Backups & DR | Bearer JWT (`modify_system_configuration`) | 200 OK, 201 Created, 403 Forbidden |

---

## 3. Negative & Boundary Testing Assertions

1. **Missing / Invalid Credentials**:
   - Omitting Authorization headers returns HTTP 401 with standard `WWW-Authenticate: Bearer` challenge.
   - Forged or malformed JWT claims return HTTP 401 without stack trace exposure.
2. **Insufficient RBAC Permissions**:
   - `VIEWER` attempting to trigger backups, mutate sensor settings, or approve defense actions receives HTTP 403 Forbidden.
3. **Malformed Payloads & Constraints**:
   - Ingestion payloads missing required `source_id` or with invalid UUIDs return HTTP 422 Unprocessable Entity.
   - Cases with invalid priority strings are rejected by database CHECK constraints.

