# SnareSight: REST API Security Controls

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Input Validation & Parameter Safety

1. **Strict Pydantic Schemas**: Every API payload is validated against strict Pydantic models. Unrecognized or unexpected fields are filtered out, preventing mass-assignment vulnerabilities.
2. **SQL Injection Resistance**: All database operations utilize SQLAlchemy 2.0 ORM expressions or explicitly parameterized queries (`:param`). User-supplied filter parameters are never concatenated into raw SQL strings.
3. **No Arbitrary Commands**: The application contains zero shell execution paths (`subprocess`, `os.system`) triggered by user input.
4. **URL Parameter Credential Rejection**: Any endpoint detecting credentials or session tokens in query parameters (`?token=...`, `?api_key=...`) immediately terminates the request with `HTTP 400 Bad Request`.

---

## 2. Resource Bounding & Rate Limiting

1. **Payload Size Caps**:
   - General REST endpoints: Maximum request body capped at **2 MB** (`2,097,152 bytes`) via `RequestSizeLimitMiddleware`.
   - Ingestion batch gateway: Capped at **10 MB** (`10,485,760 bytes`) to support legitimate high-volume telemetry batches while preventing memory exhaustion.
   - Batch event limit: Telemetry submissions are strictly capped at **500 events per request**.
2. **Query Bounds & Pagination**:
   - Audit logs, alerts, and events enforce maximum `limit` ceilings (e.g. max 100 or 200 items per page) to prevent excessive database I/O.
3. **Authentication Rate Limiting**:
   - Sliding-window counter limits failed login attempts to **5 attempts per 15 minutes** per IP/username, returning `HTTP 429 Too Many Requests`.

---

## 3. Response Sanitization & Error Handling

- **Error Masking**: Database error details, internal exception tracebacks, and database connection strings are never returned to clients.
- **Sensitive Field Omission**: Password hashes, internal API tokens, and session secrets are explicitly excluded from Pydantic response models.

