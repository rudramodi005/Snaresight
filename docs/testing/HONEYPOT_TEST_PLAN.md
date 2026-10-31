# SnareSight — Honeypot Test Plan

**Document ID:** `SNARESIGHT-TEST-PLAN-001`  
**Phase:** 2 — Lab Isolation and Honeypot  
**Target Component:** `WEB-001` (FastAPI Web-Login Decoy)  
**Classification:** Confidential — Internal Cybersecurity Engineering  

---

## 1. Objectives & Scope

This test plan defines the formal test strategy for verifying and auditing the SnareSight `WEB-001` web-login honeypot component. The objectives are:
1. Validate that the simulated corporate portal interface renders cleanly without external dependencies.
2. Confirm interactions generate valid, strictly typed, structured security events.
3. Verify that the session tracking engine assigns unguessable identifiers and correctly correlates multi-step interactions.
4. Enforce the **Zero Password Persistence Invariant**: confirm that no submitted plaintext password, hash, or auth token is ever logged, echoed, or stored.
5. Verify robust input validation, boundary handling, and that malicious injection payloads remain completely inert.
6. Verify file system logging reliability, graceful failure handling, and log rotation bounds.
7. Confirm loopback-only network isolation in accordance with the Task P08 audit verdict (`CONDITIONALLY READY / BLOCKED FOR DECOY ACTIVATION`).

---

## 2. Test Environment Baseline

| Parameter | Specification |
| :--- | :--- |
| **Operating System** | Windows 11 Home Single Language (Build 26100, x64) |
| **Python Runtime** | Python 3.14.6 (64-bit) |
| **Frameworks** | FastAPI 0.139.2, Pydantic 2.13.4, Starlette 0.46.1 |
| **Template Engine** | Jinja2 3.1.6 |
| **Test Transport** | HTTPX 0.28.1 via Starlette `TestClient` (In-memory ASGI) |
| **Binding Policy** | Loopback only (`127.0.0.1:8080`) — No external network listeners |
| **Isolation Status** | Host containment verified; Guest lab activation gated (P08) |

---

## 3. Test Suites & Identifiers

### 3.1 Functional & Route Validation
- **TEST-01**: Simulated portal page loads with HTTP 200 and corporate branding.
- **TEST-02**: Empty credential submission returns simulated HTTP 401 rejection.
- **TEST-03**: Synthetic login attempt returns realistic simulated HTTP 401 rejection.
- **TEST-10**: Suspicious route probing returns generic HTTP 404 without banner leakage.
- **TEST-11**: Oversized payload boundary enforcement (HTTP 400 rejection).

### 3.2 Security & Isolation Controls
- **TEST-04**: Sensitive canary password exclusion from JSONL persistent logs.
- **TEST-05**: Canary password exclusion from HTML responses, headers, and errors.
- **TEST-12**: Cross-Site Scripting (XSS) input escaping and inert rendering.
- **TEST-13**: OS command injection sequences remain inert strings (no execution).
- **TEST-14**: Confirms zero file upload endpoints exist.
- **TEST-15**: Confirms absence of `subprocess`, `os.system`, or dynamic execution primitives.
- **TEST-17**: Health endpoint (`/health`) sanity and zero key/credential disclosure.
- **TEST-18**: Offline development mode binds strictly to `127.0.0.1`.
- **TEST-19**: Unsafe wildcard network binding (`0.0.0.0`, `::`) is rejected at startup.
- **TEST-20**: Confirms zero database ORM or direct DB drivers are imported in the decoy.

### 3.3 Privacy & Session Management
- **TEST-06**: Deterministic and irreversible keyed HMAC-SHA256 username fingerprinting.
- **TEST-07**: Session identifier uniqueness and formatting (`decoy_sess_<uuid4>`).

### 3.4 Input Validation Suite (INPUT-001 to INPUT-017)
- **INPUT-001**: Empty username submission.
- **INPUT-002**: Empty password submission.
- **INPUT-003**: Oversized username (> 128 characters).
- **INPUT-004**: Oversized password (> 256 characters).
- **INPUT-005**: Multibyte UTF-8 and emoji handling (`user_🔒_über@corp.local`).
- **INPUT-006**: Invalid content type (`text/plain` rejected with HTTP 400).
- **INPUT-007**: Malformed multipart boundary structure rejected with HTTP 400.
- **INPUT-008**: Unexpected JSON body rejected with HTTP 400.
- **INPUT-009**: HTML tag injection treated as inert text.
- **INPUT-010**: Embedded script tags with event handlers remain inert.
- **INPUT-011**: Unix shell chaining syntax treated as plain text.
- **INPUT-012**: Directory traversal sequences (`../../windows/system32`) remain inert.
- **INPUT-013**: Sequential form submissions within a persistent session.
- **INPUT-014**: Missing session cookie receives auto-generated session identifier.
- **INPUT-015**: Unsupported HTTP methods (PUT, DELETE, PATCH) return HTTP 405.
- **INPUT-016**: Corrupted or malicious session cookie safely discarded and regenerated.
- **INPUT-017**: Malicious HTTP headers (giant buffers, injection markers) handled safely.

### 3.5 Storage, Concurrency & Resilience
- **CONCURRENCY**: 10 simultaneous threads submitting login attempts without data corruption.
- **ROTATION**: Log file exceeding configured size threshold triggers atomic `.1` rotation.
- **TEST-16**: Simulated disk write failure handled gracefully without service crash.

---

## 4. Acceptance Criteria

1. 100% of automated tests pass without skipping or assertion suppression.
2. Zero canary password strings appear anywhere in disk files, logs, or error responses.
3. Every generated telemetry event conforms to the canonical `DecoyEvent` schema.
4. All timestamps are strict UTC ISO-8601 strings.
5. All operations run within the in-memory ASGI or loopback boundary; no lab network interface is activated.

