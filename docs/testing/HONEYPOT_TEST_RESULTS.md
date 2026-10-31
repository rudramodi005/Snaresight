# SnareSight — Honeypot Test Results

**Document ID:** `SNARESIGHT-TEST-RESULTS-001`  
**Execution Date:** 2026-10-31  
**Target:** `WEB-001` Honeypot Service (`honeypot-lab/web-decoy`)  
**Executor:** Automated Test Runner (`unittest`)  
**Overall Verdict:** **PASS (100% — 39 of 39 Tests Passing)**

---

## 1. Executive Summary

The complete automated test suite for the `WEB-001` web-login decoy was executed in an isolated loopback test environment using Python 3.14.6 and Starlette ASGI `TestClient`.

A total of **39 tests** across 5 test modules were evaluated. All 39 tests passed successfully with zero errors, zero failures, and zero skipped tests. The system fully complies with the Zero Password Persistence Invariant, isolation boundaries, and structured event schema contracts.

---

## 2. Test Execution Breakdown

| Test Suite Module | Test Scope | Tests Run | Passed | Failed | Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `tests/test_login.py` | Portal rendering, forms, payload boundaries | 5 | 5 | 0 | **PASS** |
| `tests/test_security.py` | Injection safety, route restrictions, loopback binding | 8 | 8 | 0 | **PASS** |
| `tests/test_sessions.py` | HMAC fingerprinting, unguessable session IDs | 2 | 2 | 0 | **PASS** |
| `tests/test_events.py` | Zero password persistence, schema compliance, write recovery | 5 | 5 | 0 | **PASS** |
| `tests/test_validation_suite.py` | INPUT-001 to INPUT-017, thread concurrency, log rotation | 19 | 19 | 0 | **PASS** |
| **Total** | **Comprehensive Honeypot Validation** | **39** | **39** | **0** | **PASS** |

---

## 3. Detailed Results by Test Identifier

| Test Identifier | Test Description | Expected Behavior | Actual Behavior | Result |
| :--- | :--- | :--- | :--- | :---: |
| `TEST-01` | GET `/login` renders HTML | HTTP 200, form elements present | HTTP 200, HTML valid | **PASS** |
| `TEST-02` | Empty form submission | HTTP 401 simulated rejection | HTTP 401, error banner | **PASS** |
| `TEST-03` | Valid synthetic credentials | HTTP 401 realistic simulated error | HTTP 401, simulated auth failure | **PASS** |
| `TEST-04` | Sensitive canary password check | Canary string absent from JSONL | Canary string zero matches | **PASS** |
| `TEST-05` | Canary absent from responses | Canary string absent from HTML/errors | Canary string zero matches | **PASS** |
| `TEST-06` | Keyed HMAC-SHA256 fingerprinting | Deterministic & irreversible hash | Exact 64-char hex match | **PASS** |
| `TEST-07` | Session ID generation | Unique `decoy_sess_<uuid>` strings | 50/50 unique IDs | **PASS** |
| `TEST-08` | Event schema validation | All mandatory fields populated | Conforms to `DecoyEvent` | **PASS** |
| `TEST-09` | Timestamp UTC format | Strict ISO-8601 with `+00:00` or `Z` | Valid UTC timestamps | **PASS** |
| `TEST-10` | Suspicious path probe (`/admin.php`) | Generic HTTP 404 without banner | HTTP 404 generic | **PASS** |
| `TEST-11` | Oversized credentials (>128 chars) | HTTP 400 Bad Request | HTTP 400 Bad Request | **PASS** |
| `TEST-12` | XSS `<script>` inertness | HTML-escaped in output | Escaped, inert text | **PASS** |
| `TEST-13` | Command injection strings | Treated as inert plain text | No subprocess execution | **PASS** |
| `TEST-14` | File upload probe | Zero upload routes exist | Confirmed 0 upload routes | **PASS** |
| `TEST-15` | Shell execution audit | Zero `subprocess`/`os.system` | Confirmed 0 shell primitives | **PASS** |
| `TEST-16` | Storage write error recovery | Graceful logging, no crash | App continues operating | **PASS** |
| `TEST-17` | Health endpoint `/health` | HTTP 200, zero secret leakage | Operational status returned | **PASS** |
| `TEST-18` | Offline loopback binding | Binds to `127.0.0.1` | Loopback binding verified | **PASS** |
| `TEST-19` | Wildcard binding rejection | Refuses `0.0.0.0` or `::` | Startup raises ValueError | **PASS** |
| `TEST-20` | Database independence | No PostgreSQL ORM imports | Confirmed 0 DB dependencies | **PASS** |
| `INPUT-001` | Empty username field | HTTP 401 simulated rejection | HTTP 401 returned | **PASS** |
| `INPUT-002` | Empty password field | HTTP 401 simulated rejection | HTTP 401 returned | **PASS** |
| `INPUT-003` | Oversized username | HTTP 400 Bad Request | HTTP 400 returned | **PASS** |
| `INPUT-004` | Oversized password | HTTP 400 Bad Request | HTTP 400 returned | **PASS** |
| `INPUT-005` | Multibyte UTF-8 / Emoji | Handled cleanly, HTTP 401 | HTTP 401 returned | **PASS** |
| `INPUT-006` | Non-form Content-Type (`text/plain`) | HTTP 400/422 rejection | HTTP 400 returned | **PASS** |
| `INPUT-007` | Broken multipart boundary | HTTP 400/422 rejection | HTTP 400 returned | **PASS** |
| `INPUT-008` | Unexpected JSON payload | HTTP 400/422 rejection | HTTP 400 returned | **PASS** |
| `INPUT-009` | HTML-like input strings | Rendered inert | Inert text | **PASS** |
| `INPUT-010` | Script-like input strings | Rendered inert | Inert text | **PASS** |
| `INPUT-011` | Unix shell chaining syntax | Rendered inert | Inert text | **PASS** |
| `INPUT-012` | Directory traversal strings | Rendered inert | Inert text | **PASS** |
| `INPUT-013` | Repeated sequential requests | Session ID preserved across 10 calls | Session maintained | **PASS** |
| `INPUT-014` | Missing session cookie | Auto-allocates fresh session ID | New cookie set | **PASS** |
| `INPUT-015` | Unsupported HTTP methods (PUT/DEL) | HTTP 405 Method Not Allowed | HTTP 405 returned | **PASS** |
| `INPUT-016` | Corrupted session cookie | Discards & generates fresh session | Clean replacement | **PASS** |
| `INPUT-017` | Oversized / hostile headers | Graceful processing | HTTP 401 returned safely | **PASS** |
| `CONCURRENCY` | 10 simultaneous threads | No data race or log corruption | 10/10 threads completed | **PASS** |
| `ROTATION` | Max size trigger | Atomic rotation to `.1` backup | `.1` created atomically | **PASS** |

---

## 4. Test Duration & Performance

- **Total Execution Time:** 0.254 seconds
- **Average Per-Test Latency:** 6.5 milliseconds
- **Concurrency Throughput:** 10 parallel threads dispatched and joined in < 50ms without race conditions.

