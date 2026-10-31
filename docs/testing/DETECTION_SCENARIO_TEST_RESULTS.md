# Detection Scenario Test Results (Task P18)

## 1. Execution Summary
- **Test File:** `backend/tests/test_scenarios.py`
- **Total Tests Executed:** 44
- **Passed:** 44
- **Failed:** 0
- **Errors:** 0
- **Execution Time:** ~0.52 seconds
- **Full Backend Suite Status:** 233 / 233 tests passing across all modules

---

## 2. Detailed Results by Group

| Group | Target Rule(s) | Tests Run | Result | Key Invariant Verified |
|---|---|---|---|---|
| **Authentication** | `AUTH-001`, `AUTH-002` | 7 | **PASS (7/7)** | Single failure no false positive; windowing & session separation enforced; simulated access clearly labeled. |
| **Username Enumeration** | `AUTH-003` | 4 | **PASS (4/4)** | One-way SHA-256 fingerprints counted; zero plaintext username exposure. |
| **Web Path Enumeration** | `WEB-001` | 4 | **PASS (4/4)** | Path canonicalization avoids double counting; low severity prevents alert fatigue. |
| **Directory Traversal** | `WEB-002` | 5 | **PASS (5/5)** | Passive indicator recognition; filesystem APIs and process execution verified untouched. |
| **Command Discovery** | `CMD-001` | 3 | **PASS (3/3)** | Explicitly deferred for HTTP decoy; verified shell commands are never executed. |
| **File Transfer** | `FILE-001` | 4 | **PASS (4/4)** | Explicitly deferred for HTTP decoy; verified uploaded binaries are never executed or persisted in raw form. |
| **Behavioral Correlation** | `BEHAV-001`, `WEB-003` | 5 | **PASS (5/5)** | Multi-category sessions identified; suppression rules audited without deleting underlying events. |
| **Scoring Integration** | P17 Assessment | 5 | **PASS (5/5)** | Severity and confidence computed independently; provenance clearly labeled. |
| **Alert & SSE Streaming** | `AlertModel`, SSE | 7 | **PASS (7/7)** | Idempotency and cooldown enforced; post-commit broadcast; streaming faults never roll back database records. |

