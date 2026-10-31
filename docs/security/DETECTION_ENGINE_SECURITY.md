# Detection Engine Security Architecture

## 1. Threat Mitigation Matrix

| Security Threat | Prevention Mechanism | Verification Test |
| :--- | :--- | :--- |
| **Remote Code Execution via Rules** | Strict prohibition of `eval()`, `exec()`, shell calls, and dynamic imports | TEST DET-031, DET-032, DET-033 |
| **SQL Injection via Operands** | Literals treated as atomic values; no dynamic SQL construction | TEST DET-034 |
| **Credential Harvesting** | Field registry rejects `password`, `token`, `secret` fields | TEST DET-014, DET-035 |
| **Denial of Service via Complex Rules** | Max depth 3, max conditions 20, max collection 50 items | TEST DET-011, DET-012 |
| **Unauthorized Rule Manipulation** | Role-based permission checks (`admin`, `security_engineer`) | TEST DET-036 |
| **Pipeline Blocking via Rule Glitch** | Individual try/except isolation per rule evaluation | TEST DET-020, DET-038 |

