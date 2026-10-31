# Scoring Engine Security Architecture

## 1. Security Invariants

| Security Risk | Mitigation Strategy | Verification Test |
| :--- | :--- | :--- |
| **Score Manipulation / Replay Inflation** | Strict deduplication of evidence event IDs | TEST SCORE-012 |
| **Sensitive Credential Exposure** | Passwords, tokens, and secrets are permanently excluded from assessments and explanations | TEST SCORE-037, SCORE-038 |
| **Arbitrary Code Execution in Formulas** | Scoring calculations use deterministic arithmetic; no dynamic code execution (`eval()`, `exec()`) | TEST SCORE-039 |
| **Silent Overwriting of Historical Assessments**| New versions create audit records; automated scores are never erased by reviews | TEST SCORE-040 |
| **Unchecked Severity Escalation** | CRITICAL requires explicit policy flag (`allow_critical_auto_escalation = False` by default) | TEST SCORE-005 |

