# Severity Classification Model

## 1. Five-Tier Severity Framework

SnareSight evaluates the operational significance of observed decoy interactions across five distinct categorical tiers:

| Level | Score Range | Operational Meaning |
| :--- | :--- | :--- |
| **INFO** | `0 – 19` | Informational observation retained for baseline telemetry, environment monitoring, or routine connectivity checks. Does not independently indicate a threat. |
| **LOW** | `20 – 39` | Limited suspicious interaction or low-impact probing that warrants recording and standard monitoring (e.g., automated scanner requesting a static asset). |
| **MEDIUM** | `40 – 59` | Meaningful suspicious activity indicating reconnaissance, deliberate exploration, or repeated probing (e.g., repeated authentication attempts within a decoy session). |
| **HIGH** | `60 – 79` | Significant observed behavior involving deep interaction sequences, multiple correlated suspicious techniques, or high-impact actions (e.g., exploitation attempts, command execution). |
| **CRITICAL** | `80 – 100` | Exceptionally significant activity assessment governed by explicit policy authorization. Requires multi-criteria justification or explicit rule designation. |

## 2. Invariants & Governance

1. **Strict Independence from Confidence**:
   - Severity measures **impact and behavioral significance** within the deception environment.
   - Confidence measures **evidence strength and reliability**.
   - A HIGH severity finding can have LOW confidence (e.g., single uncorroborated exploitation string).
   - A LOW severity finding can have VERY HIGH confidence (e.g., verified routine GET request).
   - Under no circumstances is severity derived from or merged with confidence.
2. **Anti-Inflation Policy for CRITICAL**:
   - An event cannot be escalated to `CRITICAL` merely because:
     - An interaction count is elevated.
     - A source IP repeats across days.
     - An ordinary failed login attempt occurred.
     - A user entered a common penetration-testing payload into an unauthenticated decoy.
   - Automated escalation to CRITICAL is disabled by default (`allow_critical_auto_escalation = False`). Unless a rule was explicitly authored as CRITICAL by an authorized security architect, severity is capped at HIGH (75/100).

