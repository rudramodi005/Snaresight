# Evidence Strength Model

## 1. Evidence Strength Classification

Evidence strength assesses the depth, completeness, and independence of observations supporting a threat finding:

| Strength | Criteria | Operational Guidance |
| :--- | :--- | :--- |
| **INSUFFICIENT** | Missing required fields, validation failure, corrupted timestamps, or fatal schema errors. | Suppress automated alerting; route to ingestion diagnostic log. |
| **LIMITED** | Single valid event with no session corroboration or unverified collector source. | Log as candidate observation; await session progression. |
| **MODERATE** | Valid event within verified session context and registered collector, or multiple interactions. | Sufficient for standard SOC queue triage and correlation. |
| **STRONG** | 3+ deduplicated interactions within a verified session, consistent timestamps, and zero contradictions. | High-priority evidence foundation for attack-chain assembly. |

## 2. Deduplication & Anti-Inflation Rules

1. **Duplicate Elimination**:
   - Re-submitting the exact same event or duplicate telemetry records does **not** increment the unique evidence count.
   - Five identical login attempt events are treated as **1 unique evidence record**, preventing replay-based confidence inflation.
2. **Session Scoping**:
   - Unrelated interactions from the same source IP occurring across distinct sessions cannot be merged to claim strong evidence.

