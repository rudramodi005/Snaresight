# SnareSight Sequence Evidence and Explainability Model

> **OPERATIONAL CAUTION & SCOPE BOUNDARY**  
> Every relationship in a behavioral sequence must have an explicit, inspectable evidential justification.  
> Vague, unexplainable assertions (e.g. "AI detected an attack") are strictly forbidden.  
> Analysts must always have direct access to underlying honeypot telemetry and detection records.

---

## 1. Principles of Explainable Correlation

SnareSight enforces three core explainability requirements:
1. **Verifiable Provenance:** Every relationship edge points to underlying immutable records (`ActivitySessionModel`, `SecurityEventModel`, `AlertModel`, `AttackDetectionMappingModel`).
2. **Transparent Diagnostic Rationale:** Machine-generated natural language summaries detail the exact signals triggering the link.
3. **Explicit Evidential Limits:** Disclaimers and factor breakdowns make clear where evidence is circumstantial (e.g. shared IP) versus authoritative (e.g. explicit session token).

---

## 2. Relationship Explanations by Type

| Relationship Type | Example Diagnostic Rationale | Supporting Evidence Stored |
| :--- | :--- | :--- |
| `OBSERVED_BEFORE` | "Session act-sess-001 on WEB-001 preceded Session act-sess-002 by 2.1 hours." | `first_observed_at`, `last_activity_at` |
| `SHARED_SOURCE_CONTEXT` | "Shared observed source address 198.51.100.30 across sessions within 24h window." | `source_address`, `decoy_id`, `target_service` |
| `BEHAVIORALLY_SIMILAR` | "Consecutive sessions exhibited identical HTTP user-agent and targeted traversal patterns." | `event_category`, `action`, `sanitized_metadata` |
| `RELATED_DETECTION_PATTERN` | "Detection WEB-001 (Traversal) followed by WEB-002 (Exploit Probe) in successive sessions." | `alert_id`, `detection_rule_id`, `severity` |
| `ANALYST_LINKED` | "Analyst manually linked Session act-sess-005 based on external firewall corroboration." | `analyst_id`, `review_notes`, `timestamp` |

---

## 3. Ground Truth Preservation

- **Zero Forensic Rewriting:** Correlating an event into a sequence NEVER updates or rewrites the original `security_events.evidence_hash` or `raw_events.sanitized_payload`.
- **Inspection in SOC UI:** The Sequence Investigation Workspace allows one-click inspection of raw JSON metadata for every member and relationship in the graph.

