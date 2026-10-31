# Authentication Detection Specification (`AUTH-001`)

## 1. Objective and Threat Context
The `AUTH-001` scenario identifies repeated credential guessing or automated authentication probing observed against the SnareSight web-login honeypot (`WEB-001`).

Repeated failed authentication attempts against a decoy service provide high-confidence early warning indicators of external scanning or reconnaissance activity directed at enterprise login portals.

---

## 2. Telemetry and Field Requirements
- `event_id`: Normalized unique event identifier.
- `session_id`: Strict session boundary tracking interaction state.
- `decoy_id`: Target honeypot (`WEB-001`).
- `event_category`: Must equal `authentication`.
- `outcome`: Must equal `FAILURE`.
- `observed_at`: Interaction observation timestamp.

---

## 3. Detection and Evaluation Logic
1. Event Ingestion: An incoming authentication attempt is validated, normalized, and persisted.
2. Session Aggregation: `SessionEvaluator.get_session_events()` queries chronological events for the session.
3. Temporal Windowing: Events are filtered to a sliding window of 300 seconds relative to the current observation.
4. Deduplication: Duplicate events sharing the same event ID or deduplication reference are evaluated once only.
5. Threshold Comparison: If the count of distinct failures within the session window $\ge 3$, rule triggers `MATCHED`.
6. Evidence Linking: All qualifying failure event IDs are linked in `alert_evidence`.

---

## 4. Assessment and Triage Guidance
- **Severity Assessment:** Default `MEDIUM`. Context-dependent; multiple failures over brief intervals elevate priority.
- **Confidence Scoring:** Calculated via P17 `ConfidenceScorer` based on session consistency and timestamp fidelity.
- **Triage Recommendation:** Review the full session timeline, examine source IP geodiversity, and check for corresponding path enumeration or simulated acceptance events.
- **Safety Invariant:** Decoy failures reflect attacker behavior on an isolated honeypot; they do not represent exposure of production credentials.

