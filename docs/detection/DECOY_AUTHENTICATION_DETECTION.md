# Decoy Authentication Detection Specification (`AUTH-002`)

## 1. Objective and Concept
`AUTH-002` identifies simulated successful logins on the honeypot (`WEB-001`). When an adversary or scanning tool submits credentials that match a simulated trap user profile, the honeypot returns a synthetic success response to observe subsequent interactions.

> [!IMPORTANT]
> **Simulated Decoy Acceptance is NOT Production Compromise:**
> Decoy acceptance means the adversary triggered a deliberate deception trap. The SOC dashboard and alert generation systems must clearly articulate that no real corporate data or production infrastructure was breached.

---

## 2. Telemetry and Field Requirements
- `event_id`: Unique normalized event identifier.
- `session_id`: Interaction session token.
- `decoy_id`: Target honeypot (`WEB-001`).
- `event_category`: Must equal `authentication`.
- `outcome`: Must equal `SUCCESS`.
- `provenance`: Collector provenance metadata.

---

## 3. Evaluation and Alerting Workflow
1. Event Verification: The event is checked for valid provenance and authorized decoy status.
2. Single Event Match: Single-event evaluation matches `outcome == 'SUCCESS'`.
3. Threat Assessment:
   - Severity: `HIGH` (default). A simulated login indicates deep adversary engagement with the deception environment.
   - Confidence: High (90-100%), backed by direct honeypot telemetry.
4. Alert Persistence: Stored in `alerts` with recommendations advising session observation rather than emergency host isolation.
5. Live Streaming: Post-commit broadcast over SSE with `event: security_alert`.

