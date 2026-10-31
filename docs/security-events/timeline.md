# Chronological Event Timeline

## Purpose
Understanding what happened immediately before and after an observed event is essential for triage. The `get_event_timeline` method constructs a chronological sequence of related events.

---

## 1. Context Resolution Strategy

The service resolves timeline context using a two-tier strategy:

1. **Session Timeline (`SESSION_TIMELINE`):**
   - If the target event belongs to a session containing 2 or more events, all events sharing that exact `session_id` are loaded in chronological order (`observed_at ASC`).
   - Demonstrates the direct progression of attacker interaction within that specific connection.

2. **Temporal Context Timeline (`TEMPORAL_TIMELINE`):**
   - If the event is isolated or lacks multiple session events, the service loads events from the same decoy sensor or same source address within a bounded time window ($[T_{\text{observed}} - \Delta t, T_{\text{observed}} + \Delta t]$, default $\Delta t = 60$ minutes).
   - Clearly labeled as `relationship_context: "TEMPORAL_CONTEXT_ONLY"`.

> **Critical Guardrail:** Temporal proximity is never presented as proof of shared origin or attacker identity.

---

## 2. Timeline Item Schema

```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-10-31T14:15:00.123456Z",
  "event_category": "AUTHENTICATION",
  "event_type": "LOGIN_ATTEMPT",
  "action": "LOGIN",
  "outcome": "FAILURE",
  "sensor_id": "WEB-001",
  "source_address": "198.51.100.22",
  "is_current_event": true,
  "relationship_context": "SAME_SESSION",
  "has_alert": true,
  "alert_severity": "HIGH",
  "alert_title": "Brute Force Authentication"
}
```

