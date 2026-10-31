# Investigation Cluster Unified Timeline

## Purpose
The `InvestigationTimelineBuilder` (`backend/app/modules/campaign_intelligence/timeline.py`) generates a comprehensive, chronological investigation narrative for any given cluster.

Rather than forcing an analyst to navigate between separate session timelines, alert logs, and source profile events, the investigation timeline merges all correlated telemetry into a single, unified, microsecond-accurate stream.

---

## 1. Timeline Entry Aggregation

The builder pulls timeline elements across member entities and normalizes them into a consistent structure:

| Item Type | Source Entity | Timeline Presentation |
|:---|:---|:---|
| `SESSION_START` | `ActivitySessionModel` | Session initialization, source IP, honeypot service, port |
| `SESSION_END` | `ActivitySessionModel` | Session closure, duration, termination reason |
| `SECURITY_EVENT` | `HoneypotEventModel` | Command execution, HTTP request, authentication attempt |
| `ALERT_TRIGGERED` | `SecurityAlertModel` | Rule match, rule ID, title, severity, confidence |
| `SEQUENCE_STEP` | `BehavioralSequenceMemberModel` | Progression step in multi-session attack chain |
| `ANALYST_ACTION` | `ClusterAuditLogModel` | Status update, notes added, merge/split event |

---

## 2. Unified Timeline Entry Schema

```json
{
  "timestamp": "2026-10-31T14:20:00.123456Z",
  "event_type": "ALERT_TRIGGERED",
  "title": "Suspicious Reconnaissance Command Execution",
  "summary": "Rule R-002 triggered: uname -a and id commands observed in honeypot terminal",
  "severity": "HIGH",
  "entity_type": "ALERT",
  "entity_id": "ALRT-0098",
  "source_ip": "198.51.100.25",
  "honeypot_id": "hp-ssh-prod-01",
  "details": {
    "rule_id": "R-002",
    "commands": ["uname -a", "id"],
    "mitre_technique": "T1082"
  }
}
```

---

## 3. Strict Chronological Ordering
Entries are ordered by:
1. `timestamp` ASC (with sub-millisecond precision).
2. For identical timestamps, ordered by causal precedence:
   - `SESSION_START` precedes `SECURITY_EVENT`
   - `SECURITY_EVENT` precedes `ALERT_TRIGGERED`
   - `ALERT_TRIGGERED` precedes `SESSION_END`
   - `SESSION_END` precedes `ANALYST_ACTION`

This prevents causal inversion in the analyst UI.

