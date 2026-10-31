# False Positive Handling and Suppression Architecture

## 1. Principles of Alert Suppression
False-positive handling in SnareSight is governed by strict auditability and preservation principles:
1. **Source Preservation:** Suppressing an alert NEVER modifies, hides, or deletes underlying normalized security events. Source records remain in PostgreSQL for compliance and forensic queries.
2. **Explicit Scope:** Suppression rules must define precise boundaries (by `rule_id`, `session_id`, `decoy_id`, or `source_address`). Blanket wildcard IP whitelisting is strictly prohibited.
3. **Audit Trails:** Every suppression event creates a structured audit record containing timestamp, suppressed rule, matched criteria, and operational justification.

---

## 2. Cooldown De-duplication
To prevent alert fatigue from repeated automated scanner loops:
- `AlertService` enforces a default cooldown interval of 300 seconds per `(rule_id, session_id)` tuple.
- Subsequent matches within the cooldown window increment telemetry metrics but do not spam new alert records or SSE notifications.

---

## 3. Suppression Rule Configuration
Analysts and test coordinators can register explicit suppression rules:
```python
alert_service.add_suppression_rule(
    suppression_id="pentesters_20261031",
    session_id="authorized_audit_sess_99",
    reason="Scheduled penetration testing window",
)
```
When an alert evaluation matches an active suppression rule, alert creation is skipped, and a structured record is appended to the suppression audit log.

