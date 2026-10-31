# SnareSight — Database Relationships & Integrity Rules

**Document ID:** `SNARESIGHT-DB-REL-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Principal Database Architect & Security Auditor  

---

## 1. Referential Integrity & Deletion Invariant

In cybersecurity event persistence, forensic auditability requires that **security evidence must never be silently or accidentally deleted via cascading foreign keys**:

> **INVARIANT:** Under no circumstances shall retiring a honeypot, modifying a detection rule, or purging an analyst case cascade-delete raw events or normalized security telemetry.

| Relationship Edge | Foreign Key Reference | On Delete Policy | Forensic & Operational Rationale |
| :--- | :--- | :--- | :--- |
| `raw_events` -> `honeypots` | `decoy_id` | **`RESTRICT`** | Deleting a honeypot definition is prohibited while historical raw events reference it. |
| `security_events` -> `raw_events` | `raw_event_id` | **`RESTRICT`** | Normalized events must permanently retain their originating raw observation line. |
| `security_events` -> `honeypots` | `decoy_id` | **`RESTRICT`** | Preserves historical decoy attribution even after decoy decommissioning. |
| `alerts` -> `detection_rules` | `detection_rule_id` | **`RESTRICT`** | Alerts must retain the exact rule definition that generated them. |
| `alerts` -> `honeypots` | `decoy_id` | **`RESTRICT`** | Preserves target honeypot attribution across the alert lifecycle. |
| `alert_evidence` -> `alerts` | `alert_id` | **`CASCADE`** | Deleting a discarded test alert removes the junction record. |
| `alert_evidence` -> `security_events` | `event_id` | **`RESTRICT`** | Deleting an underlying security event while linked to an alert is prohibited. |
| `technique_mappings` -> `attack_techniques` | `technique_id` | **`RESTRICT`** | ATT&CK technique catalog cannot be dropped while mappings exist. |

---

## 2. Entity Multiplicity & Cardinality Matrix

```
honeypots (1) --------< (N) raw_events
raw_events (1) ------- (1) security_events
sessions (1) ---------< (N) security_events
detection_rules (1) --< (N) alerts
alerts (N) -----------< (M) [alert_evidence] >----------- (N) security_events
security_events (1) --< (N) [technique_mappings] >------- (1) attack_techniques
```

### Cardinality Specifications:
1. **Raw Event to Normalized Event (1:1):** Every valid `raw_event` record produces exactly one `security_event`.
2. **Session to Security Events (1:N):** A client interaction session groups multiple chronological requests.
3. **Detection Rule to Alerts (1:N):** A single behavioral rule triggers multiple discrete alerts over time.
4. **Alerts to Supporting Events (N:M):** Implemented via the `alert_evidence` junction table. Multiple events can justify one alert; a single high-fidelity event can appear in multiple correlated alerts.
5. **Security Events / Alerts to ATT&CK (N:1):** Evidence-backed mappings connect specific observations or findings to MITRE ATT&CK techniques.

