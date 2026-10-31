# Evidence Preservation Specification

**Document ID:** DB-PRESERV-001  
**Classification:** Forensics & Legal Hold Specification  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P14)  
**Status:** IMPLEMENTED  

---

## 1. Objectives & Principles

In incident response and threat investigations, telemetry associated with suspicious activity must be preserved regardless of standard retention deadlines.

SnareSight implements a two-tier evidence preservation mechanism:
1. **Relational Alert Evidence Protection:** Normalized events linked to security alerts via the [`AlertEvidenceModel`](file:///c:/Projects/SnareSight/backend/app/db/models/alert.py#L58) junction table are automatically protected by both database foreign key constraints (`ON DELETE RESTRICT`) and retention query filters.
2. **Explicit Investigation Preservation Holds:** Managed by [`EvidencePreservationService`](file:///c:/Projects/SnareSight/backend/app/retention/preservation.py).

---

## 2. Preservation Hold Data Contract

```python
@dataclass
class PreservationHold:
    hold_id: str                  # UUIDv4
    investigation_id: str         # Case or investigation identifier
    target_id: str                # Target event_id, raw_event_id, or alert_id
    target_type: str              # "SECURITY_EVENT", "RAW_EVENT", "ALERT"
    reason: str                   # Justification for hold
    authorized_analyst: str       # Analyst placing hold
    started_at: datetime          # UTC timestamp
    released_at: datetime | None  # UTC timestamp when released
    is_active: bool               # Active status flag
```

---

## 3. Override Behavior

- An active preservation hold **unconditionally overrides** category retention expiry (`TEST RET-007`).
- When a retention cleanup job evaluates candidate records, all targets with active holds are counted under `preserved_count` and skipped from deletion.
- Releasing a hold requires explicit analyst identity and timestamps the release. Only after hold release does the record become eligible for future retention cleanup.

