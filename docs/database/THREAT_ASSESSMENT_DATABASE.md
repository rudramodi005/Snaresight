# Threat Assessment Database Integration

## 1. Relational-Document Integration

Threat assessments bridge normalized events and downstream alert management:

1. **`alerts` Table Integration (Phase 4)**:
   - When alerts are generated from matching detection results, the evaluated `severity_level` maps directly to `alerts.severity`.
   - The evaluated `confidence_score` maps directly to `alerts.confidence` (`SmallInteger` check-constrained between 0 and 100).
   - `evidence_strength` maps to `alerts.evidence_strength`.
   - `detection_explanation` and `severity_explanation` populate `alerts.detection_explanation`.

2. **Forensic Linkage via `alert_evidence`**:
   - Supporting events identified during evidence assessment (`supporting_event_ids`) populate the `alert_evidence` junction table, linking normalized security event UUIDs directly to alerts.

