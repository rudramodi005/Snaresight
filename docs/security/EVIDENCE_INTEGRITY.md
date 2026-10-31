# Evidence Integrity and Provenance Preservation

## 1. Provenance Preservation

SnareSight tracks four distinct provenance classifications:
- `LIVE_HONEYPOT`: Production deception telemetry from deployed sensors.
- `CONTROLLED_TEST`: Synthetic verification events from test harnesses.
- `SYNTHETIC_SIMULATION`: Educational or simulation scenarios.
- `IMPORTED_DATA`: Retrospective audit logs or external captures.

### Invariant:
Simulated or test events are never classified as genuine external attacks. Provenance is preserved verbatim in every `ThreatAssessmentResult`.

## 2. Evidence Pointer Integrity

Assessments maintain strict foreign key references (`detection_result_id`, `supporting_event_ids`, `supporting_evidence_ids`) without copying raw event payloads, guaranteeing tamper-evident traceability while preserving storage efficiency.

