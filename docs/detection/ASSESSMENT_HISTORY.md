# Threat Assessment History and Audit Trails

## 1. Audit Invariants

Threat assessments are preserved with complete historical provenance in `AssessmentHistoryRecord`:

```json
{
  "history_id": "3e9b1190-6712-4418-9774-706f5223ab40",
  "assessment_id": "f58178ca-d402-4fc9-bfa7-3e113a3521d8",
  "assessment_version": 2,
  "previous_severity": "LOW",
  "updated_severity": "MEDIUM",
  "previous_confidence": 100,
  "updated_confidence": 85,
  "reason": "Analyst review by analyst_charlie: Elevated severity based on verified reconnaissance sequence",
  "initiator": "analyst_charlie",
  "timestamp": "2026-10-31T12:00:00.000000+00:00"
}
```

## 2. Immutability
- Initial automated assessments are never overwritten.
- Reassessments and manual reviews increment the `assessment_version` and append a traceable history entry.
- Historical queries can reconstruct the timeline of scoring adjustments from inception to final triage.

