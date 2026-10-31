# Detection Result Model Specification

## 1. Structure

Every rule evaluation yields a structured `DetectionResult`:

```json
{
  "detection_result_id": "f58178ca-d402-4fc9-bfa7-3e113a3521d8",
  "rule_id": "TEST-RULE-001",
  "rule_version": "1.0",
  "evaluated_event_id": "000d4455-3108-45b8-bebf-976ab620fe41",
  "related_event_ids": [],
  "session_id": "decoy_sess_3430c5e63810486c99cff33faad6a50d",
  "decoy_id": "WEB-001",
  "evaluation_status": "MATCHED",
  "matched_conditions": [
    {
      "field": "event_type",
      "operator": "EQUALS",
      "expected_value": "LOGIN_ATTEMPT",
      "actual_value": "LOGIN_ATTEMPT",
      "matched": true
    }
  ],
  "detection_explanation": "Rule 'TEST-RULE-001' (v1.0: Login Attempt Event Match Test) MATCHED: Evaluated 1 conditions successfully on event 000d4455-3108-45b8-bebf-976ab620fe41.",
  "evidence_references": [
    {
      "event_id": "000d4455-3108-45b8-bebf-976ab620fe41",
      "raw_event_id": "f2c7e743-12d6-43ef-a9c6-26af45bbb675",
      "observed_at": "2026-10-31T11:48:54.740491+00:00",
      "event_type": "LOGIN_ATTEMPT",
      "action": "SUBMIT_CREDENTIALS",
      "outcome": "FAILURE"
    }
  ],
  "evaluated_at": "2026-10-31T11:48:55.012345+00:00",
  "engine_version": "1.0",
  "provenance": {
    "source_type": "controlled_test",
    "environment": "isolated_lab"
  }
}
```

## 2. Invariants
- **Evidence References**: Contains pointer metadata to persisted database records.
- **Zero Raw Secrets**: Full raw payloads and credentials are never persisted in results.
- **Provenance Preservation**: Preserves the original telemetry provenance environment and source type.

