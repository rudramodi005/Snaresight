# Detection Execution History and Idempotency Specification

## 1. Execution Auditing

Every rule evaluation executed by the `DetectionEngine` logs an audit entry via `ExecutionTracker`:

```json
{
  "execution_id": "8a3e74b1-91a5-48b2-8451-297dc3f40f1a",
  "rule_id": "TEST-RULE-001",
  "rule_version": "1.0",
  "event_id": "000d4455-3108-45b8-bebf-976ab620fe41",
  "execution_time": "2026-10-31T11:48:55.012345+00:00",
  "execution_status": "MATCHED",
  "processing_duration_ms": 0.124,
  "result_reference": "f58178ca-d402-4fc9-bfa7-3e113a3521d8",
  "safe_error_category": null
}
```

## 2. Idempotency Guarantees

1. **Compound Key**:
   Evaluations are tracked using `event_id:rule_id:rule_version`.
2. **Replay Deduplication**:
   If an event is re-processed (e.g. during replay or service restart), the cached result is returned directly and no additional execution entries are created.
3. **Version Sensitivity**:
   If rule version `2.0` is registered, re-evaluation against `2.0` proceeds cleanly while preserving the cached result for `1.0`.

