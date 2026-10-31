# Event Evaluation and Condition Matching Specification

## 1. Evaluation Workflow

The `DetectionEngine` evaluates incoming normalized security events against active enabled rules:

1. **Normalization Check**:
   - Accepts either `SecurityEventModel` instances or normalized dictionaries.
2. **Idempotency Gate**:
   - Queries `ExecutionTracker` for key `event_id:rule_id:rule_version`.
   - If present, returns cached `DetectionResult` without re-evaluating.
3. **Execution Isolation**:
   - Evaluation of each rule is executed inside an isolated try/except block.
   - If an unexpected error occurs during condition matching for rule A, rule B is evaluated normally.
4. **Result Generation**:
   - Every evaluation yields a typed `DetectionResult` with status:
     - `MATCHED`: Criteria met.
     - `NO_MATCH`: Criteria not met.
     - `SKIPPED`: Rule is disabled.
     - `INVALID_RULE`: Schema or field validation issue.
     - `EVALUATION_ERROR`: Runtime exception.

