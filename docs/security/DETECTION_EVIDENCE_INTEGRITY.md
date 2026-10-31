# Detection Evidence Integrity and Provenance Preservation

## 1. Forensic Evidence Integrity

To serve as credible evidence during security operations and investigations:

1. **Foreign Key Binding**:
   - `evaluated_event_id` and `evidence_references` reference persisted records in `SecurityEventModel`.
2. **Provenance Preservation**:
   - The original telemetry environment (`isolated_lab`), source type (`controlled_test`), and timestamp fidelity are copied verbatim into the `DetectionResult`.
3. **Tamper-Evident Explanations**:
   - Condition matches record both the expected value and the actual observed value at evaluation time, ensuring deterministic reconstruction during audits.

