# Detection Database Design and Data Models

## 1. Relational-Document Integration

The detection engine leverages the existing SnareSight relational schema:

1. **`detection_rules` Table**:
   - `id`: UUID primary key.
   - `rule_id`: String(64) unique natural key.
   - `rule_name`: String(128).
   - `rule_version`: String(16) monotonic version string.
   - `description`: Text rationale.
   - `category`: String(64) indexed domain.
   - `enabled`: Boolean active toggle.
   - `severity`: String(16) check-constrained to `('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')`.
   - `configuration`: JSONB document holding condition trees, thresholds, and time windows.

2. **`security_events` Table**:
   - Provides immutable normalized evidence records referenced by `evaluated_event_id` and `evidence_references`.

3. **`alerts` & `alert_evidence` Tables (Phase 4)**:
   - Persists downstream alerts generated from matching detection results.

