# Ingestion Test Plan

**Document ID:** TEST-ING-PLAN-001  
**Classification:** Quality Assurance & Security Verification Plan  
**Scope:** SnareSight Phase 3 — Event Pipeline & Database (P13)  
**Status:** IMPLEMENTED  

---

## 1. Scope & Test Objectives

The Ingestion Test Suite validates that the SnareSight Event Ingestion Engine correctly receives, validates, sanitizes, normalizes, deduplicates, and persists telemetry across all supported modalities.

### Core Test Categories:
1. **Happy Path Ingestion:** Acceptance and normalization of valid synthetic and live honeypot telemetry.
2. **Schema & Field Validation:** Strict rejection of malformed JSON, missing fields, invalid UUIDs, bad provenance, and clock skew.
3. **Sensitive Data Protection:** Zero Password Persistence Invariant testing using synthetic credential payloads and canary strings.
4. **Idempotency & Deduplication:** Verification that duplicate events do not create redundant database rows.
5. **Security & Boundary Controls:** File path traversal protection, API authentication, and isolation confirmation (no honeypot-to-DB links).
6. **Persistence & Relational Integrity:** Transaction rollback, atomic foreign key linkage, and live metrics verification.

---

## 2. Test Case Traceability Matrix

| Test ID | Method Name | Description | Target Invariant |
| :--- | :--- | :--- | :--- |
| **ING-001** | `test_ing_001_valid_raw_event_accepted` | Valid raw event accepted by processor | Schema Conformance |
| **ING-002** | `test_ing_002_valid_event_normalized` | Event normalized into canonical fields | Normalization Taxonomy |
| **ING-003** | `test_ing_003_normalized_event_persisted_in_database` | Raw and normalized events persisted transactionally | 2-Table Persistence |
| **ING-004** | `test_ing_004_invalid_json_rejected_by_importer` | Malformed JSON line handled gracefully | Resilient Parsing |
| **ING-005** | `test_ing_005_missing_required_field_rejected` | Event lacking required attributes rejected | Schema Completeness |
| **ING-006** | `test_ing_006_unsupported_schema_version_rejected` | Unsupported schema version rejected | SemVer Control |
| **ING-007** | `test_ing_007_unknown_source_rejected` | Unregistered collector rejected | Source Registry |
| **ING-008** | `test_ing_008_disabled_source_rejected` | Disabled collector source rejected | Sensor Lifecycle |
| **ING-009** | `test_ing_009_unknown_decoy_rejected` | Unknown decoy service rejected | Sensor Lifecycle |
| **ING-010** | `test_ing_010_source_decoy_mismatch_rejected` | Source submitting for unauthorized decoy rejected | Decoy Binding |
| **ING-011** | `test_ing_011_invalid_provenance_rejected` | Unsupported provenance token rejected | Provenance Integrity |
| **ING-012** | `test_ing_012_duplicate_event_identified` | Identical resubmitted event flagged as duplicate | Idempotency |
| **ING-013** | `test_ing_013_idempotent_resubmission_does_not_duplicate_rows` | Re-submission produces zero extra DB rows | Idempotency Persistence |
| **ING-014** | `test_ing_014_distinct_events_with_similar_data_preserved` | Similar events at different times both preserved | Discriminator Accuracy |
| **ING-015** | `test_ing_015_invalid_timestamps_rejected` | Non-ISO timestamp rejected | Temporal Integrity |
| **ING-016** | `test_ing_016_password_sentinel_not_persisted` | Synthetic password sentinel strictly rejected | Zero Password Invariant |
| **ING-017** | `test_ing_017_authentication_secrets_not_persisted` | Payload with `private_key` rejected | Secret Scrubbing |
| **ING-018** | `test_ing_018_sensitive_fields_produce_safe_rejection` | Prohibited field rejection generates safe diagnostics | Information Leakage |
| **ING-019** | `test_ing_019_session_id_associates_multiple_events` | Multi-event session shares common `session_id` | Session Correlation |
| **ING-020** | `test_ing_020_batch_with_partial_failures_processes_valid_events` | 2 valid + 1 corrupt event yields 2 persists, 1 reject | Fault Isolation |
| **ING-021** | `test_ing_021_large_batch_handled_within_limits` | 50 events in single batch processed cleanly | Batch Scalability |
| **ING-022** | `test_ing_022_transaction_rollback_works` | Explicit session rollback leaves database untouched | ACID Reliability |
| **ING-023** | `test_ing_023_jsonl_importer_validates_every_line` | Importer streams and validates each line | Stream Processing |
| **ING-024** | `test_ing_024_file_path_traversal_prevented` | Attempted read from restricted system directory blocked | Path Traversal Defense |
| **ING-025** | `test_ing_025_imported_provenance_preserved` | Provenance classification preserved through ingestion | Provenance Integrity |
| **ING-026** | `test_ing_026_simulation_events_remain_labelled_simulations` | Simulation events cannot be promoted to live | Provenance Integrity |
| **ING-027** | `test_ing_027_api_requires_authorization` | API returns HTTP 401 Unauthorized without API key | Access Control |
| **ING-028** | `test_ing_028_error_responses_do_not_disclose_secrets` | Error responses contain safe explanation | Information Leakage |
| **ING-029** | `test_ing_029_ingestion_metrics_reflect_actual_results` | Live counters accurately match processed outcomes | Operational Observability |
| **ING-030** | `test_ing_030_no_direct_honeypot_to_postgresql_connection` | Confirms honeypot decoy code has zero DB dependencies | Isolation Architecture |

