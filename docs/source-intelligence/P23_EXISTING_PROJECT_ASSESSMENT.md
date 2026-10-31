# SnareSight P23 Pre-Implementation Assessment
## Task P23: Multi-Session Source Profiling and Behavioral Intelligence

### 1. Architectural Baseline Inspection (P01–P22)
Prior tasks have established a robust deception and detection architecture:
- **P01–P10:** Foundation, honeypot collection services (Cowrie SSH, Dionaea, Web Honeypots), database schemas, auth, logging.
- **P11–P15:** Ingestion pipeline, event normalization, deduplication, retention policies, and real-time streaming health.
- **P16–P18:** Rule-based detection engine, evidence-based scoring (severity & confidence), and detection scenarios.
- **P19–P20:** Versioned MITRE ATT&CK integration, STIX parser, and evidence-based detection mapping.
- **P21:** Session-based event correlation engine (`activity_sessions`, `activity_session_events`, `session_correlation_history`).
- **P22:** Multi-session behavioral sequence and attack-chain analysis (`behavioral_sequences`, `behavioral_sequence_members`, `behavioral_sequence_relationships`, `sequence_evidence`, `sequence_assessment_history`).

Total regression suite: **340 tests passing cleanly**.

### 2. Analysis of Existing Source Data Structures
- In `app.db.models.intelligence`, the table `observed_sources` (`ObservedSourceModel`) tracks high-level source occurrences (`source_id`, `source_address`, `source_identity_type`, `first_observed_at`, `last_observed_at`, `observation_count`).
- In `app.db.models.correlation`, `ActivitySessionModel` tracks single-decoy sessions linked by `source_ip_address` or `source_identifier`.
- In `app.db.models.sequence`, `BehavioralSequenceModel` correlates multiple sessions into attack-chain progressions.

### 3. Gap Analysis for Task P23
To achieve multi-session behavioral intelligence and persistent source profiling without conflating network observables with physical human identities:
1. **Dedicated Source Profiling Models:** Need dedicated tables `source_profiles`, `source_profile_sessions`, `source_profile_features`, `source_profile_history`, and `source_profile_recurrences`.
2. **Behavioral Feature Extraction:** Need statistical and qualitative feature extractors (tempo, burstiness, auth spray ratios, reconnaissance breadth, tactic footprints, command payloads).
3. **Multi-Window Aggregation:** Need an idempotent aggregation engine calculating metrics over standard time windows (1h, 24h, 7d, 30d, all-time).
4. **Explainable Similarity Engine:** Compute similarity across source profiles using normalized behavioral metric distances and Jaccard overlap of tactics/honeypot targets, with human-readable rationale.
5. **Recurrence & Dormancy Detection:** Identify sources reactivating after quiet intervals and evaluate pattern persistence.
6. **Strict Guardrails:** Enforce "Observed Source Profile" / "Source Context Profile" terminology, zero-password persistence, and no external unauthorized geolocation/deanonymization.

### 4. Implementation Plan
- **Step 1:** Create `SourceProfileModel` and relational models in `backend/app/db/models/source_profile.py`.
- **Step 2:** Register in `backend/app/db/models/__init__.py` and update `test_models.py`.
- **Step 3:** Implement the Source Intelligence subsystem in `backend/app/modules/source_intelligence/`.
- **Step 4:** Integrate API routes into FastAPI (`backend/app/main.py`).
- **Step 5:** Build React frontend interfaces in `frontend/src/features/source-intelligence/`.
- **Step 6:** Comprehensive unit and integration test coverage (`backend/tests/modules/source_intelligence/`).
- **Step 7:** Technical documentation suite in `docs/source-intelligence/`.

