# SnareSight P24 Pre-Implementation Assessment
## Task P24: Threat Campaign Intelligence and Evidence-Based Investigation Grouping

### 1. Architectural Baseline Inspection (P01–P23)
The SnareSight platform has established a verified detection and correlation architecture:
- **P01–P10:** Foundation, honeypot collection services (Cowrie SSH, Dionaea, Web Honeypots), database schemas, auth, logging.
- **P11–P15:** Ingestion pipeline, event normalization, deduplication, retention policies, and real-time streaming health.
- **P16–P18:** Rule-based detection engine, evidence-based scoring (severity & confidence), and detection scenarios.
- **P19–P20:** Versioned MITRE ATT&CK integration, STIX parser, and evidence-based detection mapping.
- **P21:** Session-based event correlation engine (`activity_sessions`, `activity_session_events`, `session_correlation_history`).
- **P22:** Multi-session behavioral sequence and attack-chain analysis (`behavioral_sequences`, `behavioral_sequence_members`, `behavioral_sequence_relationships`, `sequence_evidence`, `sequence_assessment_history`).
- **P23:** Multi-session source profiling and behavioral intelligence (`source_profiles`, `source_profile_sessions`, `source_profile_features`, `source_profile_history`, `source_profile_recurrences`).

Total baseline regression: **375/375 passing tests**.

### 2. Available Inputs for Campaign Intelligence (P24)
- **`BehavioralSequenceModel` (P22):** Attack-chain sequences grouping multi-session steps across decoys.
- **`SourceProfileModel` (P23):** Persistent source profiles with behavioral baselines, interaction tempos, auth failure frequencies, and traversal probe indicators.
- **`ActivitySessionModel` (P21):** Single-decoy visitor sessions with timestamps and protocol metrics.
- **`AlertModel` (P16–P18):** Detection alerts with confidence and severity ratings.
- **`AttackDetectionMappingModel` (P19–P20):** Evidence-backed MITRE ATT&CK mappings.

### 3. Gap Analysis for Task P24
To group related observed activity into persistent investigation clusters without conflating investigative grouping with proof of real-world human threat actors:
1. **Investigation Cluster Data Model:** Dedicated tables `investigation_clusters`, `cluster_memberships`, `cluster_evidence`, `cluster_relationships`, and `cluster_audit_logs`.
2. **Deterministic Clustering Engine:** Algorithms detecting behavioral overlaps (shared sequences, similar source profiles, decoy affinity, shared ATT&CK technique distributions) while checking for contradicting evidence (disparate tempos, opposing targets).
3. **Relationship Scoring:** Transparent scoring that decouples event severity, detection confidence, profile priority, and behavioral similarity from cluster relationship confidence.
4. **Lifecycle State Machine:** Clear lifecycle (`CANDIDATE`, `UNDER_REVIEW`, `ACTIVE`, `MONITORING`, `CLOSED`, `MERGED`, `SPLIT`) with audit logging.
5. **Non-Destructive Merge and Split:** Consolidation and partitioning mechanisms that preserve historical provenance and evidence.
6. **Unified Investigation Timeline:** Chronological timeline synthesizing sessions, alerts, sequences, source profile activity, ATT&CK mappings, and analyst decisions.
7. **Analyst Investigation Workspace:** Interactive React + TypeScript page "Campaign Investigations".
8. **SSE Live Updates:** Post-commit real-time event broadcasting to active SOC subscribers.

### 4. Implementation Plan
- **Step 1:** Define SQLAlchemy models in `backend/app/db/models/campaign.py`.
- **Step 2:** Register in `backend/app/db/models/__init__.py`, update `test_models.py`, generate Alembic migration.
- **Step 3:** Implement Clustering Engine, Relationship Scoring, Lifecycle, Timeline, and Service in `backend/app/modules/campaign_intelligence/`.
- **Step 4:** Integrate SSE post-commit notifications in `backend/app/streaming/event_publisher.py` and register routes in `backend/app/main.py`.
- **Step 5:** Create React frontend workspace in `frontend/src/features/campaigns/`.
- **Step 6:** Comprehensive test suite in `backend/tests/modules/campaign_intelligence/`.
- **Step 7:** Complete technical documentation in `docs/campaign-intelligence/`.

