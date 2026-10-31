# P19 Existing Project Assessment: MITRE ATT&CK Integration

## 1. Overview and Assessment Objective
This assessment reviews the architectural state of the **SnareSight** repository following the completion of Phase 3 (Event Pipeline & Database) and Phase 4 (Tasks P16–P18: Detection Engine, Scoring, and Scenarios).

The objective is to establish an authoritative baseline of existing models, schemas, database tables, and API structures to ensure the MITRE ATT&CK catalogue integration (Task P19) integrates seamlessly without duplicate entities, regressions, or breaking changes.

---

## 2. Existing Components Discovered

### 2.1 Backend Architecture & Tech Stack
- **Framework:** FastAPI 0.115+ (Python 3.14 compatible, strict Pydantic v2 schemas).
- **ORM / Persistence:** SQLAlchemy 2.0 Typed Declarative models with PostgreSQL 16 dialect (and in-memory SQLite for automated unit test isolation).
- **Security & Validation:**
  - `SensitiveDataInspector`: Enforces Zero-Password Persistence.
  - `FieldRegistry`: Enforces field allowlisting on detection evaluation.
  - `ThreatAssessmentService`: Independent severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and confidence (`0-100%`) assessment.
  - `EventPublisher`: Post-commit Server-Sent Events (SSE) notification streaming.
- **Active Tests:** 233 automated unit and integration tests passing in ~2.8 seconds (`tests/test_models.py`, `tests/test_ingestion.py`, `tests/test_normalization_retention.py`, `tests/test_streaming_and_health.py`, `tests/test_detection.py`, `tests/test_scoring.py`, `tests/test_scenarios.py`).

### 2.2 Relevant Existing Database Structures
Inspection of `backend/app/db/models/intelligence.py` revealed the following pre-existing models:
1. `AttackTechniqueModel` (`attack_techniques`):
   - Legacy columns: `id`, `technique_id` (String(16), unique, indexed), `technique_name`, `tactic_id`, `tactic_name`, `framework_version` (default `"v14.1"`), `description`, `created_at`.
2. `TechniqueMappingModel` (`technique_mappings`):
   - Junction table reserved for **Task P20** (linking events and alerts to `attack_techniques.technique_id` with `mapping_confidence` and `mapping_rationale`).
3. `ObservedSourceModel` (`observed_sources`):
   - Threat actor profiling table.
4. `SimulationRunModel` (`simulation_runs`):
   - Test orchestration trace table.

### 2.3 Relevant Existing API Structures
Inspection of `backend/app/api/` revealed:
- `ingestion.py`: Batch telemetry intake (`POST /api/v1/ingestion/events/batch`).
- `stream.py`: Live event and alert streaming (`GET /api/v1/stream/events`).
- `health.py`: Liveness, readiness, and pipeline health probes (`/api/v1/health/*`).
- API prefix: `/api/v1` (configured via `settings.API_PREFIX`).

### 2.4 Frontend Status
Inspection of `frontend/src/` revealed empty scaffold directories containing `.gitkeep` files (`app`, `assets`, `components`, `features`, `hooks`, `layouts`, `services`, `types`, `utils`). Full dashboard implementation is planned for Phase 6. For P19, TypeScript type definitions and API client interfaces will be established in `frontend/src/types` and `frontend/src/services`.

---

## 3. Compatibility Analysis & Design Decisions

### 3.1 Model Evolution vs. Replacement
- `attack_techniques` in `intelligence.py` was a simplified initial stub.
- **Decision:** Rather than creating competing duplicate tables, we will enhance the threat intelligence data model by structuring a dedicated `backend/app/modules/mitre` module containing:
  - `AttackDatasetVersionModel` (`attack_dataset_versions`): Tracks imported ATT&CK versions, STIX bundle checksums, retrieval dates, and active flags.
  - `AttackTacticModel` (`attack_tactics`): Stores official tactics (e.g., `TA0001` - Initial Access).
  - `AttackTechniqueModel` (`attack_techniques`): Preserves compatibility with `TechniqueMappingModel` while adding STIX ID, sub-technique indicators, platforms, data sources, deprecation/revocation status, and version references.
  - `AttackSubtechniqueModel` (`attack_subtechniques`): Stores explicit parent-child sub-technique relationships (e.g., `T1110.001` under `T1110`).
  - `AttackRelationshipModel` (`attack_relationships`): Stores STIX relationships (e.g., `subtechnique-of`, tactic-technique associations).
  - `AttackExternalReferenceModel` (`attack_external_references`): Stores external reference links (MITRE ATT&CK URLs, source citations).
  - `AttackImportRunModel` (`attack_import_runs`): Full audit log of dry-run and committed import operations.

### 3.2 Dataset Selection: Enterprise ATT&CK (STIX 2.1)
- **Domain:** Enterprise ATT&CK.
- **Format:** STIX 2.1 JSON bundle.
- **Official Source:** `https://github.com/mitre-attack/attack-stix-data`.
- **Target Release:** MITRE ATT&CK v14.1 / v15.1 Enterprise STIX 2.1.
- **Rationale:** SnareSight focuses on web honeypots, authentication activity, directory traversal, and host reconnaissance; Enterprise ATT&CK is the authoritative domain for these adversary techniques. Mobile and ICS datasets are outside current scope.

### 3.3 Security Invariants
1. **Zero Dynamic Execution:** STIX data is parsed as pure JSON. Descriptions and names are treated as passive data; never executed, never passed to `eval()` or `exec()`.
2. **Safe XSS Sanitization:** Descriptions are plain text or sanitized Markdown; raw script tags or dangerous attributes are stripped.
3. **Idempotent Imports:** Re-importing an identical verified dataset creates 0 duplicate records.
4. **Dry-Run by Default:** Imports require explicit administrator approval; candidate imports undergo dry-run validation without touching active catalogue records.
5. **Rollback Resilience:** If an active version is invalidated, administrators can rollback to the previous active version without data destruction.

---

## 4. Files Expected for P19

### Backend Module (`backend/app/modules/mitre/`)
- `__init__.py`: Package export.
- `models.py`: Declarative SQLAlchemy models for versioned ATT&CK entities.
- `schemas.py`: Pydantic schemas for STIX objects, catalogue queries, dry-run, and import summaries.
- `parser.py`: Safe STIX 2.1 JSON bundle parser with bounded limits.
- `validators.py`: Structural, identifier, and reference validation.
- `repository.py`: Database queries, filtering, pagination, and transactional upserts.
- `versioning.py`: Checksum verification, diffing between releases, and lifecycle management.
- `importer.py`: Dry-run orchestration, approval gating, and transactional execution.
- `service.py`: Service facade consumed by routes and detection engines.
- `routes.py`: Read-only catalogue endpoints and authorized administrative endpoints under `/api/v1/mitre`.
- `exceptions.py`: Domain-specific exceptions (`MitreParsingError`, `MitreValidationError`, `MitreImportError`).

### Test Suites (`backend/tests/modules/mitre/`)
- `test_parser.py`: STIX 2.1 parsing of tactics, techniques, sub-techniques, and malformed inputs.
- `test_validation.py`: Identifier, field, and size boundary tests.
- `test_importer.py`: Dry-run, idempotent import, rollback, and transaction isolation tests.
- `test_relationships.py`: Parent-child subtechniques and tactic association tests.
- `test_api.py`: FastAPI endpoints, pagination, search, status, and admin authorization tests.

### Frontend Contracts (`frontend/src/`)
- `types/mitre.ts`: TypeScript interfaces for tactics, techniques, sub-techniques, and catalogue status.
- `services/mitreApi.ts`: REST client methods for querying the ATT&CK catalogue.

### Documentation (`docs/mitre/`)
- `P19_EXISTING_PROJECT_ASSESSMENT.md` (this file)
- `MITRE_INTEGRATION.md`
- `DATA_MODEL.md`
- `DATA_IMPORT_RUNBOOK.md`
- `DATA_UPDATE_AND_ROLLBACK.md`
- `DATA_PROVENANCE.md`

---

## 5. Conclusion
The SnareSight architecture is sound, modular, and ready for MITRE ATT&CK integration. Proceed to Step 3: Dataset source verification and data model implementation.

