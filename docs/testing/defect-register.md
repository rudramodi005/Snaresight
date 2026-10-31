# SnareSight Defect Register & Resolution Log

This register catalogs all verified defects identified during Phase 8 testing, detailing root cause, severity, remediation, and regression verification evidence.

---

## Defect Summary Matrix

| Defect ID | Severity | Affected Module | Root Cause | Fix Applied | Regression Test / Verification | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`DEF-001`** | **HIGH** | `frontend/` Build Scaffolding | Missing `tsconfig.json` and `vite.config.ts` in frontend root | Scaffolded standard `tsconfig.json` (bundler mode) and `vite.config.ts` | `npx tsc` executes and completes with code 0 | **RESOLVED & VERIFIED** |
| **`DEF-002`** | **MEDIUM** | `frontend/src/types/analytics.ts` | Python syntax `int` used instead of TypeScript `number` | Corrected `min_score: number; max_score: number;` | `npx tsc` passes type validation | **RESOLVED & VERIFIED** |
| **`DEF-003`** | **MEDIUM** | `frontend/src/services/responseApi.ts` | Method signature mismatches between `DefensiveResponseCenterPage.tsx` and `responseApi.ts` | Added overloaded parameter support and aliases (`createHold`, `releaseHold`, `startPlaybook`, `advancePlaybook`) | `npx tsc` passes clean compilation | **RESOLVED & VERIFIED** |
| **`DEF-004`** | **HIGH** | `backend/app/modules/resilience/backup_service.py` | `@classmethod initiate_backup` lacked `cls` argument, causing `multiple values for argument 'db'` | Corrected signature to `def initiate_backup(cls, db: Session, ...)` | `test_06_database_backup_generation` passed | **RESOLVED & VERIFIED** |
| **`DEF-005`** | **HIGH** | `backend/app/modules/resilience/health_service.py` | Missing `and_` import from SQLAlchemy in `check_detailed_diagnostics` | Imported `and_` from `sqlalchemy` | `test_02_detailed_diagnostics` passed | **RESOLVED & VERIFIED** |
| **`DEF-006`** | **MEDIUM** | `backend/app/modules/resilience/service.py` | In-place mutation of `checklist_items` JSON not detected as dirty by SQLAlchemy | Added `flag_modified(chk, "checklist_items")` | `test_09_disaster_recovery_checklists` passed | **RESOLVED & VERIFIED** |

---

## Detailed Defect Records

### DEF-001: Missing TypeScript & Vite Configuration
- **Description**: Frontend build script `npm run build` failed with `TS5083: Cannot read file '.../tsconfig.json'`.
- **Reproduction**: Run `npm run build` in `frontend/`.
- **Root Cause**: Initial repository creation lacked configuration files in `frontend/`.
- **Fix**: Created standard `tsconfig.json` with React JSX and bundler resolution, and `vite.config.ts` with `@vitejs/plugin-react` and API proxy.
- **Verification**: `npx tsc` now parses all 14 workspaces cleanly.

### DEF-002: Invalid Type Definition in Analytics
- **Description**: Type check failed with `Cannot find name 'int'` in `src/types/analytics.ts:112-113`.
- **Reproduction**: Run `npx tsc`.
- **Root Cause**: Accidental Python type syntax `int` written into TypeScript interface `ConfidenceBucketItem`.
- **Fix**: Updated types to `number`.
- **Verification**: Zero type errors reported.

### DEF-003: Response API Client Signatures
- **Description**: Defensive response center failed to compile due to missing methods `createHold`, `startPlaybook`, and extra `case_id` arguments.
- **Reproduction**: Run `npx tsc`.
- **Root Cause**: Service client methods expected single IDs while UI passed `case_id` as first parameter.
- **Fix**: Handled polymorphic argument signatures in `responseApi.ts` to accommodate both call styles gracefully.
- **Verification**: Clean compilation of `DefensiveResponseCenterPage.tsx`.

### DEF-004: Classmethod Binding in BackupService
- **Description**: `BackupService.initiate_backup` raised `TypeError: BackupService.initiate_backup() got multiple values for argument 'db'`.
- **Reproduction**: Call `backup_service.initiate_backup(db=db)`.
- **Root Cause**: First parameter was named `db` instead of `cls` on `@classmethod`.
- **Fix**: Added explicit `cls` parameter.
- **Verification**: Verified in `test_resilience_api.py`.

### DEF-005: Missing SQLAlchemy Import in HealthService
- **Description**: Detailed diagnostics endpoint threw `NameError: name 'and_' is not defined`.
- **Reproduction**: Call `GET /api/v1/resilience/health/diagnostics`.
- **Root Cause**: `and_` was omitted from SQLAlchemy import list.
- **Fix**: Added `and_` to `from sqlalchemy import select, func, text, and_`.
- **Verification**: Verified in `test_resilience_api.py`.

### DEF-006: JSON List Change Tracking in SQLAlchemy
- **Description**: Toggle checklist item did not persist item notes in SQLite database.
- **Reproduction**: Call `POST /api/v1/resilience/dr/checklists/DB_UNAVAILABLE/items/toggle` with `notes`.
- **Root Cause**: In-place mutations inside a JSON array do not trigger SQLAlchemy ORM modification events without explicit notification.
- **Fix**: Called `flag_modified(chk, "checklist_items")` before commit.
- **Verification**: Verified in `test_resilience_api.py`.

