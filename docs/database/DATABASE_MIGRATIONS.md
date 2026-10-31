# SnareSight — Database Migration Architecture & Alembic Workflow

**Document ID:** `SNARESIGHT-DB-MIG-001`  
**Phase:** 3 — Event Pipeline and Database  
**Classification:** Confidential — Internal Cybersecurity Engineering  
**Authority:** Alembic Migration Engineer & Backend Architect  

---

## 1. Migration Philosophy & Governance

In SnareSight, all relational database schema modifications are strictly governed by **Alembic revision scripts**:

1. **Zero Auto-Creation:** `Base.metadata.create_all()` is strictly forbidden in application startup. All tables, constraints, and indexes must be managed by explicit, versioned migrations.
2. **Deterministic Revision Control:** Every schema revision script is manually inspected and committed to Git under `backend/migrations/versions/`.
3. **Bi-Directional Migration:** Every migration script must implement both `upgrade()` and `downgrade()` functions to guarantee clean rollback capabilities in testing environments.
4. **Migration Role Execution:** Schema upgrades are executed exclusively by the `snaresight_migrator` role.

---

## 2. Alembic Directory Structure

```
backend/
├── alembic.ini                   # Core Alembic configuration & logging
├── migrations/
│   ├── env.py                    # Migration runtime context & SQLAlchemy metadata link
│   ├── script.py.mako            # Template for generated revision scripts
│   ├── README.md                 # Migration directory documentation
│   └── versions/
│       └── 0001_initial_schema.py # Initial baseline migration (Phase 3)
```

---

## 3. Standard Operational Workflows

### 3.1 Applying Pending Migrations (Upgrade)
To apply all pending migrations up to the latest revision:
```powershell
cd c:\Projects\SnareSight\backend
alembic upgrade head
```

### 3.2 Rolling Back Migrations (Downgrade)
In testing and development environments, to roll back the most recent migration:
```powershell
cd c:\Projects\SnareSight\backend
alembic downgrade -1
```
To roll back to a clean empty database:
```powershell
alembic downgrade base
```
> **CAUTION:** Downgrades drop relational tables. Never execute `alembic downgrade` against an operational or production database containing active security telemetry.

### 3.3 Generating a New Schema Revision
When models in `backend/app/db/models/` are modified:
```powershell
alembic revision --autogenerate -m "describe_change"
```
The generated file must be manually audited to confirm constraints, index types, and column nullability before running `alembic upgrade head`.

---

## 4. Initial Migration Specification (`0001_initial_schema.py`)

The initial migration establishes the foundational 12 tables defined in `docs/database/DATABASE_TABLES.md`:
1. `honeypots`
2. `event_sources`
3. `raw_events`
4. `security_events`
5. `sessions`
6. `detection_rules`
7. `alerts`
8. `alert_evidence`
9. `simulation_runs`
10. `observed_sources`
11. `attack_techniques`
12. `technique_mappings`

Along with all primary keys, foreign key constraints (`ON DELETE RESTRICT`), unique indexes, and the GIN index on `security_events.sanitized_metadata`.

