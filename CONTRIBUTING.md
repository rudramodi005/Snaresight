# SnareSight: Contributing & Development Guidelines

**Classification:** Developer Guidelines  
**Current Phase:** Phase 8 Release Candidate  
**Target Stack:** React 18 + TypeScript + Vite | Python 3.11+ + FastAPI | PostgreSQL 16 + SQLAlchemy 2.0  

---

## 1. Branching & Git Workflow

SnareSight enforces a structured, task-driven Git workflow:

```
main (Production / Verified Releases)
  │
  ├── release/v1.0.0
  └── feature/<phase>-<task-description>
        │
        ├── Automated Unit & Integration Tests (100% Pass)
        ├── Security & Invariant Review
        └── Pull Request & Peer Review
```

### 1.1 Branch Naming Conventions
* Feature branches: `feat/<subsystem>-<description>` (e.g., `feat/sensors-heartbeat-jitter`)
* Bugfix branches: `fix/<subsystem>-<description>` (e.g., `fix/scoring-case-insensitivity`)
* Documentation branches: `docs/<topic>` (e.g., `docs/api-reference-update`)

### 1.2 Commit Message Standards
Follow [Conventional Commits](https://www.conventionalcommits.org/):
* `feat(sensors): implement token rotation with grace period`
* `fix(detection): normalize event category casing during threshold checks`
* `docs(api): document demonstration lab evaluation endpoints`
* `test(e2e): add test for retention hold protection on case deletion`

---

## 2. Coding Standards & Architectural Discipline

### 2.1 Backend (Python / FastAPI)
* **Python Version:** Python 3.11+ compatible.
* **Code Style:** Comply with PEP 8. Format with Black/Ruff (`line-length = 88`).
* **Type Annotations:** Explicit type hints on all function parameters and return types.
* **Data Validation:** Validate all external request bodies with Pydantic schemas. Never accept arbitrary untyped dictionaries.
* **Database Queries:** Strictly use SQLAlchemy 2.0 select/insert/update statements. **Zero raw string concatenation in SQL queries.**
* **Error Handling:** Use custom exceptions mapped to explicit HTTP status codes via FastAPI exception handlers.

### 2.2 Frontend (React / TypeScript)
* **TypeScript Strict Mode:** Enabled. Zero `any` types permitted in production code without explicit justification.
* **Styling:** Strictly Tailwind CSS utility classes. Avoid inline style attributes.
* **State Management:** Custom React hooks and React Context.
* **Data Visualization:** Recharts for time-series charts; React Flow for attack chain DAGs.
* **Error Boundaries:** Wrap major dashboard views in React error boundaries.

---

## 3. Testing Requirements & Quality Gates

Every code change must be accompanied by automated verification evidence:

```bash
# 1. Run Backend Pytest Suite (Must pass 100%)
cd backend
pytest -v

# 2. Run Frontend Unit Tests
cd frontend
npm test -- --run

# 3. Verify Production Frontend Build
npm run build
```

Never mark a feature as working without automated test coverage or empirical demonstration evidence.

---

## 4. Mandatory Security Review Checklist

Before creating a commit or opening a pull request, verify:

- [ ] **No Hardcoded Secrets:** Confirm no passwords, JWT secret keys, or sensor tokens are committed.
- [ ] **Zero-Execution Invariant:** Confirm that no decoy payloads or uploaded files can be executed on the host.
- [ ] **Zero-Password Storage:** Confirm that captured passwords are salted SHA-256 hashed and redacted in logs.
- [ ] **Localhost Binding:** Development server configs must bind strictly to `127.0.0.1`.
- [ ] **Alembic Migrations:** Any schema change must include a reversible Alembic migration script in `backend/migrations/versions/`.
- [ ] **Retention Hold Compliance:** Confirm that data pruning functions respect `retention_hold = TRUE`.
