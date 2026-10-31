# SnareSight: Dependency & Supply-Chain Security Audit

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Dependency Review & Minimal Surface Area

SnareSight prioritizes minimal, auditable dependencies to reduce the application supply-chain attack surface:

### Backend Core Dependencies
- **FastAPI / Starlette**: High-performance asynchronous web framework.
- **Pydantic v2**: Type enforcement, input validation, and schema serialization.
- **SQLAlchemy 2.0**: Typed ORM and parameterized query engine.
- **psycopg (v3)**: Modern PostgreSQL driver with binary protocol support.
- **Alembic**: Database migration management.
- **bcrypt**: Constant-time Blowfish salted password hashing.
- **python-jose / cryptography**: Cryptographic JWT signing and RFC 7519 verification.
- **ReportLab 5.0.0**: In-memory PDF document compilation engine.

### Frontend Core Dependencies
- **React 18 & TypeScript 5**: Type-safe component architecture with automatic HTML escaping.
- **Vite 6**: Fast, secure bundler with environment variable scoping (`VITE_*`).
- **Tailwind CSS**: Utility-first CSS styling without runtime eval or dynamic script injection.
- **Recharts**: Declarative SVG chart rendering.
- **Lucide React**: Clean SVG icon system.

---

## 2. Supply-Chain Hardening Principles

1. **Pinned Dependency Versions**: Versions in `pyproject.toml` and `package.json` use bounded semantic versioning.
2. **Lockfile Integrity**: Dependency graphs are verified to prevent unpinned resolution drift.
3. **No Unnecessary External Identity Providers**: Authentication is maintained internally with modern cryptographic standards (bcrypt, JWT), eliminating third-party authentication vendor dependencies and attack vectors.
4. **Vulnerability Mitigation**: Periodic checks against Python Safety / pip-audit databases to ensure critical security patches are integrated promptly.

