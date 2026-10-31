# SnareSight: Final Release Package Manifest (v1.0.0-RC)

**Project Name:** SnareSight — Deception-Driven Threat Detection & Security Operations Platform  
**Release Candidate Version:** `v1.0.0-RC`  
**Phase:** 8 — Testing, Demonstration & Project Handover (Final Prompt 40/40)  
**Build Timestamp:** October 2026  
**Document:** `docs/final/RELEASE_MANIFEST.md`  
**Classification:** Official Release Manifest  

---

## 1. Release Identification & Version Metadata

| Attribute | Specification | Verification Evidence |
|---|---|---|
| **Platform Name** | SnareSight | Browser-based Web Application |
| **Release Version** | `v1.0.0-RC` (Release Candidate) | Tagged in documentation & manifests |
| **Frontend Version** | `0.1.0` (React 18.3, TypeScript 5.6, Vite 6.4) | `frontend/package.json` |
| **Backend Version** | `0.1.0` (FastAPI 0.115, Pydantic v2, Python 3.11+) | `backend/pyproject.toml` |
| **Database Engine** | PostgreSQL 16 / SQLAlchemy 2.0.35 | Relational normalized event store |
| **Migration Lineage** | `p34_operational_resilience (head)` | 9 unbroken Alembic migrations |
| **Dependency Locks** | `uv.lock` (Backend) / `package-lock.json` (Frontend) | Lockfiles committed and verified |
| **Backend Test Status** | **532 / 532 Passing (100%)** | Pytest execution completed in 84.7s |
| **Frontend Test Status** | **9 / 9 Passing (100%)** | Vitest execution completed in 0.57s |
| **Production Build** | **1618 modules transformed (0 errors)** | `npm run build` completed in 3.04s |
| **Deployment Mode** | Local Lab / Docker Compose (Non-Root) | `docker-compose.yml` verified |

---

## 2. Package Contents & Architecture Inventory

```
SnareSight-v1.0.0-RC/
├── backend/                              # Python FastAPI Modular Monolith
│   ├── app/                              # Application source code
│   │   ├── api/                          # HTTP controllers (ingestion, health, stream)
│   │   ├── core/                         # Settings, security, config
│   │   ├── db/                           # SQLAlchemy base & 42 declarative models
│   │   ├── detection/                    # Threat engine, 10 catalogue rules, scoring
│   │   ├── correlation/                  # Temporal sessions & attack chains
│   │   ├── modules/                      # 15 domain service modules
│   │   └── main.py                       # Central FastAPI ASGI entrypoint
│   ├── migrations/                       # Alembic versioned migrations (p01 to p34)
│   ├── tests/                            # 532 Pytest unit & integration tests
│   ├── alembic.ini                       # Migration configuration
│   ├── pyproject.toml                    # Python project configuration & dependencies
│   ├── requirements.txt                  # Pip dependency specification
│   ├── Dockerfile                        # Multi-stage production container
│   └── README.md                         # Backend technical documentation
├── frontend/                             # React 18 + TypeScript + Vite SOC Dashboard
│   ├── src/                              # Source code (components, pages, services)
│   ├── tests/                            # Vitest automated unit test suite
│   ├── package.json                      # Node dependencies & npm scripts
│   ├── vite.config.ts                    # Vite build & proxy configuration
│   ├── tsconfig.json                     # TypeScript strict configuration
│   └── Dockerfile                        # Multi-stage Node + Nginx container
├── honeypot-lab/                         # Isolated Decoy Configurations
│   └── web-decoy/                        # Python HTTP Web Login Decoy
├── docs/                                 # Complete Technical Documentation Library
│   ├── documentation/                    # 13 authoritative user & admin manuals
│   ├── final/                            # 15 academic evaluation & presentation docs
│   └── README.md                         # Master documentation index
├── docker-compose.yml                    # Multi-container orchestration (DB, API, UI)
├── .env.example                          # Sanitized environment template
├── CONTRIBUTING.md                       # Developer guidelines & coding standards
└── README.md                             # Project landing page & quickstart
```

---

## 3. Sanitization & Secret Exclusion Audit

In strict compliance with defensive cybersecurity invariants:
* **Excluded:** All `.env` local environment files, secret tokens, private keys (`*.key`, `*.pem`), temporary caches (`__pycache__`, `.pytest_cache`, `.venv`), and local node modules (`node_modules/`).
* **Included:** `.env.example` template with sanitized RFC 5737 dummy values and placeholder secrets.

---

## 4. Quickstart Execution Instructions

To deploy and execute the release candidate in under 3 minutes:

```bash
# 1. Clone repository
git clone https://github.com/your-org/SnareSight.git
cd SnareSight

# 2. Create environment file from template
cp .env.example .env

# 3. Start services via Docker Compose
docker compose up --build -d

# 4. Verify service health
docker compose ps
# Access Dashboard at: http://localhost:5173 (or port 80)
# Access API Docs at: http://localhost:8000/docs
```

---

## 5. Known Limitations & Scope Boundary Disclosure

1. **Local Lab Scoping:** Designed and verified for local isolated virtual network subnets; external public cloud deployment is not authorized without firewall perimeter integration.
2. **Deferred Shell Rules:** Rules `CMD-001` (Command Discovery) and `FILE-001` (File Transfer) are intentionally marked `DEFERRED` in the catalogue until physical high-interaction Cowrie SSH hardware sensors are deployed.
3. **Frontend Bundle Size:** Single minified JS bundle is 659 kB; route-based code splitting (`React.lazy()`) is scheduled for Phase 9 optimization.
4. **Attribution Boundaries:** IP threat profiles cluster network behavior; they do not claim legal proof of human identity.

