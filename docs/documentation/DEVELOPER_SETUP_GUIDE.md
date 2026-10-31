# SnareSight: Developer Installation & Setup Guide

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Date:** October 2026  
**Audience:** Developers, DevOps Engineers, and Evaluators  

---

## 1. System Requirements & Prerequisites

Before setting up SnareSight locally, verify that your host machine meets the following hardware and software requirements:

### Hardware Requirements
* **CPU:** Dual-core 64-bit processor (4 cores recommended for running background demo scenarios).
* **RAM:** 8 GB minimum (16 GB recommended).
* **Disk Space:** 10 GB free space for repository, dependencies, database storage, and test artifacts.

### Software Prerequisites
| Component | Minimum Version | Recommended Version | Verification Command |
|---|---|---|---|
| **Python** | 3.11 | 3.11, 3.12, or 3.13 | `python --version` |
| **Node.js** | 20.0 LTS | 22.0 LTS | `node --version` |
| **npm** | 10.0+ | 10.8+ | `npm --version` |
| **PostgreSQL** | 15.0 | 16.2 | `psql --version` |
| **Git** | 2.30+ | 2.45+ | `git --version` |
| **Docker (Optional)** | 24.0+ | Latest Desktop | `docker --version` |

---

## 2. Repository Cloning & Structure

Clone the repository to your local workspace:

```bash
git clone https://github.com/your-org/SnareSight.git
cd SnareSight
```

### Directory Layout
```
SnareSight/
├── backend/                  # FastAPI Modular Monolith application
│   ├── alembic.ini           # Alembic database migration configuration
│   ├── migrations/           # Database migration scripts (p01 to p34)
│   ├── app/                  # Application source code
│   │   ├── core/             # Configuration, database engine, security
│   │   ├── models/           # SQLAlchemy ORM declarative models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── api/              # FastAPI route controllers
│   │   ├── modules/          # Subsystem domain services (15 modules)
│   │   └── main.py           # FastAPI application entrypoint
│   ├── tests/                # Pytest unit and integration test suite
│   ├── requirements.txt      # Python dependencies
│   └── Dockerfile            # Multi-stage production container
├── frontend/                 # React 18 + TypeScript + Vite UI
│   ├── src/                  # Application source code
│   │   ├── components/       # Reusable UI widgets and layout
│   │   ├── pages/            # Page views (Overview, Alerts, Sessions, Demo...)
│   │   ├── services/         # API clients and SSE listeners
│   │   └── types/            # TypeScript data contracts
│   ├── tests/                # Vitest unit test suite
│   ├── package.json          # Node dependencies and scripts
│   ├── vite.config.ts        # Vite build and proxy configuration
│   └── Dockerfile            # Node + Nginx production container
├── docs/                     # Comprehensive documentation repository
├── docker-compose.yml        # Orchestration for DB, backend, and frontend
└── CONTRIBUTING.md           # Developer guidelines and coding standards
```

---

## 3. Backend Setup & Configuration

### 3.1 Python Virtual Environment

#### On Windows (PowerShell):
```powershell
cd c:\Projects\SnareSight\backend
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### On Linux / macOS (Bash):
```bash
cd /path/to/SnareSight/backend
python3 -m venv venv
source venv/bin/activate
```

### 3.2 Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 Configure Environment Variables

Create the `backend/.env` file from the provided template:

```bash
# Windows
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Review and adjust the environment variables in `backend/.env`:

```ini
# ==============================================================================
# SNARESIGHT BACKEND CONFIGURATION
# ==============================================================================

# Application Environment (development, testing, production)
ENVIRONMENT=development
APP_NAME=SnareSight
DEBUG=True

# Host & Port Binding (Strict Localhost Binding)
HOST=127.0.0.1
PORT=8000

# Database Configuration (PostgreSQL 16)
POSTGRES_SERVER=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=snaresight
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

# Secret Key for JWT Authentication (Use a cryptographically random 32+ char key)
SECRET_KEY=change-this-in-production-secure-random-token-32-chars-min
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Sensor Ingestion Authentication Key
SENSOR_SHARED_SECRET=sensor-auth-secret-token-key-2026

# CORS Allowed Origins
CORS_ORIGINS=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]

# Retention & Log Level
LOG_LEVEL=INFO
DATA_RETENTION_DAYS=90
```

---

## 4. Database Setup & Migration

### 4.1 Create Database in PostgreSQL

Verify that PostgreSQL is running, then initialize the database:

```sql
-- Connect via psql
psql -U postgres -h 127.0.0.1

-- Create SnareSight database
CREATE DATABASE snaresight;
\q
```

*(Alternatively, if using Docker for PostgreSQL)*:
```bash
docker run -d --name snaresight-postgres -p 5432:5432 \
  -e POSTGRES_DB=snaresight \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  postgres:16-alpine
```

### 4.2 Execute Alembic Migrations

Run database migrations to initialize all tables, foreign keys, and indexes:

```bash
cd backend

# Apply all migrations up to the latest revision
alembic upgrade head
```

Verify that the migration head corresponds to `p34_operational_resilience`:
```bash
alembic current
```

#### Migration Management Commands:
* **Rollback one revision:** `alembic downgrade -1`
* **Rollback to baseline:** `alembic downgrade base`
* **Generate new autocommit migration:** `alembic revision --autogenerate -m "description_of_change"`
* **Check migration history:** `alembic history --verbose`

---

## 5. Starting the Development Servers

### 5.1 Start Backend (FastAPI + Uvicorn)
From the `backend/` directory with `venv` activated:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Output will indicate:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Application startup complete.
```

Verify backend health in another terminal:
```bash
curl http://127.0.0.1:8000/health
# Response: {"status":"healthy","database":"connected","timestamp":"..."}
```

Open interactive Swagger API documentation:
* **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc UI:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### 5.2 Start Frontend (React + Vite)
In a new terminal window:
```powershell
cd c:\Projects\SnareSight\frontend
npm install
npm run dev
```
Output will indicate:
```
  VITE v5.x.x  ready in 240 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

Open your browser to [http://localhost:5173](http://localhost:5173). The frontend includes a pre-configured Vite proxy forwarding `/api` and `/stream` requests directly to `http://127.0.0.1:8000`.

---

## 6. Running the Automated Test Suites

### 6.1 Backend Tests (Pytest)
```bash
cd backend
pytest -v
```
All integration and workflow tests will run against an in-memory SQLite / test database and complete in seconds:
* `tests/test_demo_api.py` (11 passed)
* `tests/test_e2e_workflows.py` (8 passed)

### 6.2 Frontend Tests (Vitest)
```bash
cd frontend
npm test -- --run
```
Executes all UI component tests, state hooks, and routing tests (9 passed).

### 6.3 Frontend Production Build Verification
```bash
cd frontend
npm run build
```
Generates optimized static assets in `frontend/dist/` with zero TypeScript or bundling errors.

---

## 7. Development Workflows & Best Practices

1. **Strict Localhost Binding:** Never change host bindings to `0.0.0.0` during development without firewall isolation.
2. **Database Migrations:** Never modify database schema directly in SQL. Always create and commit an Alembic migration script in `backend/migrations/versions/`.
3. **Pydantic Validation:** All incoming HTTP requests and honeypot events must have corresponding Pydantic request models with explicit validation constraints.
4. **Zero-Password Storage:** Ensure that password fields in incoming honeypot events are hashed and salted prior to database persistence.
5. **Linting and Formatting:**
   * Backend: Run `ruff check .` or `flake8`
   * Frontend: Run `npm run lint`

