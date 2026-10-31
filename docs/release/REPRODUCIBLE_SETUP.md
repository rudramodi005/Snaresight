# SnareSight Release Candidate — Reproducible Setup & Startup Guide

**Document ID:** RUN-P37-001  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Release Target:** v1.0.0-rc1  
**Date:** October 31, 2026  
**Status:** VERIFIED RUNBOOK  

---

## 1. Prerequisites

- **Python:** 3.11+ (Python 3.14 tested and supported)
- **Node.js:** v18+ (Node.js v22 tested and supported)
- **Database:** PostgreSQL 15+ (or isolated Docker container)
- **Tooling:** `uv` (fast Python package manager) and `npm`

---

## 2. Option A: Native Local Startup (Development & Evaluation)

### Step 1: Initialize Database & Apply Migrations
```powershell
cd c:\Projects\SnareSight\backend

# Run schema migrations from baseline to head
uv run alembic upgrade head
```

### Step 2: Launch Backend Gateway
```powershell
cd c:\Projects\SnareSight\backend

# Start FastAPI server on port 8000
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify gateway health:
```powershell
curl http://127.0.0.1:8000/api/v1/health
# Expected: {"status":"HEALTHY","subsystems":{...}}
```

### Step 3: Launch Frontend Dashboard
```powershell
cd c:\Projects\SnareSight\frontend

# Install dependencies and start Vite dev server
npm install
npm run dev
```
Open browser to `http://localhost:5173`.

---

## 3. Option B: Docker Compose Startup (Hermetic Release Candidate)

To start the complete platform (PostgreSQL, Backend API, Frontend Dashboard) in an isolated container network:

```powershell
cd c:\Projects\SnareSight

# Build and start all services
docker compose up --build -d
```

Check service status:
```powershell
docker compose ps
```

Apply migrations within the container:
```powershell
docker compose exec backend alembic upgrade head
```

Access Web Dashboard:
- Browser URL: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`

Clean teardown:
```powershell
docker compose down
```

---

## 4. Verification and Sanity Testing

After starting the platform, execute the end-to-end integration and demonstration tests:

```powershell
# 1. Run Backend Automated Test Suite
cd c:\Projects\SnareSight\backend
uv run --extra dev pytest

# 2. Run Frontend Automated Test Suite
cd c:\Projects\SnareSight\frontend
npm run test

# 3. Verify Production Frontend Build
npm run build
```

