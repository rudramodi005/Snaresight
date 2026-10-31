# SnareSight Docker Infrastructure & Container Verification

**Orchestrator:** Docker Compose v2  
**Host Architecture:** Windows x86_64 / Docker Desktop Linux Containers  
**Date:** November 1, 2026  
**Auditor:** DevOps & Infrastructure Engineer  
**Status:** **VERIFIED (3/3 CONTAINERS HEALTHY)**

---

## 1. Container Topology & Health Status

```
NAME                  IMAGE                 SERVICE    STATUS                    PORTS
snaresight-backend    snaresight-backend    backend    Up (healthy)              127.0.0.1:8000->8000/tcp
snaresight-frontend   snaresight-frontend   frontend   Up (healthy)              127.0.0.1:5173->5173/tcp
snaresight-postgres   postgres:16-alpine    postgres   Up (healthy)              127.0.0.1:5432->5432/tcp
```

---

## 2. Container Configuration Verification

### 1. PostgreSQL Service (`snaresight-postgres`):
- **Image:** `postgres:16-alpine`
- **Volume:** `pgdata:/var/lib/postgresql/data` (persistent database volume preserved)
- **Health Check:** `pg_isready -U snaresight_app -d snaresight`
- **Port:** `127.0.0.1:5432:5432`
- **Status:** Up and healthy.

### 2. Backend Service (`snaresight-backend`):
- **Build Context:** `./backend`
- **Multi-Stage Build:**
  - Builder Stage: `python:3.12-slim` + `ghcr.io/astral-sh/uv:latest`
  - Creates virtual environment at `/opt/venv` and installs dependencies from `pyproject.toml`
  - Runtime Stage: `python:3.12-slim` with `/opt/venv` copied from builder
- **Command:** `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **Health Check:** `python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"`
- **Port:** `127.0.0.1:8000:8000`
- **Status:** Up and healthy.

### 3. Frontend Service (`snaresight-frontend`):
- **Build Context:** `./frontend`
- **Multi-Stage Build:**
  - Builder Stage: `node:22-alpine` (`npm ci` + `npm run build`)
  - Transformed 1,624 production modules via Vite 6 and TypeScript 5
  - Runtime Stage: `nginx:alpine-slim`
- **Reverse Proxy:**
  - Listens on port `5173`.
  - Serves static assets from `/usr/share/nginx/html`.
  - Proxies `/api/` to `http://backend:8000`.
  - Non-buffering SSE streaming proxy configured for `/api/v1/stream/`.
- **Health Check:** `wget -qO- http://127.0.0.1:5173/ > /dev/null || exit 1`
- **Port:** `127.0.0.1:5173:5173`
- **Status:** Up and healthy.

---

## 3. Network Isolation & Security Rules

- **Bridge Network:** `snaresight-internal` connects all 3 containers with internal DNS resolution.
- **Port Binding:** All host port bindings are strictly bound to loopback `127.0.0.1`, preventing unauthorized external network exposure.
- **Persistent Volume Safety:** Database volumes were untouched (`docker compose down -v` was never executed).

