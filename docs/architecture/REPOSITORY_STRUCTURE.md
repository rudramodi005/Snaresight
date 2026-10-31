# SnareSight: Repository & Directory Structure Strategy
**Document ID:** ARCH-008  
**Status:** Approved Monorepo Structure Baseline  

---

## 1. Monorepo Organization

SnareSight uses a clean **Monorepo** structure that isolates frontend, backend, isolated lab scripts, simulation harnesses, and documentation within a single version-controlled repository:

```
SnareSight/
│
├── frontend/                      # React + TypeScript + Vite Dashboard
│   ├── src/
│   │   ├── assets/                # Logos, static assets, custom SVG icons
│   │   ├── components/            # Reusable atomic UI components (Button, Modal, Card, Badge)
│   │   ├── features/              # Feature modules (alerts, events, attack-chains, mitre)
│   │   │   ├── alerts/            # Alert center components and hooks
│   │   │   ├── attack-chains/     # React Flow canvas, node renderers, edge types
│   │   │   ├── events/            # Event table, raw JSON viewer drawer
│   │   │   ├── honeypots/         # Decoy status cards, registration forms
│   │   │   ├── investigations/    # Case management and analyst notes
│   │   │   └── mitre/             # ATT&CK matrix grid and technique cards
│   │   ├── hooks/                 # Custom React hooks (useSSE, useAuth, useDebounce)
│   │   ├── layouts/               # DashboardLayout, Sidebar, Navbar
│   │   ├── pages/                 # Route entry pages (OverviewPage, AlertsPage, etc.)
│   │   ├── services/              # API clients (axios / fetch wrapper with auth injection)
│   │   ├── types/                 # Shared TypeScript interfaces (Event, Alert, Decoy)
│   │   └── utils/                 # Formatting utilities, date helpers, severity parsers
│   ├── public/                    # Static public assets (favicon, manifest)
│   ├── index.html                 # Vite HTML entry point
│   ├── package.json               # Frontend dependencies & npm scripts
│   ├── tsconfig.json              # Strict TypeScript compiler options
│   ├── tailwind.config.js         # Tailwind theme & color definitions
│   └── vite.config.ts             # Vite bundler & proxy configuration
│
├── backend/                       # Python FastAPI Modular Monolith
│   ├── app/
│   │   ├── api/                   # REST routing layer
│   │   │   ├── v1/                # Versioned API routes
│   │   │   │   ├── alerts.py      # Alert query and triage endpoints
│   │   │   │   ├── auth.py        # User login, JWT token issuance
│   │   │   │   ├── chains.py      # Attack-chain graph retrieval
│   │   │   │   ├── events.py      # Event query & timeline endpoints
│   │   │   │   ├── health.py      # System health and heartbeat checks
│   │   │   │   ├── honeypots.py   # Decoy registration & status
│   │   │   │   ├── ingest.py      # Telemetry intake endpoint
│   │   │   │   ├── investigations.py # Case management & analyst notes
│   │   │   │   ├── mitre.py       # ATT&CK technique catalog endpoints
│   │   │   │   └── reports.py     # Forensic report & IOC export
│   │   │   └── deps.py            # FastAPI dependency injection (DB session, auth user)
│   │   ├── core/                  # Application core
│   │   │   ├── config.py          # Pydantic BaseSettings environment loader
│   │   │   ├── database.py        # SQLAlchemy engine and session factory
│   │   │   ├── logging.py         # Structured JSON logging configuration
│   │   │   └── security.py        # JWT generation, bcrypt password hashing
│   │   ├── models/                # SQLAlchemy ORM database models
│   │   ├── schemas/               # Pydantic request, response, and ingestion schemas
│   │   ├── services/              # Business logic services
│   │   ├── ingestion/             # Telemetry sanitization and normalization pipeline
│   │   ├── detection/             # Rule evaluation engine and rule definitions
│   │   ├── correlation/           # Session grouping and attack-chain graph generator
│   │   └── intelligence/          # MITRE ATT&CK catalog and source profiling
│   ├── migrations/                # Alembic database migration scripts
│   ├── tests/                     # Pytest test suite (unit, integration, API tests)
│   ├── alembic.ini                # Alembic migration configuration
│   └── requirements.txt           # Python package requirements
│
├── honeypot-lab/                  # Isolated Lab Artifacts & Decoys
│   ├── web-decoy/                 # Isolated mock web-login service (simulated admin panel)
│   │   ├── app.py                 # Lightweight decoy Flask/FastAPI app
│   │   ├── forwarder.py           # Local forwarder shipper script
│   │   └── Dockerfile             # Container definition for isolated execution
│   └── cowrie-adapter/            # Modular Cowrie SSH integration adapter (post-MVP)
│
├── simulation/                    # Controlled Security Simulation Harnesses
│   ├── scenarios/                 # Attack simulation scripts (credential brute-force, traversal)
│   └── fixtures/                  # Reproducible test events and baseline telemetry
│
├── docs/                          # Comprehensive Technical & Security Documentation
│   ├── architecture/              # System, component, database, and API specifications
│   ├── security/                  # Threat models, risk registers, and isolation policies
│   └── runbooks/                  # Incident response, decoy setup, and recovery guides
│
├── scripts/                       # Local development and maintenance automation
│   ├── dev_setup.ps1              # Local environment bootstrapping script
│   └── run_simulation.ps1         # Safe attack simulation launcher
│
├── .gitignore                     # Git exclusion rules (secrets, venv, node_modules)
├── .env.example                   # Sanitized environment template
└── README.md                      # Project entry overview and quickstart guide
```

---

## 2. Monorepo Execution & Phasing Notice

> [!IMPORTANT]
> This folder structure represents the **architectural design**. In accordance with Phase 1 constraints, **the physical directory structure and Git repository will be created and validated during Task P05**, preserving a clean step-by-step progression.

