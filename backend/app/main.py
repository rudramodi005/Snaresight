"""SnareSight backend central FastAPI application entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.ingestion import router as ingestion_router
from app.api.stream import router as stream_router
from app.api.health import router as health_router
from app.modules.mitre import mitre_router, mapping_router, attack_router
from app.correlation import correlation_router, sequence_router
from app.modules.source_intelligence import router as source_profile_router
from app.modules.campaign_intelligence import router as campaign_router
from app.modules.dashboard import dashboard_router
from app.modules.security_events import events_router
from app.modules.alerts import alerts_router
from app.modules.analytics import analytics_router, reports_router
from app.modules.response import response_router
from app.modules.sensors import sensors_router
from app.modules.resilience import resilience_router
from app.modules.demo import demo_router
from app.modules.security import (
    auth_router,
    audit_router,
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
)

app = FastAPI(
    title="SnareSight",
    description="Deception-Driven Threat Detection and Security Operations Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Security Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)

# CORS configuration for authorized frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register modular subsystem routers
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(audit_router, prefix=settings.API_PREFIX)
app.include_router(ingestion_router, prefix=settings.API_PREFIX)
app.include_router(stream_router, prefix=settings.API_PREFIX)
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(mitre_router, prefix=settings.API_PREFIX)
app.include_router(mapping_router, prefix=settings.API_PREFIX)
app.include_router(correlation_router, prefix=settings.API_PREFIX)
app.include_router(sequence_router, prefix=settings.API_PREFIX)
app.include_router(source_profile_router, prefix=settings.API_PREFIX)
app.include_router(campaign_router, prefix=settings.API_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(events_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(attack_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)
app.include_router(reports_router, prefix=settings.API_PREFIX)
app.include_router(response_router, prefix=settings.API_PREFIX)
app.include_router(sensors_router, prefix=settings.API_PREFIX)
app.include_router(resilience_router, prefix=settings.API_PREFIX)
app.include_router(demo_router, prefix=settings.API_PREFIX)


@app.on_event("startup")
def on_startup():
    """Ensure database tables and rule catalogue exist upon application boot."""
    try:
        from app.db.base import Base
        from app.db.session import engine
        import app.db.models  # noqa: F401
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"[Startup Notice] Database initialization: {e}")

    try:
        from app.modules.mitre.dashboard_service import AttackDashboardService
        from app.db.session import SessionLocal
        with SessionLocal() as db:
            AttackDashboardService.ensure_catalogue_initialized(db)
    except Exception as e:
        print(f"[Startup Notice] MITRE ATT&CK catalogue initialization: {e}")

    try:
        from app.detection.scenario_catalogue import register_scenario_catalogue
        register_scenario_catalogue()
    except Exception as e:
        print(f"[Startup Notice] Rule catalogue registration: {e}")

    try:
        from app.db.session import SessionLocal
        from app.modules.security.seed import seed_default_users
        with SessionLocal() as db:
            seed_default_users(db)
    except Exception as e:
        print(f"[Startup Notice] Default user seeding: {e}")

    try:
        from app.db.session import SessionLocal
        from app.db.seed_demo_data import seed_default_sensors
        with SessionLocal() as db:
            seed_default_sensors(db)
    except Exception as e:
        print(f"[Startup Notice] Default sensors seeding: {e}")


@app.get("/", tags=["Root"])
@app.head("/", tags=["Root"])
async def root():
    """Root operational gateway heartbeat."""
    return {
        "platform": "SnareSight",
        "status": "OPERATIONAL",
        "api_version": "v1",
        "docs": "/docs",
    }


@app.get("/health", tags=["Root"])
@app.head("/health", tags=["Root"])
async def root_health():
    """Liveness check for container orchestration and application launchers."""
    return {"status": "UP", "platform": "SnareSight"}


