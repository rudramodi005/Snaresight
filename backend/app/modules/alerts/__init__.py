"""SOC Alert Management and Triage Center module entrypoint (Task P28)."""

from app.modules.alerts.routes import router as alerts_router

__all__ = ["alerts_router"]

