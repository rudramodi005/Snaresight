"""SnareSight Security Events Explorer module exports (Task P27)."""

from app.modules.security_events.routes import router as events_router

__all__ = ["events_router"]

