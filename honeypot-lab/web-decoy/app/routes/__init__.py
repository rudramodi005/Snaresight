"""Routes package for SnareSight Web Decoy."""

from .health import router as health_router
from .login import router as login_router

__all__ = ["health_router", "login_router"]

