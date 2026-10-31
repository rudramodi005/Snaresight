"""Main entrypoint for the SnareSight Web-Login Decoy Service.

Configures FastAPI, security response headers, and exception handlers.
"""

from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.routes import health_router, login_router
from app.schemas.events import (
    DecoyEvent,
    EventInteraction,
    EventProvenance,
    EventRequest,
    EventSource,
    EventType,
)
from app.services.event_logger import event_logger
from app.services.sanitization import sanitize_string


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces standard defensive HTTP response headers."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Rejects oversized incoming requests to prevent memory exhaustion DoS."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Request body exceeds maximum threshold."}
            )
        return await call_next(request)


# Initialize FastAPI instance
app = FastAPI(
    title="SnareSight Web-Login Deception Decoy",
    description="Isolated honeypot decoy emulating an enterprise single sign-on portal.",
    version="0.1.0",
    docs_url=None,   # Disable OpenAPI swagger docs to avoid honeypot fingerprinting
    redoc_url=None,
    openapi_url=None,
)

# Register security middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MaxBodySizeMiddleware)

# Mount static directory for CSS styling
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Include routes
app.include_router(login_router)
app.include_router(health_router)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Logs suspicious URI probing (e.g. /wp-admin, /.env, /.git) as INVALID_REQUEST events."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = sanitize_string(request.headers.get("user-agent", "unknown"), max_len=256)
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME, "anonymous_probe")

    event = DecoyEvent(
        event_type=EventType.INVALID_REQUEST,
        decoy_id=settings.DECOY_ID,
        session_id=session_id,
        source=EventSource(ip_address=client_ip, user_agent_summary=user_agent),
        request=EventRequest(method=request.method, path=request.url.path),
        interaction=EventInteraction(
            status_code=status.HTTP_404_NOT_FOUND,
            simulated_outcome="not_found_logged",
            notes=f"Probing non-existent route: {request.url.path[:64]}"
        ),
        provenance=EventProvenance(
            source_type=settings.PROVENANCE_SOURCE,
            environment=settings.ENVIRONMENT
        )
    )
    event_logger.log_event(event)

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": "Resource not found on this administrative server."}
    )


def run():
    """CLI launcher for local offline testing."""
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.BIND_HOST,
        port=settings.BIND_PORT,
        log_level="info"
    )


if __name__ == "__main__":
    run()

