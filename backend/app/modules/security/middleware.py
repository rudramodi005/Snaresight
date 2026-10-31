"""HTTP middleware components for security headers and request payload bounds."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces defense-in-depth HTTP response security headers."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Standard browser protection headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

        # Content Security Policy (allows inline styles for Tailwind utility UI while prohibiting script injection)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )

        # HSTS in production environments
        if settings.ENVIRONMENT.lower() == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces maximum request body payload sizes to prevent memory exhaustion attacks."""

    def __init__(self, app: ASGIApp, max_bytes: int = None):
        super().__init__(app)
        self.max_bytes = max_bytes or settings.MAX_REQUEST_BODY_SIZE_BYTES

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                # Allow higher limit for ingestion batch endpoints (10MB) vs general REST (2MB)
                limit = 10 * 1024 * 1024 if "/ingestion" in request.url.path else self.max_bytes
                if length > limit:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Payload too large. Maximum permitted request body is {limit} bytes."
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)

