"""Web login decoy route handlers.

Implements simulated corporate authentication, session tracking, and structured
deception event emission while guaranteeing zero password persistence.
"""

from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.schemas.events import (
    DecoyEvent,
    EventInteraction,
    EventProvenance,
    EventRequest,
    EventSource,
    EventType,
)
from app.services.event_logger import event_logger
from app.services.sanitization import (
    categorize_password_length,
    compute_username_fingerprint,
    detect_payload_markers,
    sanitize_string,
)
from app.services.session_manager import session_manager

router = APIRouter(tags=["Decoy Interaction"])

# Configure Jinja2 templates directory
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _extract_source(request: Request) -> EventSource:
    """Extracts direct connection source metadata."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = sanitize_string(request.headers.get("user-agent", "unknown"), max_len=256)
    return EventSource(ip_address=client_ip, user_agent_summary=user_agent)


@router.get("/", response_class=HTMLResponse)
@router.get("/login", response_class=HTMLResponse)
async def get_login_page(
    request: Request,
    response: Response,
    apex_session_id: Optional[str] = Cookie(None)
):
    """Presents the simulated corporate login portal and emits DECOY_PAGE_VISITED event."""
    session_id, is_new = session_manager.get_or_create_session(apex_session_id)

    # Emit DECOY_PAGE_VISITED event
    event = DecoyEvent(
        event_type=EventType.DECOY_PAGE_VISITED,
        decoy_id=settings.DECOY_ID,
        session_id=session_id,
        source=_extract_source(request),
        request=EventRequest(method="GET", path=request.url.path),
        interaction=EventInteraction(
            status_code=status.HTTP_200_OK,
            simulated_outcome="portal_rendered",
            notes="Initial portal view"
        ),
        provenance=EventProvenance(
            source_type=settings.PROVENANCE_SOURCE,
            environment=settings.ENVIRONMENT
        )
    )
    event_logger.log_event(event)

    rendered = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error_message": None}
    )
    if is_new or apex_session_id != session_id:
        rendered.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=session_id,
            max_age=settings.SESSION_LIFETIME_SECONDS,
            httponly=True,
            samesite="lax",
            path="/"
        )
    return rendered


@router.post("/login", response_class=HTMLResponse)
async def post_login_attempt(
    request: Request,
    response: Response,
    username: str = Form(default=""),
    password: str = Form(default=""),
    apex_session_id: Optional[str] = Cookie(None)
):
    """Processes simulated authentication attempts.

    INVARIANT: Plaintext password is NEVER logged, stored, or echoed.
    """
    session_id, is_new = session_manager.get_or_create_session(apex_session_id)

    # 0. Validate Content-Type header
    content_type = request.headers.get("content-type", "").lower()
    if not (content_type.startswith("application/x-www-form-urlencoded") or content_type.startswith("multipart/form-data")):
        event = DecoyEvent(
            event_type=EventType.INVALID_REQUEST,
            decoy_id=settings.DECOY_ID,
            session_id=session_id,
            source=_extract_source(request),
            request=EventRequest(method="POST", path="/login"),
            interaction=EventInteraction(
                status_code=status.HTTP_400_BAD_REQUEST,
                simulated_outcome="invalid_content_type_rejected",
                notes=f"Unsupported Content-Type header: {content_type}"
            ),
            provenance=EventProvenance(
                source_type=settings.PROVENANCE_SOURCE,
                environment=settings.ENVIRONMENT
            )
        )
        event_logger.log_event(event)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported Media Type: expected application/x-www-form-urlencoded"
        )

    # 0b. Validate form structure integrity
    try:
        form_data = await request.form()
        if "username" not in form_data and "password" not in form_data:
            event = DecoyEvent(
                event_type=EventType.INVALID_REQUEST,
                decoy_id=settings.DECOY_ID,
                session_id=session_id,
                source=_extract_source(request),
                request=EventRequest(method="POST", path="/login"),
                interaction=EventInteraction(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    simulated_outcome="malformed_body_rejected",
                    notes="Missing required form fields in request body"
                ),
                provenance=EventProvenance(
                    source_type=settings.PROVENANCE_SOURCE,
                    environment=settings.ENVIRONMENT
                )
            )
            event_logger.log_event(event)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Malformed form structure: missing credential fields."
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed form body encoding."
        )

    # Input length restrictions
    if len(username) > settings.MAX_USERNAME_LENGTH or len(password) > settings.MAX_PASSWORD_LENGTH:
        # Emit INVALID_REQUEST event
        event = DecoyEvent(
            event_type=EventType.INVALID_REQUEST,
            decoy_id=settings.DECOY_ID,
            session_id=session_id,
            source=_extract_source(request),
            request=EventRequest(method="POST", path="/login"),
            interaction=EventInteraction(
                status_code=status.HTTP_400_BAD_REQUEST,
                simulated_outcome="oversized_payload_rejected",
                notes="Submitted credentials exceed maximum length thresholds"
            ),
            provenance=EventProvenance(
                source_type=settings.PROVENANCE_SOURCE,
                environment=settings.ENVIRONMENT
            )
        )
        event_logger.log_event(event)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload size exceeds permitted boundary."
        )

    # 1. Privacy-preserving username HMAC fingerprint
    uname_fp = compute_username_fingerprint(username, settings.HMAC_SALT_KEY)
    uname_len = len(username) if username else 0

    # 2. Categorize password length and immediately discard plaintext
    pwd_present, pwd_cat = categorize_password_length(password)
    del password  # Explicitly release memory reference

    # 3. Detect inert attack markers for threat telemetry
    markers = detect_payload_markers(username)
    notes = f"Markers: {','.join(markers)}" if markers else "Standard probe"

    # 4. Check for simulated demonstration trigger
    is_demo_trigger = username.strip().lower() in ("demo_analyst", "demo_admin", "lab_test_user")

    if is_demo_trigger and pwd_present:
        # Emit SIMULATED_DECOY_ACCESS event
        event = DecoyEvent(
            event_type=EventType.SIMULATED_DECOY_ACCESS,
            decoy_id=settings.DECOY_ID,
            session_id=session_id,
            source=_extract_source(request),
            request=EventRequest(method="POST", path="/login"),
            interaction=EventInteraction(
                username_fingerprint=uname_fp,
                username_length=uname_len,
                password_present=pwd_present,
                password_length_category=pwd_cat,
                status_code=status.HTTP_200_OK,
                simulated_outcome="simulated_access_granted",
                notes=f"Controlled demo activation. {notes}"
            ),
            provenance=EventProvenance(
                source_type="controlled_simulation",
                environment=settings.ENVIRONMENT
            )
        )
        event_logger.log_event(event)

        rendered = templates.TemplateResponse(
            request=request,
            name="simulated_portal.html",
            context={"session_id": session_id}
        )
        if is_new:
            rendered.set_cookie(
                key=settings.SESSION_COOKIE_NAME,
                value=session_id,
                max_age=settings.SESSION_LIFETIME_SECONDS,
                httponly=True,
                samesite="lax",
                path="/"
            )
        return rendered

    # Default Decoy Behavior: Emit LOGIN_ATTEMPT and return realistic simulated rejection
    event = DecoyEvent(
        event_type=EventType.LOGIN_ATTEMPT,
        decoy_id=settings.DECOY_ID,
        session_id=session_id,
        source=_extract_source(request),
        request=EventRequest(method="POST", path="/login"),
        interaction=EventInteraction(
            username_fingerprint=uname_fp,
            username_length=uname_len,
            password_present=pwd_present,
            password_length_category=pwd_cat,
            status_code=status.HTTP_401_UNAUTHORIZED,
            simulated_outcome="auth_rejected",
            notes=notes
        ),
        provenance=EventProvenance(
            source_type=settings.PROVENANCE_SOURCE,
            environment=settings.ENVIRONMENT
        )
    )
    event_logger.log_event(event)

    error_msg = "Authentication failed. Invalid corporate credentials (Error code: AC-4019). Attempt has been logged."
    rendered = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error_message": error_msg},
        status_code=status.HTTP_401_UNAUTHORIZED
    )
    if is_new:
        rendered.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=session_id,
            max_age=settings.SESSION_LIFETIME_SECONDS,
            httponly=True,
            samesite="lax",
            path="/"
        )
    return rendered


@router.get("/logout")
async def logout(
    request: Request,
    response: Response,
    apex_session_id: Optional[str] = Cookie(None)
):
    """Terminates the decoy session and emits SESSION_TERMINATED event."""
    if apex_session_id:
        event = DecoyEvent(
            event_type=EventType.SESSION_TERMINATED,
            decoy_id=settings.DECOY_ID,
            session_id=apex_session_id,
            source=_extract_source(request),
            request=EventRequest(method="GET", path="/logout"),
            interaction=EventInteraction(
                status_code=status.HTTP_302_FOUND,
                simulated_outcome="session_closed",
                notes="Client initiated session termination"
            ),
            provenance=EventProvenance(
                source_type=settings.PROVENANCE_SOURCE,
                environment=settings.ENVIRONMENT
            )
        )
        event_logger.log_event(event)

    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    return redirect
