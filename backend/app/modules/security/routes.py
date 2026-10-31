"""FastAPI router for authentication, password management, user governance, and audit logs."""

from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.db.session import get_db
from app.db.models.security import UserModel, RevokedTokenModel, SystemAuditLogModel
from app.core.config import settings
from app.modules.security.permissions import Permission, Role, ROLE_PERMISSIONS
from app.modules.security.crypto import (
    hash_password,
    verify_password,
    create_access_token,
)
from app.modules.security.rate_limiter import auth_rate_limiter
from app.modules.security.audit_service import audit_service
from app.modules.security.dependencies import (
    get_current_user,
    require_permission,
    require_role,
    AuthenticatedUser,
)
from app.modules.security.schemas import (
    LoginRequest,
    TokenResponse,
    UserResponse,
    UserCreateRequest,
    ChangePasswordRequest,
    AuditLogResponse,
    AuditLogListResponse,
)

auth_router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])
audit_router = APIRouter(prefix="/audit", tags=["Security Audit Logging"])


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT session token",
)
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    """Authenticates credentials using salted bcrypt verification with rate-limiting."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    rate_limit_key = f"{client_ip}:{payload.username}"

    # 1. Rate limiting check
    if not auth_rate_limiter.is_allowed(
        rate_limit_key,
        max_attempts=settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_MINUTES * 60,
    ):
        audit_service.log_event(
            db=db,
            actor_username=payload.username,
            actor_role="UNKNOWN",
            action="LOGIN_RATE_LIMITED",
            resource_type="AUTH",
            outcome="DENIED",
            status_code=429,
            reason="Exceeded maximum login attempts",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )

    # 2. Query user from database by username or email
    user = (
        db.query(UserModel)
        .filter(
            or_(
                UserModel.username == payload.username,
                UserModel.email == payload.username,
            )
        )
        .first()
    )

    # Generic invalid credentials message to prevent user enumeration
    generic_error = "Invalid username or password"

    if not user:
        auth_rate_limiter.record_attempt(rate_limit_key)
        audit_service.log_event(
            db=db,
            actor_username=payload.username,
            actor_role="UNKNOWN",
            action="FAILED_LOGIN",
            resource_type="AUTH",
            outcome="FAILED",
            status_code=401,
            reason="User not found",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=generic_error,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check password hash
    if not verify_password(payload.password, user.hashed_password):
        auth_rate_limiter.record_attempt(rate_limit_key)
        user.failed_login_attempts += 1
        db.commit()
        audit_service.log_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            action="FAILED_LOGIN",
            resource_type="AUTH",
            outcome="FAILED",
            status_code=401,
            reason="Invalid password",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=generic_error,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Check active status
    if not user.is_active:
        audit_service.log_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            action="LOGIN_DENIED",
            resource_type="AUTH",
            outcome="DENIED",
            status_code=403,
            reason="Account is deactivated",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Please contact an administrator.",
        )

    # 5. Successful login: reset rate limiter and update stats
    auth_rate_limiter.reset(rate_limit_key)
    user.failed_login_attempts = 0
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    # 6. Issue JWT token
    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
    }
    access_token, jti = create_access_token(token_data)

    # 7. Set secure HttpOnly session cookie
    is_prod = settings.ENVIRONMENT.lower() == "production"
    response.set_cookie(
        key="snaresight_session",
        value=access_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    # 8. Record audit log
    audit_service.log_event(
        db=db,
        actor_username=user.username,
        actor_role=user.role,
        action="LOGIN",
        resource_type="AUTH",
        resource_id=user.id,
        outcome="SUCCESS",
        status_code=200,
        ip_address=client_ip,
    )

    user_role_enum = Role(user.role.upper()) if user.role.upper() in Role.__members__ else Role.VIEWER
    permissions = [p.value for p in ROLE_PERMISSIONS.get(user_role_enum, set())]

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        user_id=user.id,
        username=user.username,
        role=user.role,
        permissions=permissions,
    )


@auth_router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke session token and clear cookies",
)
def logout(
    response: Response,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Invalidates the active JWT session and records audit event."""
    if current_user.jti:
        revoked = RevokedTokenModel(
            jti=current_user.jti,
            user_id=current_user.user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        db.add(revoked)
        db.commit()

    # Clear session cookie
    response.delete_cookie("snaresight_session")

    audit_service.log_event(
        db=db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="LOGOUT",
        resource_type="AUTH",
        resource_id=current_user.user_id,
        outcome="SUCCESS",
    )

    return {"message": "Session terminated successfully"}


@auth_router.get(
    "/me",
    summary="Retrieve current user profile and granted permissions",
)
def get_current_user_profile(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns profile and operational permissions for the currently authenticated user."""
    user = db.query(UserModel).filter(UserModel.username == current_user.username).first()
    
    role_enum = Role(current_user.role.upper()) if current_user.role.upper() in Role.__members__ else Role.VIEWER
    permissions = [p.value for p in ROLE_PERMISSIONS.get(role_enum, set())]

    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": user.full_name if user else "Senior SOC Lead",
        "role": current_user.role,
        "is_active": current_user.is_active,
        "permissions": permissions,
    }


@auth_router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    summary="Change user password",
)
def change_password(
    payload: ChangePasswordRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Updates password after validating current password."""
    user = db.query(UserModel).filter(UserModel.username == current_user.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found")

    if not verify_password(payload.current_password, user.hashed_password):
        audit_service.log_event(
            db=db,
            actor_username=current_user.username,
            actor_role=current_user.role,
            action="PASSWORD_CHANGE_FAILED",
            resource_type="USER",
            resource_id=user.id,
            outcome="FAILED",
            reason="Incorrect current password",
        )
        raise HTTPException(status_code=400, detail="Current password verification failed")

    user.hashed_password = hash_password(payload.new_password)
    db.commit()

    audit_service.log_event(
        db=db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="PASSWORD_CHANGE_SUCCESS",
        resource_type="USER",
        resource_id=user.id,
        outcome="SUCCESS",
    )

    return {"message": "Password updated successfully"}


@auth_router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List all application users (ADMIN only)",
)
def list_users(
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_USERS)),
    db: Session = Depends(get_db),
):
    """Returns application users list for administrators."""
    users = db.query(UserModel).order_by(UserModel.created_at.desc()).all()
    return users


@auth_router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new application user (ADMIN only)",
)
def create_user(
    payload: UserCreateRequest,
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MANAGE_USERS)),
    db: Session = Depends(get_db),
):
    """Creates a new user account with hashed password and role."""
    role_upper = payload.role.upper()
    if role_upper not in Role.__members__:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{payload.role}'. Must be ADMIN, ANALYST, or VIEWER.",
        )

    # Check for duplicate username or email
    existing_user = db.query(UserModel).filter(
        (UserModel.username == payload.username) | (UserModel.email == payload.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this username or email already exists.",
        )

    new_user = UserModel(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=role_upper,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit_service.log_event(
        db=db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="USER_CREATE",
        resource_type="USER",
        resource_id=new_user.id,
        outcome="SUCCESS",
        request_context={"new_username": new_user.username, "new_role": new_user.role},
    )

    return new_user


@audit_router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Query system security audit logs",
)
def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    actor_username: Optional[str] = Query(None, description="Filter by actor"),
    outcome: Optional[str] = Query(None, description="Filter by outcome (SUCCESS, DENIED, FAILED)"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
    db: Session = Depends(get_db),
):
    """Retrieves immutable security audit logs with pagination and filters."""
    query = db.query(SystemAuditLogModel)

    if action:
        query = query.filter(SystemAuditLogModel.action == action)
    if actor_username:
        query = query.filter(SystemAuditLogModel.actor_username == actor_username)
    if outcome:
        query = query.filter(SystemAuditLogModel.outcome == outcome)

    total = query.count()
    items = (
        query.order_by(desc(SystemAuditLogModel.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return AuditLogListResponse(
        total=total,
        page=page,
        limit=limit,
        items=items,
    )

