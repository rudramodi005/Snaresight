"""SnareSight application security, RBAC, authentication, and audit module."""

from app.modules.security.routes import auth_router, audit_router
from app.modules.security.dependencies import (
    get_current_user,
    require_permission,
    require_role,
    AuthenticatedUser,
)
from app.modules.security.permissions import Permission, Role, ROLE_PERMISSIONS, has_permission
from app.modules.security.crypto import hash_password, verify_password, create_access_token, decode_access_token
from app.modules.security.audit_service import audit_service
from app.modules.security.middleware import SecurityHeadersMiddleware, RequestSizeLimitMiddleware

__all__ = [
    "auth_router",
    "audit_router",
    "get_current_user",
    "require_permission",
    "require_role",
    "AuthenticatedUser",
    "Permission",
    "Role",
    "ROLE_PERMISSIONS",
    "has_permission",
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "audit_service",
    "SecurityHeadersMiddleware",
    "RequestSizeLimitMiddleware",
]

