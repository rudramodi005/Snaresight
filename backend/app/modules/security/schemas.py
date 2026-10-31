"""Pydantic schemas for authentication, authorization, and audit logging."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credentials for authentication request."""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """Successful authentication response containing JWT and user profile."""
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user_id: str
    username: str
    role: str
    permissions: List[str]


class UserResponse(BaseModel):
    """User profile response without sensitive credentials."""
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserCreateRequest(BaseModel):
    """Administrative user creation request."""
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=128)
    role: str = Field("ANALYST", description="ADMIN, ANALYST, or VIEWER")


class ChangePasswordRequest(BaseModel):
    """Authenticated password update request."""
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


class AuditLogResponse(BaseModel):
    """Audit log entry response."""
    id: str
    actor_username: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    outcome: str
    status_code: Optional[int] = None
    reason: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_context: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    """Paginated list of system audit log entries."""
    total: int
    page: int
    limit: int
    items: List[AuditLogResponse]
