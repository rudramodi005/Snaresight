"""SnareSight security, user authentication, session, and audit logging models.

Implements UserModel, RevokedTokenModel, and SystemAuditLogModel with strict constraints,
role-based authorization, and non-repudiable audit trails.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, JSON, func
from app.db.base import Base


class UserModel(Base):
    """Internal application user entity with role-based access control."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), nullable=False, default="ANALYST")  # ADMIN, ANALYST, VIEWER
    is_active = Column(Boolean, nullable=False, default=True)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class RevokedTokenModel(Base):
    """Revoked JWT tokens (denylist) for immediate session invalidation on logout."""

    __tablename__ = "revoked_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    jti = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class SystemAuditLogModel(Base):
    """Immutable audit log recording security-relevant actions across SnareSight."""

    __tablename__ = "system_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_username = Column(String(64), nullable=False, index=True)
    actor_role = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False, index=True)  # LOGIN, FAILED_LOGIN, ALERT_STATUS, etc.
    resource_type = Column(String(64), nullable=False)       # USER, ALERT, REPORT, SENSOR, etc.
    resource_id = Column(String(128), nullable=True)
    outcome = Column(String(16), nullable=False, default="SUCCESS")  # SUCCESS, DENIED, FAILED
    status_code = Column(Integer, nullable=True)
    reason = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    request_context = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

