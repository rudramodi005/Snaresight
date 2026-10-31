"""Cryptographic utilities for password hashing and JWT token management.

Uses bcrypt for constant-time, salted password hashing and python-jose for JWT operations.
Plaintext passwords are never logged or stored.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import bcrypt
from jose import jwt, JWTError

from app.core.config import settings


def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using bcrypt with salt work factor 12."""
    if not plain_password:
        raise ValueError("Password cannot be empty")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash in constant time."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> tuple[str, str]:
    """Generates a signed JWT access token.
    
    Returns:
        tuple[token_string, jti]
    """
    to_encode = data.copy()
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt, jti


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and cryptographically validates a JWT access token.
    
    Raises:
        JWTError: If signature is invalid, token is expired, or claims are malformed.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )

