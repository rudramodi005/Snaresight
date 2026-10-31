"""Sensor authentication and credential management service.

Handles cryptographically secure token generation, hashing, verification,
and anti-impersonation checks for honeypot telemetry and heartbeat streams.
"""

import secrets
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Tuple, Optional
from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models.sensor import SensorModel, SensorCredentialModel


def hash_sensor_key(raw_key: str) -> str:
    """Computes SHA-256 cryptographic digest of a raw API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_sensor_api_key(sensor_id: str) -> Tuple[str, str, str, str]:
    """
    Generates a cryptographically strong sensor API key.
    
    Returns:
        (key_id, raw_api_key, key_prefix, hashed_api_key)
    """
    token_entropy = secrets.token_urlsafe(32)
    raw_api_key = f"snr_live_{token_entropy}"
    key_prefix = f"snr_live_{raw_api_key[9:15]}..."
    hashed_api_key = hash_sensor_key(raw_api_key)
    key_id = f"KEY-{uuid.uuid4().hex[:12].upper()}"
    return key_id, raw_api_key, key_prefix, hashed_api_key


def authenticate_sensor_request(
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    db: Session = Depends(get_db),
) -> Tuple[SensorModel, SensorCredentialModel]:
    """
    FastAPI dependency validating the X-Sensor-Key header against active sensor credentials.
    Prevents sensor impersonation and rejects revoked/disabled sensors.
    """
    if not x_sensor_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-Sensor-Key authentication header",
        )

    hashed_input = hash_sensor_key(x_sensor_key)
    credential = (
        db.query(SensorCredentialModel)
        .filter(
            SensorCredentialModel.hashed_api_key == hashed_input,
            SensorCredentialModel.status == "ACTIVE",
        )
        .first()
    )

    if not credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked sensor API key",
        )

    # Check expiration if set
    if credential.expires_at and credential.expires_at < datetime.now(timezone.utc):
        credential.status = "EXPIRED"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sensor API key has expired",
        )

    # Load associated sensor
    sensor = db.query(SensorModel).filter(SensorModel.sensor_id == credential.sensor_id).first()
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Associated sensor record not found",
        )

    if sensor.operational_status == "DISABLED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sensor '{sensor.sensor_id}' is administratively disabled",
        )

    if sensor.operational_status == "RETIRED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sensor '{sensor.sensor_id}' is permanently retired",
        )

    # Update last_used_at timestamp
    credential.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return sensor, credential

