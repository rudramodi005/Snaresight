"""Pydantic schemas for structured JSONL honeypot events.

Guarantees 100% evidentiary integrity and strict sensitive data exclusion.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Supported deception telemetry event types."""
    DECOY_PAGE_VISITED = "decoy_page_visited"
    LOGIN_ATTEMPT = "login_attempt"
    SIMULATED_DECOY_ACCESS = "simulated_decoy_access"
    INVALID_REQUEST = "invalid_request"
    SESSION_TERMINATED = "session_terminated"


class EventSource(BaseModel):
    """Source connection metadata."""
    ip_address: str = Field(..., description="Direct connection remote IP address")
    user_agent_summary: str = Field(..., max_length=256, description="Sanitized client user agent summary")


class EventRequest(BaseModel):
    """HTTP request parameters."""
    method: str = Field(..., description="HTTP Method (GET, POST)")
    path: str = Field(..., description="Requested relative URI path")


class EventInteraction(BaseModel):
    """Deception interaction details. Strictly excludes plaintext passwords."""
    username_fingerprint: Optional[str] = Field(
        None, description="Privacy-safe HMAC-SHA256 pseudonym of username"
    )
    username_length: Optional[int] = Field(None, ge=0, le=1024)
    password_present: bool = Field(False, description="True if password field was non-empty")
    password_length_category: Optional[str] = Field(
        None, description="Coarse bucket: 'none', 'short (<8)', 'medium (8-16)', 'long (>16)'"
    )
    status_code: int = Field(..., description="Simulated HTTP response status returned to client")
    simulated_outcome: str = Field(..., description="Outcome summary (e.g. 'auth_rejected', 'portal_mock')")
    notes: Optional[str] = Field(None, max_length=512)


class EventProvenance(BaseModel):
    """Data provenance tracking."""
    source_type: str = Field("live_honeypot", description="live_honeypot | synthetic_demo | controlled_simulation")
    environment: str = Field("isolated_lab", description="Runtime environment zone")


class DecoyEvent(BaseModel):
    """Canonical SnareSight JSONL event record."""
    schema_version: str = Field("1.0", description="Event contract version")
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    observed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Strict UTC ISO-8601 timestamp"
    )
    decoy_id: str
    session_id: str
    source: EventSource
    request: EventRequest
    interaction: EventInteraction
    provenance: EventProvenance

