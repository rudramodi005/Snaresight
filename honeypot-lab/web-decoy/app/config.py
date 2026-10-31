"""Configuration management for SnareSight Web Decoy.

Enforces strict network binding safety and sensitive data limits using core Pydantic.
"""

import os
from pathlib import Path
from pydantic import BaseModel, Field, field_validator


class DecoySettings(BaseModel):
    """Runtime configuration for the web-login honeypot."""

    # Decoy Identity
    DECOY_ID: str = Field(default_factory=lambda: os.getenv("DECOY_ID", "WEB-DECOY-01"))
    DECOY_NAME: str = Field(default_factory=lambda: os.getenv("DECOY_NAME", "ApexCore Logistics Employee Access Portal"))
    ENVIRONMENT: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "isolated_lab"))
    PROVENANCE_SOURCE: str = Field(default_factory=lambda: os.getenv("PROVENANCE_SOURCE", "live_honeypot"))

    # Network Binding
    # INVARIANT: Must never bind to wildcard 0.0.0.0 or ::
    BIND_HOST: str = Field(default_factory=lambda: os.getenv("BIND_HOST", "127.0.0.1"))
    BIND_PORT: int = Field(default_factory=lambda: int(os.getenv("BIND_PORT", "8080")))

    # Storage & Logging
    DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data")
    EVENT_LOG_FILENAME: str = Field(default_factory=lambda: os.getenv("EVENT_LOG_FILENAME", "events.jsonl"))
    MAX_LOG_SIZE_BYTES: int = Field(default_factory=lambda: int(os.getenv("MAX_LOG_SIZE_BYTES", str(10 * 1024 * 1024))))

    # Privacy & Anonymization
    HMAC_SALT_KEY: str = Field(default_factory=lambda: os.getenv("HMAC_SALT_KEY", "snaresight_default_local_lab_salt_key_do_not_use_in_prod"))

    # Input Limits & Security Boundaries
    MAX_REQUEST_BODY_BYTES: int = Field(default_factory=lambda: int(os.getenv("MAX_REQUEST_BODY_BYTES", "32768")))
    MAX_USERNAME_LENGTH: int = Field(default_factory=lambda: int(os.getenv("MAX_USERNAME_LENGTH", "128")))
    MAX_PASSWORD_LENGTH: int = Field(default_factory=lambda: int(os.getenv("MAX_PASSWORD_LENGTH", "256")))
    SESSION_COOKIE_NAME: str = Field(default_factory=lambda: os.getenv("SESSION_COOKIE_NAME", "apex_session_id"))
    SESSION_LIFETIME_SECONDS: int = Field(default_factory=lambda: int(os.getenv("SESSION_LIFETIME_SECONDS", "3600")))

    @field_validator("BIND_HOST")
    @classmethod
    def validate_non_wildcard_host(cls, v: str) -> str:
        """Enforces that the decoy never listens on all public network interfaces."""
        normalized = v.strip().lower()
        if normalized in ("0.0.0.0", "::", "*"):
            raise ValueError(
                "SECURITY VIOLATION: Wildcard binding (0.0.0.0 or ::) is strictly "
                "prohibited by SnareSight isolation policies. Bind explicitly to "
                "127.0.0.1 or the verified isolated lab IP (e.g. 192.168.56.10)."
            )
        return v

    @property
    def event_log_path(self) -> Path:
        """Returns the full path to the active events.jsonl file."""
        return self.DATA_DIR / self.EVENT_LOG_FILENAME


# Global singleton settings instance
settings = DecoySettings()
