"""Services package for SnareSight Web Decoy."""

from .event_logger import DecoyEventLogger, event_logger
from .sanitization import (
    categorize_password_length,
    compute_username_fingerprint,
    detect_payload_markers,
    sanitize_string,
)
from .session_manager import DecoySessionManager, session_manager

__all__ = [
    "DecoyEventLogger",
    "event_logger",
    "DecoySessionManager",
    "session_manager",
    "sanitize_string",
    "compute_username_fingerprint",
    "categorize_password_length",
    "detect_payload_markers",
]

