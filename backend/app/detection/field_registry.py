"""Controlled event field registry for SnareSight detection rules.

Enforces strict allowlists on inspectable event attributes, protects sensitive
fields, and defines explicit sensitivity classifications.
"""

from enum import Enum
from typing import Any, Callable, Dict, Optional, Set
from app.detection.exceptions import RestrictedFieldError, UnsupportedFieldError


class FieldSensitivity(str, Enum):
    """Sensitivity classification for event fields."""
    PUBLIC = "PUBLIC"              # Non-sensitive telemetry (e.g. decoy_id, protocol, timestamps)
    INTERNAL = "INTERNAL"          # Internal diagnostic/network data (e.g. source IP, session ID)
    RESTRICTED = "RESTRICTED"      # Confidential/security attributes; strictly prohibited


# Explicit denylist of prohibited sensitive fields. Any rule targeting these is rejected.
PROHIBITED_SENSITIVE_FIELDS: Set[str] = {
    "password",
    "password_hash",
    "raw_password",
    "secret",
    "secret_key",
    "api_key",
    "auth_token",
    "token",
    "authorization",
    "private_key",
    "credentials",
    "cookie",
    "session_secret",
}


class FieldDefinition:
    """Specification for an allowed event field in detection rules."""

    def __init__(
        self,
        name: str,
        expected_type: type | tuple[type, ...],
        sensitivity: FieldSensitivity,
        description: str,
        extractor: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.name = name
        self.expected_type = expected_type
        self.sensitivity = sensitivity
        self.description = description
        self.extractor = extractor or (lambda event: event.get(name))


class FieldRegistry:
    """Authoritative registry of inspectable normalized event fields."""

    _FIELDS: Dict[str, FieldDefinition] = {}

    @classmethod
    def register_field(cls, field_def: FieldDefinition) -> None:
        """Registers an allowed field in the registry."""
        cls._FIELDS[field_def.name] = field_def

    @classmethod
    def is_field_allowed(cls, field_name: str) -> bool:
        """Checks if a field is permitted for rule evaluation."""
        return field_name in cls._FIELDS

    @classmethod
    def get_field_def(cls, field_name: str) -> FieldDefinition:
        """Retrieves field specification or raises appropriate validation error."""
        normalized = field_name.strip().lower()
        if normalized in PROHIBITED_SENSITIVE_FIELDS:
            raise RestrictedFieldError(
                f"Field '{field_name}' is strictly classified as RESTRICTED and cannot be targeted by detection rules.",
                field=field_name,
            )
        if field_name not in cls._FIELDS:
            raise UnsupportedFieldError(
                f"Field '{field_name}' is not in the approved detection field registry.",
                field=field_name,
            )
        return cls._FIELDS[field_name]

    @classmethod
    def extract_value(cls, event: Dict[str, Any], field_name: str) -> Any:
        """Safely extracts field value from event dictionary using registered extractor."""
        field_def = cls.get_field_def(field_name)
        return field_def.extractor(event)

    @classmethod
    def all_fields(cls) -> Dict[str, FieldDefinition]:
        """Returns all registered inspectable fields."""
        return dict(cls._FIELDS)


# -----------------------------------------------------------------------------
# Initialize Approved Field Registry
# -----------------------------------------------------------------------------

def _extract_provenance_field(event: Dict[str, Any], subfield: str) -> Any:
    prov = event.get("provenance")
    if isinstance(prov, dict):
        return prov.get(subfield)
    return None


def _extract_metadata_field(event: Dict[str, Any], subfield: str) -> Any:
    meta = event.get("sanitized_metadata") or event.get("service_metadata")
    if isinstance(meta, dict):
        if subfield in meta:
            return meta.get(subfield)
        # Search nested scopes if partitioned by normalizer (auth, http, command, file)
        for section in ("auth", "http", "command", "file"):
            nested = meta.get(section)
            if isinstance(nested, dict):
                if subfield in nested:
                    return nested.get(subfield)
                if subfield == "http_path" and "path" in nested:
                    return nested.get("path")
                if subfield == "http_method" and "method" in nested:
                    return nested.get("method")
    return None


# Event Identifiers & Classification
FieldRegistry.register_field(FieldDefinition("event_id", str, FieldSensitivity.PUBLIC, "Normalized event unique identifier"))
FieldRegistry.register_field(FieldDefinition("raw_event_id", str, FieldSensitivity.PUBLIC, "Raw event unique identifier"))
FieldRegistry.register_field(FieldDefinition("event_type", str, FieldSensitivity.PUBLIC, "Canonical security event type"))
FieldRegistry.register_field(FieldDefinition("event_category", str, FieldSensitivity.PUBLIC, "High-level security classification"))
FieldRegistry.register_field(FieldDefinition("event_subcategory", (str, type(None)), FieldSensitivity.PUBLIC, "Sub-classification if available"))
FieldRegistry.register_field(FieldDefinition("action", str, FieldSensitivity.PUBLIC, "Observed interaction action"))
FieldRegistry.register_field(FieldDefinition("outcome", str, FieldSensitivity.PUBLIC, "Result outcome (SUCCESS, FAILURE, BLOCKED, etc.)"))

# Temporal Attributes
FieldRegistry.register_field(FieldDefinition("observed_at", str, FieldSensitivity.PUBLIC, "ISO-8601 UTC timestamp of interaction"))
FieldRegistry.register_field(FieldDefinition("received_at", (str, type(None)), FieldSensitivity.PUBLIC, "ISO-8601 UTC timestamp when ingested"))

# Source Attributes
FieldRegistry.register_field(FieldDefinition("source_address", str, FieldSensitivity.INTERNAL, "Origin IP address of interaction"))
FieldRegistry.register_field(FieldDefinition("source_port", (int, type(None)), FieldSensitivity.INTERNAL, "Origin TCP/UDP port"))
FieldRegistry.register_field(FieldDefinition("source_protocol", str, FieldSensitivity.PUBLIC, "Transport/Application protocol"))
FieldRegistry.register_field(FieldDefinition("observed_source_id", (str, type(None)), FieldSensitivity.INTERNAL, "Collector source identifier"))

# Target / Decoy Attributes
FieldRegistry.register_field(FieldDefinition("decoy_id", str, FieldSensitivity.PUBLIC, "Honeypot decoy identifier"))
FieldRegistry.register_field(FieldDefinition("target_service", str, FieldSensitivity.PUBLIC, "Simulated service target"))
FieldRegistry.register_field(FieldDefinition("target_port", (int, type(None)), FieldSensitivity.PUBLIC, "Decoy destination listening port"))

# Session
FieldRegistry.register_field(FieldDefinition("session_id", str, FieldSensitivity.INTERNAL, "Decoy interaction session identifier"))

# Provenance
FieldRegistry.register_field(FieldDefinition(
    "provenance.source_type", str, FieldSensitivity.PUBLIC, "Provenance source origin",
    lambda ev: _extract_provenance_field(ev, "source_type")
))
FieldRegistry.register_field(FieldDefinition(
    "provenance.environment", str, FieldSensitivity.PUBLIC, "Provenance environment",
    lambda ev: _extract_provenance_field(ev, "environment")
))

# Sanitized Metadata fields (safe inspection only; no passwords)
FieldRegistry.register_field(FieldDefinition(
    "metadata.username", (str, type(None)), FieldSensitivity.INTERNAL, "Observed decoy username",
    lambda ev: _extract_metadata_field(ev, "username")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.password_length", (int, type(None)), FieldSensitivity.INTERNAL, "Length of submitted password (not value)",
    lambda ev: _extract_metadata_field(ev, "password_length")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.http_method", (str, type(None)), FieldSensitivity.PUBLIC, "HTTP request method",
    lambda ev: _extract_metadata_field(ev, "http_method") or _extract_metadata_field(ev, "method")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.http_path", (str, type(None)), FieldSensitivity.PUBLIC, "HTTP requested URL path",
    lambda ev: _extract_metadata_field(ev, "http_path") or _extract_metadata_field(ev, "path")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.status_code", (int, type(None)), FieldSensitivity.PUBLIC, "HTTP response status code",
    lambda ev: _extract_metadata_field(ev, "status_code")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.username_fingerprint", (str, type(None)), FieldSensitivity.INTERNAL, "Privacy-safe hash/fingerprint of observed username",
    lambda ev: _extract_metadata_field(ev, "username_fingerprint")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.command_category", (str, type(None)), FieldSensitivity.PUBLIC, "Categorized command classification",
    lambda ev: _extract_metadata_field(ev, "command_category")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.command_text", (str, type(None)), FieldSensitivity.INTERNAL, "Sanitized captured command text (passive text only)",
    lambda ev: _extract_metadata_field(ev, "command_text")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.transfer_direction", (str, type(None)), FieldSensitivity.PUBLIC, "File transfer direction (UPLOAD, DOWNLOAD)",
    lambda ev: _extract_metadata_field(ev, "transfer_direction")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.file_name", (str, type(None)), FieldSensitivity.INTERNAL, "Sanitized filename in file transfer",
    lambda ev: _extract_metadata_field(ev, "file_name")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.file_size", (int, type(None)), FieldSensitivity.PUBLIC, "Observed file transfer size in bytes",
    lambda ev: _extract_metadata_field(ev, "file_size")
))
FieldRegistry.register_field(FieldDefinition(
    "metadata.request_pattern", (str, type(None)), FieldSensitivity.PUBLIC, "Suspicious request pattern classification",
    lambda ev: _extract_metadata_field(ev, "request_pattern")
))


