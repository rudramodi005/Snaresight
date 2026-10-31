"""Telemetry validation engine for SnareSight event ingestion.

Validates schema conformity, UTC timestamp boundaries, and identifier conventions.
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Any, Tuple
from uuid import UUID
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic

# Strict session identifier pattern
SESSION_REGEX = re.compile(r"^decoy_sess_[a-f0-9]{32}$")

# Allowed provenance enums
ALLOWED_SOURCE_TYPES = {"live_honeypot", "controlled_test", "synthetic_simulation", "imported_data"}
ALLOWED_ENVIRONMENTS = {"isolated_lab", "demo_sandbox", "production"}

# Timestamp skew tolerance (5 minutes into the future max)
MAX_FUTURE_TOLERANCE_SECONDS = 300


class TelemetryValidator:
    """Validates raw incoming telemetry against P11 contracts."""

    @classmethod
    def parse_and_validate_timestamp(cls, timestamp_str: Any) -> Tuple[datetime | None, RejectionDiagnostic | None]:
        """Validates that a timestamp is a valid UTC ISO-8601 string within acceptable clock skew."""
        if not timestamp_str or not isinstance(timestamp_str, str):
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_TIMESTAMP,
                rejection_category="timestamp",
                explanation="Missing or non-string timestamp",
                field_reference="observed_at",
            )
        
        try:
            # Parse ISO-8601 string
            parsed_dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_TIMESTAMP,
                rejection_category="timestamp",
                explanation=f"Malformed ISO-8601 timestamp: {str(exc)}",
                field_reference="observed_at",
            )
        
        # Enforce UTC timezone presence
        if parsed_dt.tzinfo is None:
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_TIMESTAMP,
                rejection_category="timestamp",
                explanation="Timestamp lacks timezone offset; strict UTC required",
                field_reference="observed_at",
            )
        
        # Check future timestamp anomaly
        now_utc = datetime.now(timezone.utc)
        if parsed_dt > now_utc + timedelta(seconds=MAX_FUTURE_TOLERANCE_SECONDS):
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.FUTURE_TIMESTAMP_ANOMALY,
                rejection_category="timestamp_skew",
                explanation="Timestamp is positioned excessively in the future (>5 min clock skew)",
                field_reference="observed_at",
            )
            
        return parsed_dt.astimezone(timezone.utc), None

    @classmethod
    def validate_raw_event_structure(cls, event: dict[str, Any]) -> Tuple[bool, RejectionDiagnostic | None]:
        """Validates mandatory top-level fields, UUID formats, and provenance."""
        # 0. Backward-compatibility: map event_id to raw_event_id if needed
        if "raw_event_id" not in event and "event_id" in event:
            event["raw_event_id"] = event["event_id"]

        # 1. Required top-level fields
        required_fields = ["raw_event_id", "schema_version", "event_type", "observed_at", "decoy_id", "session_id", "provenance"]
        for field in required_fields:
            if field not in event or event[field] is None:
                return False, RejectionDiagnostic(
                    error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                    rejection_category="schema_contract",
                    explanation=f"Missing mandatory field '{field}'",
                    field_reference=field,
                )
        
        # 2. Schema version check
        if str(event.get("schema_version")) != "1.0":
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.UNSUPPORTED_SCHEMA_VERSION,
                rejection_category="versioning",
                explanation=f"Unsupported schema version '{event.get('schema_version')}'; expected '1.0'",
                field_reference="schema_version",
            )
            
        # 3. UUIDv4 format check
        try:
            UUID(str(event["raw_event_id"]))
        except (ValueError, AttributeError):
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="identifier",
                explanation="raw_event_id is not a valid UUIDv4 string",
                field_reference="raw_event_id",
            )
            
        # 4. Session ID pattern check
        session_id = str(event.get("session_id", ""))
        if not SESSION_REGEX.match(session_id):
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="session",
                explanation=f"session_id does not conform to regex pattern: '{session_id}'",
                field_reference="session_id",
            )
            
        # 5. Provenance validation
        prov = event.get("provenance")
        if not isinstance(prov, dict):
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_PROVENANCE,
                rejection_category="provenance",
                explanation="provenance block must be an object",
                field_reference="provenance",
            )
            
        source_type = prov.get("source_type")
        if source_type not in ALLOWED_SOURCE_TYPES:
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_PROVENANCE,
                rejection_category="provenance",
                explanation=f"Invalid provenance source_type '{source_type}'",
                field_reference="provenance.source_type",
            )
            
        environment = prov.get("environment")
        if environment not in ALLOWED_ENVIRONMENTS:
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_PROVENANCE,
                rejection_category="provenance",
                explanation=f"Invalid provenance environment '{environment}'",
                field_reference="provenance.environment",
            )

        return True, None
