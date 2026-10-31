"""Event classification and consistency engine for SnareSight.

Maps and validates event types, categories, actions, outcomes, and detects contradictory
combinations across all telemetry sources.
"""

from typing import Any, Tuple
from app.ingestion.schema_registry import SchemaRegistry
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic


class EventClassifier:
    """Centralized classification taxonomy engine for cross-source event normalization."""

    # Raw event type to canonical action mapping
    ACTION_MAP = {
        "decoy_page_visited": "HTTP_GET",
        "login_attempt": "SUBMIT_CREDENTIALS",
        "simulated_decoy_access": "PORTAL_NAVIGATION",
        "invalid_request": "MALFORMED_PROBE",
        "session_terminated": "SESSION_TERMINATE",
        "session_initiated": "SESSION_INITIATE",
        "command_attempt": "COMMAND_EXECUTE",
        "file_download": "FILE_DOWNLOAD",
        "file_upload": "FILE_UPLOAD",
        "port_probe": "PORT_SCAN",
        "service_heartbeat": "SERVICE_HEARTBEAT",
    }

    # Raw event type to canonical category mapping
    TYPE_TO_CATEGORY_MAP = {
        "decoy_page_visited": "REQUEST",
        "login_attempt": "AUTHENTICATION",
        "simulated_decoy_access": "SESSION",
        "invalid_request": "REQUEST",
        "session_terminated": "SESSION",
        "session_initiated": "SESSION",
        "command_attempt": "COMMAND_INTERACTION",
        "file_download": "FILE_INTERACTION",
        "file_upload": "FILE_INTERACTION",
        "port_probe": "CONNECTION",
        "service_heartbeat": "SERVICE_HEALTH",
    }

    @classmethod
    def classify_action(cls, event_type: str, raw_method: str | None = None) -> str:
        """Determines the canonical action for an event."""
        norm_type = event_type.lower()
        if norm_type in cls.ACTION_MAP:
            return cls.ACTION_MAP[norm_type]
        if raw_method:
            method_upper = raw_method.upper()
            if method_upper == "GET":
                return "HTTP_GET"
            if method_upper == "POST":
                return "HTTP_POST"
        return "HTTP_REQUEST"

    @classmethod
    def classify_category(cls, event_type: str, source_category: str | None = None) -> str:
        """Determines the approved taxonomy category."""
        norm_type = event_type.lower()
        if norm_type in cls.TYPE_TO_CATEGORY_MAP:
            return cls.TYPE_TO_CATEGORY_MAP[norm_type]
        if source_category:
            cat_upper = source_category.upper()
            if SchemaRegistry.is_valid_category(cat_upper):
                return cat_upper
        return "REQUEST"

    @classmethod
    def classify_outcome(cls, status_code: int | None, explicit_outcome: str | None = None, is_success: bool | None = None) -> str:
        """Standardizes interaction outcomes into SUCCESS, FAILURE, BLOCKED, ERROR, UNKNOWN."""
        if explicit_outcome:
            outcome_upper = explicit_outcome.upper()
            if SchemaRegistry.is_valid_outcome(outcome_upper):
                return outcome_upper
        if is_success is not None:
            return "SUCCESS" if is_success else "FAILURE"
        if status_code is not None:
            if status_code in {200, 204}:
                return "SUCCESS"
            if status_code == 401:
                return "FAILURE"
            if status_code in {400, 403, 405, 422}:
                return "BLOCKED"
            if status_code >= 500:
                return "ERROR"
        return "UNKNOWN"

    @classmethod
    def validate_classification_consistency(
        cls,
        event_type: str,
        category: str,
        action: str,
        outcome: str,
        provenance: dict[str, Any] | str,
        interaction: dict[str, Any]
    ) -> Tuple[bool, RejectionDiagnostic | None]:
        """Verifies that category, action, outcome, and provenance do not contain contradictory combinations."""
        cat_upper = category.upper()
        type_lower = event_type.lower()
        outcome_upper = outcome.upper()

        # Rule 1: Category must match taxonomy
        if not SchemaRegistry.is_valid_category(cat_upper):
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="classification",
                explanation=f"Unsupported event category '{category}'",
                field_reference="event_category",
            )

        # Rule 2: Authentication failure cannot have SUCCESS outcome
        if type_lower == "login_attempt" and cat_upper == "AUTHENTICATION":
            # In decoy logins, authentication into real systems never succeeds
            # Decoy simulation outcome can be 'simulated_success', but real outcome remains FAILURE/BLOCKED
            if outcome_upper == "SUCCESS" and not interaction.get("is_authorized", False):
                return False, RejectionDiagnostic(
                    error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                    rejection_category="classification_contradiction",
                    explanation="Authentication attempt on decoy cannot be classified as SUCCESS",
                    field_reference="outcome",
                )

        # Rule 3: Artificial simulation must not claim live provenance
        prov_dict = provenance if isinstance(provenance, dict) else {"collection_method": str(provenance)}
        env = str(prov_dict.get("environment", "")).lower()
        method = str(prov_dict.get("collection_method", "")).lower()
        
        if env == "simulation" or "simulation" in method or "synthetic" in method:
            if env == "production" or method == "live_honeypot":
                return False, RejectionDiagnostic(
                    error_code=IngestionErrorCode.INVALID_PROVENANCE,
                    rejection_category="provenance_contradiction",
                    explanation="Simulation telemetry cannot be classified as production or live_honeypot",
                    field_reference="provenance",
                )

        return True, None

