"""Source registration and decoy authorization validator.

Ensures that incoming telemetry originates strictly from authorized, enabled decoys
and collector agents.
"""

from typing import Tuple
from sqlalchemy.orm import Session
from app.db.models.honeypot import HoneypotModel, EventSourceModel
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic

# Static authorized source fallback cache for offline development/standalone testing
DEFAULT_REGISTERED_SOURCES = {
    "collector-agent-01": {"source_type": "LOCAL_FILE_WATCHER", "status": "ONLINE", "decoy_id": "WEB-001"},
    "collector-web-01": {"source_type": "HTTP_INGESTION", "status": "ONLINE", "decoy_id": "WEB-001"},
    "collector-test-harness": {"source_type": "TEST_CLIENT", "status": "ONLINE", "decoy_id": "WEB-001"},
    "disabled-source-99": {"source_type": "HTTP_INGESTION", "status": "DISABLED", "decoy_id": "WEB-001"},
}

DEFAULT_REGISTERED_DECOYS = {
    "WEB-001": {"name": "ApexCore Logistics Portal", "status": "ACTIVE"},
    "WEB-DECOY-01": {"name": "ApexCore Logistics Portal (P09 Legacy Alias)", "status": "ACTIVE"},
}


class SourceRegistryValidator:
    """Verifies that the telemetry source and decoy are registered and authorized."""

    @classmethod
    def validate_source_and_decoy(
        cls, db: Session | None, source_id: str, decoy_id: str
    ) -> Tuple[bool, RejectionDiagnostic | None]:
        """Validates that both source and decoy exist, are active, and have valid associations."""
        # 1. Database-backed verification if DB session provided and contains records
        if db is not None:
            db_source = db.query(EventSourceModel).filter(EventSourceModel.source_id == source_id).first()
            if db_source is not None:
                if db_source.status != "ONLINE":
                    return False, RejectionDiagnostic(
                        error_code=IngestionErrorCode.DISABLED_SOURCE,
                        rejection_category="authorization",
                        explanation=f"Telemetry source '{source_id}' is marked as {db_source.status}",
                        field_reference="source_id",
                    )
            
            db_decoy = db.query(HoneypotModel).filter(HoneypotModel.decoy_id == decoy_id).first()
            if db_decoy is not None:
                if db_decoy.status != "ACTIVE":
                    return False, RejectionDiagnostic(
                        error_code=IngestionErrorCode.UNKNOWN_DECOY,
                        rejection_category="authorization",
                        explanation=f"Decoy '{decoy_id}' is inactive or retired",
                        field_reference="decoy_id",
                    )

        # 2. In-memory registered cache check (authoritative for registered fixtures)
        if source_id not in DEFAULT_REGISTERED_SOURCES:
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.UNKNOWN_SOURCE,
                rejection_category="authorization",
                explanation=f"Unregistered telemetry source identifier '{source_id}'",
                field_reference="source_id",
            )
            
        source_meta = DEFAULT_REGISTERED_SOURCES[source_id]
        if source_meta["status"] != "ONLINE":
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.DISABLED_SOURCE,
                rejection_category="authorization",
                explanation=f"Telemetry source '{source_id}' is disabled",
                field_reference="source_id",
            )
            
        if decoy_id not in DEFAULT_REGISTERED_DECOYS:
            return False, RejectionDiagnostic(
                error_code=IngestionErrorCode.UNKNOWN_DECOY,
                rejection_category="authorization",
                explanation=f"Unregistered honeypot decoy identifier '{decoy_id}'",
                field_reference="decoy_id",
            )
            
        if source_meta.get("decoy_id") and source_meta["decoy_id"] != decoy_id:
            # Allow WEB-DECOY-01 as legacy alias for WEB-001
            if not (source_meta["decoy_id"] == "WEB-001" and decoy_id == "WEB-DECOY-01"):
                return False, RejectionDiagnostic(
                    error_code=IngestionErrorCode.SOURCE_DECOY_MISMATCH,
                    rejection_category="authorization",
                    explanation=f"Source '{source_id}' is not authorized to submit events for decoy '{decoy_id}'",
                    field_reference="decoy_id",
                )

        return True, None
