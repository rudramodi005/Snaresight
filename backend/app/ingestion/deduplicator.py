"""Deduplication and idempotency engine for SnareSight event ingestion.

Implements a layered deduplication strategy:
- Layer 1: Stable event identifier (raw_event_id).
- Layer 2: Source-scoped identification (source_id:decoy_id:raw_event_id).
- Layer 3: Deterministic SHA-256 fingerprint over immutable attributes.

Distinguishes:
- EXACT_DUPLICATE: Identical identifier and content -> Safe duplicate status.
- IDENTIFIER_COLLISION: Same identifier with conflicting content -> Conflict diagnostic.
- SIMILAR_OBSERVATION: Similar payload with distinct IDs -> Preserved as distinct events.
"""

import hashlib
import json
import uuid
from enum import Enum
from typing import Any, Tuple
from sqlalchemy.orm import Session
from app.db.models.event import SecurityEventModel, RawEventModel
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic


class DuplicateCategory(str, Enum):
    """Categorization of deduplication outcomes."""
    NONE = "none"
    EXACT_DUPLICATE = "exact_duplicate"
    IDENTIFIER_COLLISION = "identifier_collision"
    SIMILAR_OBSERVATION = "similar_observation"


class EventDeduplicator:
    """Manages layered event deduplication, collision detection, and idempotent processing."""

    @classmethod
    def compute_source_scoped_id(cls, source_id: str, decoy_id: str, raw_event_id: str) -> str:
        """Layer 2: Source-scoped identifier string."""
        return f"{source_id}:{decoy_id}:{raw_event_id}"

    @classmethod
    def compute_fingerprint(cls, event: dict[str, Any]) -> str:
        """Layer 3: Computes deterministic SHA-256 fingerprint from immutable event fields."""
        decoy_id = str(event.get("decoy_id", ""))
        observed_at = str(event.get("observed_at", ""))
        session_id = str(event.get("session_id", ""))
        raw_event_id = str(event.get("raw_event_id", event.get("event_id", "")))
        event_type = str(event.get("event_type", ""))
        
        # Extract sanitized interaction attributes (excluding passwords, auth secrets, volatile timestamps)
        interaction = event.get("interaction", {})
        sanitized_interaction = {
            k: v for k, v in interaction.items()
            if k.lower() not in {"password", "passwd", "auth_token", "secret", "timestamp", "received_at"}
        }
        interaction_serialized = json.dumps(sanitized_interaction, sort_keys=True)
        
        digest_input = f"{decoy_id}:{observed_at}:{session_id}:{raw_event_id}:{event_type}:{interaction_serialized}"
        return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

    @classmethod
    def check_duplicate(
        cls, db: Session | None, deduplication_ref: str, raw_event_id: str, current_event: dict[str, Any] | None = None
    ) -> Tuple[bool, bool, RejectionDiagnostic | None]:
        """Checks if an event is an exact duplicate, an identifier collision, or a fresh event.
        
        Returns:
            (is_duplicate: bool, is_collision: bool, diagnostic: RejectionDiagnostic | None)
        """
        if db is None:
            return False, False, None

        # 1. Check for exact deduplication reference match (Layer 3 fingerprint match)
        existing_by_ref = db.query(SecurityEventModel).filter(
            SecurityEventModel.deduplication_reference == deduplication_ref
        ).first()
        
        if existing_by_ref is not None:
            return True, False, RejectionDiagnostic(
                error_code=IngestionErrorCode.DUPLICATE_EVENT,
                rejection_category="idempotency",
                explanation=f"Exact duplicate event already processed: reference '{deduplication_ref}'",
                field_reference="deduplication_reference",
            )
            
        # 2. Check for raw_event_id collision with different fingerprint (Layer 1 collision)
        try:
            raw_uuid = uuid.UUID(raw_event_id)
        except (ValueError, TypeError):
            raw_uuid = None

        if raw_uuid:
            existing_by_id = db.query(SecurityEventModel).filter(
                SecurityEventModel.raw_event_id == raw_uuid
            ).first()
            
            if existing_by_id is not None:
                # Same raw_event_id but different fingerprint -> Material Content Collision!
                return False, True, RejectionDiagnostic(
                    error_code=IngestionErrorCode.DUPLICATE_EVENT,
                    rejection_category="identifier_collision",
                    explanation=f"raw_event_id '{raw_event_id}' conflicts with existing record having different payload",
                    field_reference="raw_event_id",
                )

        return False, False, None
