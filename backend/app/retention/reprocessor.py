"""Controlled event reprocessing service for SnareSight.

Enables safe, non-destructive re-normalization of stored Raw Events when
detection rules, normalization mappings, or taxonomy classifications are updated.
"""

import uuid
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.db.models.event import RawEventModel, SecurityEventModel
from app.ingestion.normalizer import EventNormalizer
from app.ingestion.deduplicator import EventDeduplicator


class EventReprocessingService:
    """Safe, authorized reprocessing of raw forensic events without evidence loss."""

    REPROCESSOR_VERSION = "1.0"

    @classmethod
    def preview_reprocessing(
        cls, db: Session, raw_event_ids: List[uuid.UUID] | None = None
    ) -> Dict[str, Any]:
        """Dry-run preview of candidate raw events for re-normalization."""
        query = db.query(RawEventModel)
        if raw_event_ids:
            query = query.filter(RawEventModel.raw_event_id.in_(raw_event_ids))
        candidates = query.all()

        return {
            "mode": "DRY_RUN",
            "reprocessor_version": cls.REPROCESSOR_VERSION,
            "candidate_count": len(candidates),
            "candidate_ids": [str(c.raw_event_id) for c in candidates],
        }

    @classmethod
    def execute_reprocessing(
        cls,
        db: Session,
        raw_event_ids: List[uuid.UUID] | None = None,
        authorized_by: str = "admin",
    ) -> Dict[str, Any]:
        """Safely re-normalizes raw events into updated security event records."""
        query = db.query(RawEventModel)
        if raw_event_ids:
            query = query.filter(RawEventModel.raw_event_id.in_(raw_event_ids))
        raw_records = query.all()

        processed_count = 0
        updated_count = 0
        error_count = 0

        for raw in raw_records:
            try:
                # Re-compute fingerprint and normalize
                dedup_ref = EventDeduplicator.compute_fingerprint(raw.sanitized_payload)
                normalized = EventNormalizer.normalize_event(
                    raw.sanitized_payload,
                    observed_at_dt=raw.observed_at,
                    deduplication_ref=dedup_ref,
                    received_at_dt=raw.received_at,
                )

                # Check if security_event already exists
                existing_sec = db.query(SecurityEventModel).filter(
                    SecurityEventModel.raw_event_id == raw.raw_event_id
                ).first()

                if existing_sec:
                    # Update normalized attributes without altering raw evidence or IDs
                    existing_sec.action = normalized["action"]
                    existing_sec.event_category = normalized["event_category"]
                    existing_sec.outcome = normalized["outcome"]
                    existing_sec.sanitized_metadata = normalized["sanitized_metadata"]
                    updated_count += 1
                else:
                    new_sec = SecurityEventModel(**normalized)
                    db.add(new_sec)
                    updated_count += 1

                processed_count += 1
            except Exception:
                error_count += 1

        db.commit()

        return {
            "mode": "EXECUTE",
            "authorized_by": authorized_by,
            "reprocessor_version": cls.REPROCESSOR_VERSION,
            "total_candidates": len(raw_records),
            "processed_count": processed_count,
            "updated_count": updated_count,
            "error_count": error_count,
        }

