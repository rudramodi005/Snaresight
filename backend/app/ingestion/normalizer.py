"""Centralized normalization engine converting validated Raw Events into canonical Normalized Security Events.

Coordinates specialized classification, timestamp, source, and metadata normalizers.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from app.ingestion.event_classifier import EventClassifier
from app.ingestion.timestamp_normalizer import TimestampNormalizer
from app.ingestion.source_normalizer import SourceNormalizer
from app.ingestion.metadata_normalizer import MetadataNormalizer
from app.ingestion.schema_registry import SchemaRegistry


class EventNormalizer:
    """Standardizes heterogeneous decoy telemetry into the canonical SnareSight event structure."""

    ACTION_MAP = EventClassifier.ACTION_MAP
    CATEGORY_MAP = EventClassifier.TYPE_TO_CATEGORY_MAP

    @classmethod
    def normalize_event(
        cls,
        raw_event: Dict[str, Any],
        observed_at_dt: datetime,
        deduplication_ref: str,
        received_at_dt: datetime | None = None
    ) -> Dict[str, Any]:
        """Maps validated raw event fields into the canonical Normalized Security Event contract."""
        event_type_raw = str(raw_event.get("event_type", "invalid_request"))
        source_category = raw_event.get("event_category")
        decoy_id = str(raw_event.get("decoy_id", "WEB-001"))
        session_id = str(raw_event.get("session_id", "sess_unknown"))

        # 1. Classification (Action, Category, Outcome)
        action = EventClassifier.classify_action(
            event_type_raw,
            raw_method=raw_event.get("request", {}).get("method") or raw_event.get("interaction", {}).get("method")
        )
        event_category = EventClassifier.classify_category(event_type_raw, source_category)
        
        interaction = raw_event.get("interaction", {})
        status_code = interaction.get("status_code", 200 if not interaction.get("is_authorized") is False else 401)
        outcome = EventClassifier.classify_outcome(
            status_code=status_code,
            explicit_outcome=interaction.get("outcome"),
            is_success=interaction.get("success") if "success" in interaction else None
        )

        # 2. Source and Target Information
        source_info = SourceNormalizer.normalize_source_info(raw_event, session_id)
        target_info = SourceNormalizer.normalize_target_info(raw_event, decoy_id)

        # 3. Metadata Normalization & Zero Password Protection
        sanitized_meta = MetadataNormalizer.normalize_metadata(raw_event)

        # 4. Standardized Processing Timestamps
        obs_utc, recv_utc, norm_utc = TimestampNormalizer.get_processing_timestamps(
            observed_at_dt, received_at_dt
        )

        # 5. Provenance Handling
        provenance = raw_event.get("provenance", {
            "source_classification": "HONEYPOT_DECOY",
            "environment": "isolated_lab",
            "collection_method": "decoy_logging",
        })
        if isinstance(provenance, str):
            provenance = {
                "source_classification": "HONEYPOT_DECOY",
                "environment": "isolated_lab",
                "collection_method": provenance,
            }

        # 6. Parse and ensure raw_event_id is UUID
        raw_id_val = raw_event.get("raw_event_id") or raw_event.get("event_id")
        raw_event_uuid = uuid.UUID(str(raw_id_val)) if raw_id_val else uuid.uuid4()

        return {
            "event_id": uuid.uuid4(),
            "raw_event_id": raw_event_uuid,
            "schema_version": "1.0",
            "event_type": event_type_raw.upper(),
            "event_category": event_category,
            "action": action,
            "outcome": outcome,
            "decoy_id": decoy_id,
            "session_id": session_id,
            "observed_source_id": source_info["observed_source_id"],
            "source_address": source_info["source_address"],
            "source_port": source_info["source_port"],
            "source_protocol": source_info["source_protocol"],
            "target_service": target_info["target_service"],
            "target_port": target_info["target_port"],
            "observed_at": obs_utc,
            "received_at": recv_utc,
            "normalized_at": norm_utc,
            "sanitized_metadata": sanitized_meta,
            "provenance": provenance,
            "processing_status": "PROCESSED",
            "deduplication_reference": deduplication_ref,
        }
