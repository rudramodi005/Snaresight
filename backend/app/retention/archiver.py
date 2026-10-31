"""Controlled archival engine for SnareSight security telemetry.

Exports eligible historical events to compressed JSONL packages with
cryptographic SHA-256 checksums outside git-tracked paths.
"""

import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.db.models.event import RawEventModel


class ControlledArchiver:
    """Safe, non-destructive export of historical telemetry for offsite long-term storage."""

    ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "storage", "archives")

    @classmethod
    def export_archive(
        cls,
        db: Session,
        cutoff_date: datetime,
        output_directory: str | None = None,
    ) -> Dict[str, Any]:
        """Archives raw events prior to cutoff_date into a compressed, checksummed file."""
        target_dir = output_directory or cls.ARCHIVE_DIR
        os.makedirs(target_dir, exist_ok=True)

        records = db.query(RawEventModel).filter(RawEventModel.received_at < cutoff_date).all()
        if not records:
            return {
                "record_count": 0,
                "message": "No records eligible for archival prior to cutoff date",
            }

        archive_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"snaresight_raw_events_{archive_ts}.jsonl.gz"
        archive_path = os.path.join(target_dir, filename)

        sha256_hasher = hashlib.sha256()
        exported_count = 0

        with gzip.open(archive_path, "wt", encoding="utf-8") as gz_file:
            for rec in records:
                row_dict = {
                    "raw_event_id": str(rec.raw_event_id),
                    "schema_version": rec.schema_version,
                    "event_type": rec.event_type,
                    "event_category": rec.event_category,
                    "decoy_id": rec.decoy_id,
                    "observed_at": rec.observed_at.isoformat(),
                    "received_at": rec.received_at.isoformat(),
                    "sanitized_payload": rec.sanitized_payload,
                    "provenance": rec.provenance,
                }
                serialized = json.dumps(row_dict) + "\n"
                gz_file.write(serialized)
                sha256_hasher.update(serialized.encode("utf-8"))
                exported_count += 1

        checksum = sha256_hasher.hexdigest()

        return {
            "archive_filename": filename,
            "archive_path": archive_path,
            "record_count": exported_count,
            "sha256_checksum": checksum,
            "cutoff_date": cutoff_date.isoformat(),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

