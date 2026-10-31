"""Controlled JSONL file importer for SnareSight honeypot telemetry exports."""

import json
from pathlib import Path
from typing import Any, Tuple
from sqlalchemy.orm import Session
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic
from app.ingestion.schemas import EventProcessingResult, EventProcessingStatus
from app.ingestion.processor import EventProcessor

# Importer boundaries
MAX_ALLOWED_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ALLOWED_LINES_PER_FILE = 5000


class JsonlTelemetryImporter:
    """Safe, bounded importer for offline or batch honeypot JSONL logs."""

    @classmethod
    def validate_file_path(cls, file_path_str: str) -> Tuple[Path | None, RejectionDiagnostic | None]:
        """Prevents path traversal attacks and verifies safe file bounds."""
        target_path = Path(file_path_str).resolve()
        
        # 1. Enforce .jsonl file extension
        if target_path.suffix.lower() != ".jsonl":
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="file_format",
                explanation=f"Unsupported file extension '{target_path.suffix}'; strictly .jsonl required",
                field_reference="file_path",
            )
            
        # 2. Check file existence
        if not target_path.exists() or not target_path.is_file():
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="file_access",
                explanation=f"Target file does not exist or is not a regular file: '{target_path.name}'",
                field_reference="file_path",
            )
            
        # 3. Path traversal safety check (must not be system critical directories)
        resolved_str = str(target_path).lower()
        if "system32" in resolved_str or "windows" in resolved_str and "projects" not in resolved_str:
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.PATH_TRAVERSAL_DETECTED,
                rejection_category="security_boundary",
                explanation="Access to restricted system directories is forbidden",
                field_reference="file_path",
            )
            
        # 4. Enforce file size boundary
        file_size = target_path.stat().st_size
        if file_size > MAX_ALLOWED_FILE_SIZE_BYTES:
            return None, RejectionDiagnostic(
                error_code=IngestionErrorCode.OVERSIZED_FILE,
                rejection_category="boundary",
                explanation=f"File size {file_size} bytes exceeds limit of {MAX_ALLOWED_FILE_SIZE_BYTES} bytes",
                field_reference="file_size",
            )
            
        return target_path, None

    @classmethod
    def import_file(
        cls, db: Session | None, file_path_str: str, source_id: str = "collector-agent-01"
    ) -> dict[str, Any]:
        """Imports and validates records line-by-line from a JSONL export."""
        path, diag = cls.validate_file_path(file_path_str)
        if diag is not None:
            return {
                "file_path": file_path_str,
                "status": "FAILED",
                "error": diag.model_dump(),
                "total_records": 0,
                "accepted_count": 0,
                "duplicate_count": 0,
                "rejected_count": 0,
                "results": [],
            }
            
        results: list[EventProcessingResult] = []
        accepted = 0
        duplicates = 0
        rejected = 0
        
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                if line_no > MAX_ALLOWED_LINES_PER_FILE:
                    results.append(
                        EventProcessingResult(
                            status=EventProcessingStatus.REJECTED,
                            error=RejectionDiagnostic(
                                error_code=IngestionErrorCode.OVERSIZED_BATCH,
                                rejection_category="boundary",
                                explanation=f"Line count exceeds maximum threshold of {MAX_ALLOWED_LINES_PER_FILE}",
                                field_reference="line_number",
                            )
                        )
                    )
                    rejected += 1
                    break
                    
                stripped = line.strip()
                if not stripped:
                    continue  # Safely skip blank lines
                    
                # 1. Parse JSON line
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    results.append(
                        EventProcessingResult(
                            status=EventProcessingStatus.REJECTED,
                            error=RejectionDiagnostic(
                                error_code=IngestionErrorCode.MALFORMED_JSON,
                                rejection_category="json_syntax",
                                explanation=f"Line {line_no} malformed JSON: {str(exc)}",
                                field_reference="line",
                            )
                        )
                    )
                    rejected += 1
                    continue
                    
                # 2. Process record independently
                result = EventProcessor.process_single_event(db, record, source_id)
                results.append(result)
                
                if result.status == EventProcessingStatus.ACCEPTED:
                    accepted += 1
                elif result.status == EventProcessingStatus.DUPLICATE:
                    duplicates += 1
                else:
                    rejected += 1
                    
        return {
            "file_path": str(path),
            "status": "COMPLETED",
            "total_records": len(results),
            "accepted_count": accepted,
            "duplicate_count": duplicates,
            "rejected_count": rejected,
            "results": [r.model_dump() for r in results],
        }

