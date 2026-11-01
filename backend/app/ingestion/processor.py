"""Event processing orchestrator executing transactional ingestion, validation, and persistence."""

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.honeypot import HoneypotModel
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic
from app.ingestion.schemas import EventProcessingResult, EventProcessingStatus
from app.ingestion.sanitizer import SensitiveDataInspector
from app.ingestion.validators import TelemetryValidator
from app.ingestion.source_registry import SourceRegistryValidator
from app.ingestion.deduplicator import EventDeduplicator
from app.ingestion.normalizer import EventNormalizer


class EventProcessor:
    """Processes incoming raw telemetry records individually with strict transactional boundaries."""

    @classmethod
    def process_single_event(
        cls, db: Session | None, event: dict[str, Any], source_id: str
    ) -> EventProcessingResult:
        """Processes one raw event record through validation, sanitization, deduplication, and persistence."""
        # Backward-compatibility: map legacy event_id to raw_event_id if needed
        if "raw_event_id" not in event and "event_id" in event:
            event["raw_event_id"] = event["event_id"]
            
        raw_event_id_str = str(event.get("raw_event_id", ""))
        
        # 1. Sensitive Data Inspection (Strict Zero Password Invariant)
        is_safe, privacy_diag = SensitiveDataInspector.inspect_record(event)
        if not is_safe:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.REJECTED,
                error=privacy_diag,
            )
            
        # 2. Schema and Structure Validation
        is_valid_struct, struct_diag = TelemetryValidator.validate_raw_event_structure(event)
        if not is_valid_struct:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.REJECTED,
                error=struct_diag,
            )
            
        # 3. Timestamp Validation & Boundary Check
        observed_at_dt, time_diag = TelemetryValidator.parse_and_validate_timestamp(event.get("observed_at"))
        if time_diag is not None:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.REJECTED,
                error=time_diag,
            )
            
        # 4. Source and Decoy Authorization Check
        decoy_id = str(event.get("decoy_id", ""))
        is_auth, auth_diag = SourceRegistryValidator.validate_source_and_decoy(db, source_id, decoy_id)
        if not is_auth:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.REJECTED,
                error=auth_diag,
            )
            
        # 5. Deduplication and Collision Check
        dedup_ref = EventDeduplicator.compute_fingerprint(event)
        is_dup, is_collision, dup_diag = EventDeduplicator.check_duplicate(db, dedup_ref, raw_event_id_str)
        if is_dup:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.DUPLICATE,
                deduplication_reference=dedup_ref,
                error=dup_diag,
            )
        if is_collision:
            return EventProcessingResult(
                raw_event_id=raw_event_id_str,
                status=EventProcessingStatus.REJECTED,
                deduplication_reference=dedup_ref,
                error=dup_diag,
            )
            
        # 6. Normalization
        normalized_data = EventNormalizer.normalize_event(event, observed_at_dt, dedup_ref)
        
        # 7. Database Persistence (Transactional per-record boundary)
        if db is not None:
            try:
                # Ensure referenced decoy exists in DB to satisfy foreign key
                existing_decoy = db.query(HoneypotModel).filter(HoneypotModel.decoy_id == decoy_id).first()
                if not existing_decoy:
                    db_decoy = HoneypotModel(
                        decoy_id=decoy_id,
                        name=f"Decoy {decoy_id}",
                        decoy_type="WEB_LOGIN" if decoy_id.startswith("WEB") else "SSH_DAEMON",
                        protocol="HTTP" if decoy_id.startswith("WEB") else "SSH",
                        environment=event["provenance"]["environment"],
                        status="ACTIVE"
                    )
                    db.add(db_decoy)
                    db.flush()

                # Persist Raw Event Record
                raw_model = RawEventModel(
                    raw_event_id=uuid.UUID(raw_event_id_str),
                    schema_version="1.0",
                    event_type=str(event["event_type"]),
                    event_category=str(event.get("event_category", "request")),
                    decoy_id=decoy_id,
                    event_source_id=source_id,
                    session_id=str(event["session_id"]),
                    observed_at=observed_at_dt,
                    received_at=datetime.now(timezone.utc),
                    sanitized_payload=event,
                    provenance=event["provenance"],
                    validation_status="VALID",
                )
                db.add(raw_model)
                db.flush()
                
                # Persist Normalized Event Record
                sec_model = SecurityEventModel(**normalized_data)
                db.add(sec_model)
                db.commit()

                # Post-Commit Real-Time Notification Publishing
                try:
                    from app.streaming.event_publisher import event_publisher
                    event_publisher.publish_persisted_event(normalized_data, observed_at=observed_at_dt)
                except Exception:
                    # Security invariant: Streaming notification failures must never roll back persistent DB state
                    pass

                # Post-Commit Session Correlation (Task P21)
                try:
                    from app.correlation.engine import correlation_engine
                    correlation_engine.correlate_event(db=db, event=normalized_data)
                except Exception:
                    # Security invariant: Correlation errors must never cause an already ingested event to be lost
                    pass

                # Post-Commit Detection Engine Evaluation
                try:
                    from app.detection.engine import detection_engine
                    detection_results = detection_engine.evaluate_event(normalized_data, db=db)
                    for det_res in detection_results:
                        if getattr(det_res, "evaluation_status", None) and det_res.evaluation_status.value == "MATCHED":
                            try:
                                from app.services.threat_assessment_service import threat_assessment_service
                                from app.services.alert_service import alert_service
                                threat_assessment_service.assess_detection(
                                    detection_result=det_res,
                                    event=normalized_data,
                                    db=db,
                                )
                                alert_service.create_alert(
                                    db=db,
                                    detection_result=det_res,
                                    event=normalized_data,
                                )
                                # Post-Alert Sequence Correlation (Task P22)
                                try:
                                    from app.modules.correlation.sequence_engine import default_sequence_engine
                                    default_sequence_engine.evaluate_session(db=db, session_id=str(normalized_data["session_id"]))
                                except Exception:
                                    pass
                            except Exception:
                                pass
                except Exception:
                    # Security invariant: Detection evaluation errors must never roll back or destroy persisted event state
                    pass
                
            except Exception as exc:
                db.rollback()
                return EventProcessingResult(
                    raw_event_id=raw_event_id_str,
                    status=EventProcessingStatus.FAILED,
                    error=RejectionDiagnostic(
                        error_code=IngestionErrorCode.DATABASE_TRANSACTION_ERROR,
                        rejection_category="storage",
                        explanation=f"Transactional write failed: {str(exc)}",
                        field_reference="database",
                    )
                )

        return EventProcessingResult(
            raw_event_id=raw_event_id_str,
            status=EventProcessingStatus.ACCEPTED,
            deduplication_reference=dedup_ref,
            normalized_event_id=str(normalized_data["event_id"]),
        )
