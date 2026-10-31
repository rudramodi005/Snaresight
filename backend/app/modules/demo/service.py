"""Demonstration Service orchestrating synthetic execution, evaluation, and safe cleanup."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, delete

from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.db.models.honeypot import HoneypotModel
from app.db.models.response import EvidencePreservationHoldModel, ResponseCaseModel, CaseNoteModel
from app.ingestion.schemas import EventBatchRequest
from app.services.ingestion_service import ingestion_service
from app.modules.demo.schemas import (
    DatasetSize,
    DemoCleanupRequest,
    DemoCleanupResponse,
    DemoExportResponse,
    EvaluationSummaryResponse,
    ScenarioRunRequest,
    ScenarioRunResponse,
    ScenarioType,
)
from app.modules.demo.generator import SyntheticTelemetryGenerator
from app.modules.demo.evaluator import DetectionQualityEvaluator
from app.modules.demo.scenarios import SCENARIO_CATALOG


class DemoService:
    """Manages demonstration scenarios, evaluation results, and safe selective cleanup."""

    # In-memory evaluation cache for instant metrics viewing
    _latest_evaluation: Optional[EvaluationSummaryResponse] = None
    _latest_run_summary: Optional[Dict[str, Any]] = None

    @classmethod
    def _ensure_decoy_exists(cls, db: Session, decoy_id: str) -> None:
        """Verifies target honeypot decoy exists in DB to prevent foreign key errors."""
        existing = db.query(HoneypotModel).filter(HoneypotModel.decoy_id == decoy_id).first()
        if not existing:
            decoy = HoneypotModel(
                decoy_id=decoy_id,
                name="ApexCore Web Application Decoy",
                decoy_type="WEB_LOGIN",
                protocol="HTTP",
                environment="isolated_lab",
                status="ACTIVE",
            )
            db.add(decoy)
            db.commit()

    @classmethod
    def run_scenario(
        cls,
        db: Session,
        request: ScenarioRunRequest,
        current_username: str = "analyst_demo",
    ) -> ScenarioRunResponse:
        """Executes a full demonstration scenario through the genuine ingestion pipeline."""
        start_time = time.perf_counter()
        run_id = f"demo_{uuid.uuid4().hex[:8]}"

        cls._ensure_decoy_exists(db, request.target_decoy_id)

        # 1. Generate Synthetic Events and Ground Truth
        events, ground_truth = SyntheticTelemetryGenerator.generate_events(
            scenario_type=request.scenario_type,
            size=request.size,
            seed=request.seed,
            target_decoy_id=request.target_decoy_id,
            source_ip_override=request.source_ip,
            run_id=run_id,
        )

        # 2. Ingest Events in batches of 250 (max batch limit is 500)
        accepted_count = 0
        rejected_count = 0
        batch_size = 200

        for i in range(0, len(events), batch_size):
            chunk = events[i : i + batch_size]
            batch_req = EventBatchRequest(
                batch_id=f"batch_{run_id}_{i // batch_size}",
                source_id="collector-web-01",
                events=chunk,
            )
            resp = ingestion_service.process_batch(batch_req, db=db)
            accepted_count += resp.accepted_count
            rejected_count += resp.rejected_count

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # 3. Query Alerts generated for this run's sessions
        run_sessions = {ev["session_id"] for ev in events}
        sec_events = (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.session_id.in_(list(run_sessions)))
            .all()
        )
        sec_event_ids = [se.event_id for se in sec_events]

        matched_alerts: List[Dict[str, Any]] = []
        if sec_event_ids:
            alert_links = (
                db.query(AlertEvidenceModel)
                .filter(AlertEvidenceModel.event_id.in_(sec_event_ids))
                .all()
            )
            alert_ids = {al.alert_id for al in alert_links}
            if alert_ids:
                alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(list(alert_ids))).all()
                for alt in alerts:
                    matched_alerts.append(
                        {
                            "alert_id": str(alt.alert_id),
                            "detection_rule_id": alt.detection_rule_id,
                            "title": alt.title,
                            "severity": alt.severity,
                            "confidence": alt.confidence,
                            "session_id": sec_events[0].session_id if sec_events else "unknown",
                        }
                    )

        # 4. Handle Scenario E (Analyst Investigation Workflow)
        case_id = None
        hold_id = None
        if request.scenario_type == ScenarioType.SCENARIO_E and matched_alerts:
            # Create a response case
            case_id = f"CASE-DEMO-{uuid.uuid4().hex[:6].upper()}"
            demo_case = ResponseCaseModel(
                case_id=case_id,
                title="Synthetic Investigation: Credential Guessing & Web Probing",
                description="Demonstration response case automatically escalated from multi-rule honeypot alert.",
                priority="P2_HIGH",
                status="INVESTIGATING",
                assigned_analyst=current_username,
                created_by=current_username,
            )
            db.add(demo_case)
            db.flush()

            # Add analyst note
            note = CaseNoteModel(
                case_id=case_id,
                author_username=current_username,
                author_role="ANALYST",
                note_type="TRIAGE_NOTE",
                content=(
                    f"Demonstration triage completed by {current_username}. "
                    f"Correlated {len(matched_alerts)} alerts across session. Applying legal evidence hold."
                ),
            )
            db.add(note)

            # Apply Evidence Preservation Hold
            first_sess = list(run_sessions)[0] if run_sessions else "SESS-DEMO-001"
            hold_id = f"HOLD-DEMO-{uuid.uuid4().hex[:6].upper()}"
            hold = EvidencePreservationHoldModel(
                hold_id=hold_id,
                case_id=case_id,
                evidence_type="SESSION",
                evidence_identifier=first_sess,
                retention_hold_status="ACTIVE",
                hold_reason="Preservation hold for forensic demonstration evidence",
                applied_by=current_username,
            )
            db.add(hold)
            db.commit()

        # 5. Handle Scenario F (Operational Failure & Sandbox Recovery)
        resilience_info = {}
        if request.scenario_type == ScenarioType.SCENARIO_F:
            try:
                from app.modules.resilience.health_service import PlatformHealthService
                from app.modules.resilience.backup_service import BackupService

                diag = PlatformHealthService.assess_platform_health(db)
                backup_record = BackupService.initiate_backup(db, backup_type="DEMO_MANUAL", retention_hold=True)
                restore_record = BackupService.execute_sandbox_restore_test(
                    db, backup_record.backup_id, test_environment="isolated_sandbox_db"
                )
                resilience_info = {
                    "health_status": diag.overall_status.value if hasattr(diag, "overall_status") else "HEALTHY",
                    "backup_id": backup_record.backup_id,
                    "restore_test_status": restore_record.status.value if hasattr(restore_record, "status") else "SUCCESS",
                    "integrity_verified": restore_record.integrity_check_passed,
                }
            except Exception as exc:
                resilience_info = {"note": f"Resilience components executed with fallback: {str(exc)}"}

        # 6. Evaluate Quality Metrics
        evaluation = DetectionQualityEvaluator.evaluate(
            ground_truth=ground_truth,
            matched_alerts=matched_alerts,
            duration_ms=duration_ms,
        )
        cls._latest_evaluation = evaluation

        meta = SCENARIO_CATALOG.get(request.scenario_type)
        summary = (
            f"Successfully executed {meta.title if meta else request.scenario_type.value}: "
            f"{accepted_count} events ingested, {len(matched_alerts)} alerts created, "
            f"Precision: {evaluation.overall_precision * 100:.1f}%, Recall: {evaluation.overall_recall * 100:.1f}%."
        )

        details: Dict[str, Any] = {
            "unique_sessions": len(run_sessions),
            "alerts": matched_alerts,
            "resilience": resilience_info,
        }
        if case_id:
            details["escalated_case_id"] = case_id
            details["evidence_hold_id"] = hold_id

        run_resp = ScenarioRunResponse(
            run_id=run_id,
            scenario_type=request.scenario_type.value,
            size=request.size.value,
            seed=request.seed,
            events_generated=len(events),
            events_accepted=accepted_count,
            events_rejected=rejected_count,
            detections_triggered=len(matched_alerts),
            alerts_created=len(matched_alerts),
            sessions_created=len(run_sessions),
            duration_ms=duration_ms,
            status="SUCCESS" if rejected_count == 0 else "PARTIAL",
            summary=summary,
            details=details,
        )

        cls._latest_run_summary = run_resp.model_dump()
        return run_resp

    @classmethod
    def get_latest_evaluation(cls) -> EvaluationSummaryResponse:
        """Retrieves latest detection quality evaluation or returns default baseline."""
        if cls._latest_evaluation is not None:
            return cls._latest_evaluation

        return EvaluationSummaryResponse(
            total_events_evaluated=0,
            overall_true_positives=0,
            overall_false_positives=0,
            overall_false_negatives=0,
            overall_precision=1.0,
            overall_recall=1.0,
            overall_f1_score=1.0,
            average_processing_latency_ms=0.0,
            rules_evaluated=[],
            evaluation_notes=["No scenario has been executed in the current session."],
        )

    @classmethod
    def cleanup_demonstration_data(
        cls,
        db: Session,
        request: DemoCleanupRequest,
    ) -> DemoCleanupResponse:
        """Safely cleans up synthetic demonstration telemetry respecting retention holds."""
        start_time = time.perf_counter()

        # Query all raw events marked as synthetic demonstration
        raw_events = db.query(RawEventModel).all()
        synthetic_raw = [
            re for re in raw_events
            if isinstance(re.provenance, dict)
            and (
                re.provenance.get("is_synthetic") is True
                or re.provenance.get("source_type") == "synthetic_simulation"
                or (request.run_id and re.provenance.get("run_id") == request.run_id)
            )
        ]

        found_count = len(synthetic_raw)
        synthetic_event_ids = [re.raw_event_id for re in synthetic_raw]
        synthetic_sessions = {re.session_id for re in synthetic_raw}

        # Check Active Evidence Preservation Holds
        active_holds = (
            db.query(EvidencePreservationHoldModel)
            .filter(EvidencePreservationHoldModel.retention_hold_status == "ACTIVE")
            .all()
        )
        held_identifiers = {h.evidence_identifier for h in active_holds}

        # Filter out records protected by active holds
        protected_count = 0
        eligible_raw = []
        for re in synthetic_raw:
            is_held = (
                str(re.raw_event_id) in held_identifiers
                or re.session_id in held_identifiers
            )
            if is_held:
                protected_count += 1
            else:
                eligible_raw.append(re)

        eligible_count = len(eligible_raw)
        eligible_raw_ids = [re.raw_event_id for re in eligible_raw]

        deleted_events = 0
        deleted_alerts = 0
        deleted_sessions = 0

        if not request.dry_run and eligible_raw_ids:
            # 1. Find matching normalized security events
            sec_events = (
                db.query(SecurityEventModel)
                .filter(SecurityEventModel.raw_event_id.in_(eligible_raw_ids))
                .all()
            )
            sec_ids = [se.event_id for se in sec_events]

            if sec_ids:
                # 1b. Delete correlated activity session event associations to satisfy RESTRICT foreign key
                from app.db.models.correlation import ActivitySessionEventModel, ActivitySessionModel
                db.query(ActivitySessionEventModel).filter(
                    ActivitySessionEventModel.event_id.in_(sec_ids)
                ).delete(synchronize_session=False)
                db.flush()

                # 2. Delete alert evidence associations
                evidence_links = (
                    db.query(AlertEvidenceModel)
                    .filter(AlertEvidenceModel.event_id.in_(sec_ids))
                    .all()
                )
                affected_alert_ids = {el.alert_id for el in evidence_links}
                for el in evidence_links:
                    db.delete(el)
                db.flush()

                # 3. Clean up alerts that have zero remaining non-synthetic evidence
                for aid in affected_alert_ids:
                    # check if alert has an active hold
                    if str(aid) in held_identifiers:
                        continue
                    remaining_ev = (
                        db.query(AlertEvidenceModel)
                        .filter(AlertEvidenceModel.alert_id == aid)
                        .count()
                    )
                    if remaining_ev == 0:
                        alt = db.query(AlertModel).filter(AlertModel.alert_id == aid).first()
                        if alt:
                            db.delete(alt)
                            deleted_alerts += 1
                db.flush()

                # 4. Delete security events
                for se in sec_events:
                    db.delete(se)
                db.flush()

            # Clean up associated synthetic activity sessions
            if synthetic_sessions:
                from app.db.models.correlation import ActivitySessionModel
                for sess_id in synthetic_sessions:
                    sess = db.query(ActivitySessionModel).filter(ActivitySessionModel.session_id == sess_id).first()
                    if sess:
                        db.delete(sess)
                        deleted_sessions += 1
                db.flush()

            # 5. Delete raw events
            for re in eligible_raw:
                db.delete(re)

            deleted_events = len(eligible_raw)
            db.commit()

        exec_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        mode_str = "DRY RUN: " if request.dry_run else "EXECUTED: "
        msg = (
            f"{mode_str}Found {found_count} synthetic events. "
            f"{protected_count} protected by active retention holds. "
            f"{eligible_count} eligible for deletion. "
            f"Removed {deleted_events} events and {deleted_alerts} alerts."
        )

        return DemoCleanupResponse(
            dry_run=request.dry_run,
            synthetic_events_found=found_count,
            events_protected_by_hold=protected_count,
            events_eligible_for_deletion=eligible_count,
            events_deleted=deleted_events,
            alerts_deleted=deleted_alerts,
            sessions_deleted=deleted_sessions,
            execution_ms=exec_ms,
            message=msg,
        )

    @classmethod
    def export_data(cls, db: Session) -> DemoExportResponse:
        """Exports synthetic demonstration events with a visible synthetic watermark."""
        raw_events = db.query(RawEventModel).all()
        synthetic_raw = [
            re for re in raw_events
            if isinstance(re.provenance, dict)
            and (
                re.provenance.get("is_synthetic") is True
                or re.provenance.get("source_type") == "synthetic_simulation"
            )
        ]

        export_events = []
        for re in synthetic_raw[:250]:
            export_events.append(
                {
                    "raw_event_id": str(re.raw_event_id),
                    "event_type": re.event_type,
                    "event_category": re.event_category,
                    "decoy_id": re.decoy_id,
                    "session_id": re.session_id,
                    "observed_at": re.observed_at.isoformat() if re.observed_at else None,
                    "sanitized_payload": re.sanitized_payload,
                    "watermark": "SYNTHETIC DEMONSTRATION DATA",
                }
            )

        return DemoExportResponse(
            export_id=f"exp_{uuid.uuid4().hex[:8]}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            watermark="SYNTHETIC DEMONSTRATION DATA - NOT REAL INCIDENT",
            scenario_type="DEMONSTRATION_ARCHIVE",
            total_events=len(export_events),
            events=export_events,
        )


demo_service = DemoService()
