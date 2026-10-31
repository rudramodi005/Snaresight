"""Controlled Retention Execution Service for SnareSight.

Implements safe, bounded, dry-run-first data lifecycle management with explicit
authorization guards, preservation holds, and audit recording.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.db.models.event import RawEventModel, SecurityEventModel
from app.db.models.alert import AlertModel
from app.retention.config import RetentionPolicyConfig, retention_config
from app.retention.calculator import RetentionCalculator
from app.retention.preservation import EvidencePreservationService, preservation_service
from app.retention.audit import RetentionAuditTracker, retention_audit_tracker


class RetentionService:
    """Coordinates identification, preview, and safe authorized execution of retention cleanup."""

    BATCH_SIZE = 500
    REQUIRED_EXECUTION_TOKEN = "CONFIRM_RETENTION_DELETION"

    def __init__(
        self,
        config: RetentionPolicyConfig | None = None,
        preservation: EvidencePreservationService | None = None,
        audit: RetentionAuditTracker | None = None,
    ) -> None:
        self.config = config or retention_config
        self.preservation = preservation or preservation_service
        self.audit = audit or retention_audit_tracker

    def preview_retention(
        self,
        db: Session | None,
        categories: List[str] | None = None,
        as_of_time: datetime | None = None,
    ) -> Dict[str, Any]:
        """Dry-run preview: Identifies expired candidate records without making any database changes."""
        return self._evaluate_retention(
            db=db,
            categories=categories or ["RAW_EVENTS", "NORMALIZED_EVENTS", "ALERTS"],
            as_of_time=as_of_time,
            dry_run=True,
            initiated_by="analyst_preview",
        )

    def execute_retention(
        self,
        db: Session,
        authorization_token: str,
        initiated_by: str,
        categories: List[str] | None = None,
        as_of_time: datetime | None = None,
    ) -> Dict[str, Any]:
        """Executes actual deletion of expired, unpreserved records. Requires explicit authorization token."""
        if authorization_token != self.REQUIRED_EXECUTION_TOKEN:
            raise PermissionError(
                "Destructive retention deletion rejected: Missing or invalid authorization token"
            )

        return self._evaluate_retention(
            db=db,
            categories=categories or ["RAW_EVENTS", "NORMALIZED_EVENTS", "ALERTS"],
            as_of_time=as_of_time,
            dry_run=False,
            initiated_by=initiated_by,
        )

    def _evaluate_retention(
        self,
        db: Session | None,
        categories: List[str],
        as_of_time: datetime | None,
        dry_run: bool,
        initiated_by: str,
    ) -> Dict[str, Any]:
        """Internal worker evaluating expired records with dry-run or execution mode."""
        candidate_count = 0
        preserved_count = 0
        deleted_count = 0
        failure_count = 0
        category_breakdown: Dict[str, Dict[str, int]] = {}

        now_utc = as_of_time or datetime.now(timezone.utc)

        if db is not None:
            # 1. Evaluate Normalized Events (SECURITY_EVENTS)
            if "NORMALIZED_EVENTS" in categories:
                sec_candidates, sec_preserved, sec_deleted, sec_fails = self._process_security_events(
                    db, now_utc, dry_run
                )
                category_breakdown["NORMALIZED_EVENTS"] = {
                    "candidates": sec_candidates,
                    "preserved": sec_preserved,
                    "deleted": sec_deleted,
                    "failures": sec_fails,
                }
                candidate_count += sec_candidates
                preserved_count += sec_preserved
                deleted_count += sec_deleted
                failure_count += sec_fails

            # 2. Evaluate Raw Events (RAW_EVENTS)
            if "RAW_EVENTS" in categories:
                raw_candidates, raw_preserved, raw_deleted, raw_fails = self._process_raw_events(
                    db, now_utc, dry_run
                )
                category_breakdown["RAW_EVENTS"] = {
                    "candidates": raw_candidates,
                    "preserved": raw_preserved,
                    "deleted": raw_deleted,
                    "failures": raw_fails,
                }
                candidate_count += raw_candidates
                preserved_count += raw_preserved
                deleted_count += raw_deleted
                failure_count += raw_fails

            # 3. Evaluate Alerts (ALERTS)
            if "ALERTS" in categories:
                alt_candidates, alt_preserved, alt_deleted, alt_fails = self._process_alerts(
                    db, now_utc, dry_run
                )
                category_breakdown["ALERTS"] = {
                    "candidates": alt_candidates,
                    "preserved": alt_preserved,
                    "deleted": alt_deleted,
                    "failures": alt_fails,
                }
                candidate_count += alt_candidates
                preserved_count += alt_preserved
                deleted_count += alt_deleted
                failure_count += alt_fails

        status = "SUCCESS" if failure_count == 0 else ("PARTIAL" if deleted_count > 0 else "FAILED")

        # Record audit log
        audit_record = self.audit.log_operation(
            initiated_by=initiated_by,
            policy_version=self.config.POLICY_VERSION,
            categories_evaluated=categories,
            mode="DRY_RUN" if dry_run else "EXECUTE",
            candidate_count=candidate_count,
            preserved_count=preserved_count,
            deleted_count=deleted_count,
            failure_count=failure_count,
            completion_status=status,
        )

        return {
            "operation_id": audit_record.operation_id,
            "mode": "DRY_RUN" if dry_run else "EXECUTE",
            "candidate_count": candidate_count,
            "preserved_count": preserved_count,
            "deleted_count": deleted_count,
            "failure_count": failure_count,
            "status": status,
            "category_breakdown": category_breakdown,
        }

    def _process_security_events(
        self, db: Session, now_utc: datetime, dry_run: bool
    ) -> tuple[int, int, int, int]:
        candidates, preserved, deleted, fails = 0, 0, 0, 0
        records = db.query(SecurityEventModel).all()
        to_delete = []

        for ev in records:
            trusted_ts = ev.received_at or ev.created_at
            if RetentionCalculator.is_expired("NORMALIZED_EVENTS", trusted_ts, as_of_time=now_utc, policy_config=self.config):
                candidates += 1
                if self.preservation.is_target_preserved(db, ev.event_id, "SECURITY_EVENT"):
                    preserved += 1
                else:
                    to_delete.append(ev)

        if not dry_run and to_delete:
            try:
                for item in to_delete:
                    db.delete(item)
                db.commit()
                deleted = len(to_delete)
            except Exception:
                db.rollback()
                fails = len(to_delete)

        return candidates, preserved, deleted, fails

    def _process_raw_events(
        self, db: Session, now_utc: datetime, dry_run: bool
    ) -> tuple[int, int, int, int]:
        candidates, preserved, deleted, fails = 0, 0, 0, 0
        records = db.query(RawEventModel).all()
        to_delete = []

        for ev in records:
            trusted_ts = ev.received_at or ev.created_at
            if RetentionCalculator.is_expired("RAW_EVENTS", trusted_ts, as_of_time=now_utc, policy_config=self.config):
                candidates += 1
                # If raw_event is referenced by security_event or preserved, keep it
                if self.preservation.is_target_preserved(db, ev.raw_event_id, "RAW_EVENT") or ev.security_event is not None:
                    preserved += 1
                else:
                    to_delete.append(ev)

        if not dry_run and to_delete:
            try:
                for item in to_delete:
                    db.delete(item)
                db.commit()
                deleted = len(to_delete)
            except Exception:
                db.rollback()
                fails = len(to_delete)

        return candidates, preserved, deleted, fails

    def _process_alerts(
        self, db: Session, now_utc: datetime, dry_run: bool
    ) -> tuple[int, int, int, int]:
        candidates, preserved, deleted, fails = 0, 0, 0, 0
        records = db.query(AlertModel).all()
        to_delete = []

        for alt in records:
            trusted_ts = alt.generated_at or alt.created_at
            if RetentionCalculator.is_expired("ALERTS", trusted_ts, as_of_time=now_utc, policy_config=self.config):
                candidates += 1
                if self.preservation.is_target_preserved(db, alt.alert_id, "ALERT"):
                    preserved += 1
                else:
                    to_delete.append(alt)

        if not dry_run and to_delete:
            try:
                for item in to_delete:
                    db.delete(item)
                db.commit()
                deleted = len(to_delete)
            except Exception:
                db.rollback()
                fails = len(to_delete)

        return candidates, preserved, deleted, fails

