"""Sensor health classification engine and operational alerting logic.

Evaluates heartbeat timing, missed heartbeat counts, and operational failures
to classify sensor state into HEALTHY, DEGRADED, OFFLINE, MAINTENANCE, or DISABLED,
while generating segregated operational health alerts.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from app.db.models.sensor import SensorModel, OperationalAlertModel
from app.streaming.event_publisher import event_publisher


class SensorHealthEngine:
    """Evaluates factual sensor health based on heartbeat telemetry and triggers operational alerts."""

    @classmethod
    def evaluate_sensor_health(
        cls, db: Session, sensor: SensorModel, current_time: Optional[datetime] = None
    ) -> Tuple[str, str]:
        """
        Calculates and updates operational_status and health_status for a sensor.
        
        Returns:
            (operational_status, health_status)
        """
        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        # 1. Respect administrative overrides
        if sensor.operational_status == "MAINTENANCE":
            sensor.health_status = "HEALTHY"
            return "MAINTENANCE", "HEALTHY"

        if sensor.operational_status in ("DISABLED", "RETIRED"):
            sensor.health_status = "UNKNOWN"
            return sensor.operational_status, "UNKNOWN"

        # 2. Check if sensor has ever reported
        if not sensor.last_heartbeat_at:
            created = sensor.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).total_seconds()
            if age > sensor.heartbeat_interval_seconds * 3:
                sensor.operational_status = "DEGRADED"
                sensor.health_status = "DEGRADED"
                cls.create_or_update_operational_alert(
                    db=db,
                    sensor_id=sensor.sensor_id,
                    alert_category="SENSOR_REGISTRATION_NO_HEARTBEAT",
                    severity="LOW",
                    evidence={
                        "created_at": created.isoformat(),
                        "seconds_since_registration": age,
                    },
                    recommended_action="Verify honeypot sensor process startup and network egress connectivity.",
                )
            else:
                sensor.health_status = "UNKNOWN"
            return sensor.operational_status, sensor.health_status

        # 3. Calculate elapsed time since last heartbeat
        last_hb = sensor.last_heartbeat_at
        if last_hb.tzinfo is None:
            last_hb = last_hb.replace(tzinfo=timezone.utc)
        elapsed_seconds = (now - last_hb).total_seconds()
        interval = float(sensor.heartbeat_interval_seconds)

        # Allow 2.5x interval before declaring degraded (absorbs network jitter & transmission delays)
        if elapsed_seconds <= interval * 2.5:
            sensor.operational_status = "ACTIVE"
            sensor.health_status = "HEALTHY"
            sensor.missed_heartbeat_count = 0
            # Auto-resolve transient heartbeat alerts
            cls.auto_resolve_operational_alert(
                db=db,
                sensor_id=sensor.sensor_id,
                alert_category="SENSOR_HEARTBEAT_OVERDUE",
                resolution_notes="Heartbeat restored within expected operational interval.",
            )
            cls.auto_resolve_operational_alert(
                db=db,
                sensor_id=sensor.sensor_id,
                alert_category="SENSOR_OFFLINE",
                resolution_notes="Sensor reconnected and resumed active heartbeat transmission.",
            )

        elif elapsed_seconds <= interval * 5.0:
            # DEGRADED: Missed 1 to 3 heartbeats
            sensor.operational_status = "DEGRADED"
            sensor.health_status = "DEGRADED"
            sensor.missed_heartbeat_count = max(1, int(elapsed_seconds // interval))
            cls.create_or_update_operational_alert(
                db=db,
                sensor_id=sensor.sensor_id,
                alert_category="SENSOR_HEARTBEAT_OVERDUE",
                severity="MEDIUM",
                evidence={
                    "last_heartbeat_at": sensor.last_heartbeat_at.isoformat(),
                    "elapsed_seconds": round(elapsed_seconds, 1),
                    "expected_interval_seconds": interval,
                    "missed_heartbeats": sensor.missed_heartbeat_count,
                },
                recommended_action="Investigate sensor host load, network latency, or forwarder daemon status.",
            )

        else:
            # OFFLINE: Persistent timeout (> 5x interval)
            sensor.operational_status = "OFFLINE"
            sensor.health_status = "CRITICAL"
            sensor.missed_heartbeat_count = int(elapsed_seconds // interval)
            cls.create_or_update_operational_alert(
                db=db,
                sensor_id=sensor.sensor_id,
                alert_category="SENSOR_OFFLINE",
                severity="HIGH",
                evidence={
                    "last_heartbeat_at": sensor.last_heartbeat_at.isoformat(),
                    "elapsed_seconds": round(elapsed_seconds, 1),
                    "expected_interval_seconds": interval,
                    "missed_heartbeats": sensor.missed_heartbeat_count,
                },
                recommended_action="Check if honeypot VM or container crashed or network route was interrupted.",
            )

        return sensor.operational_status, sensor.health_status

    @classmethod
    def create_or_update_operational_alert(
        cls,
        db: Session,
        sensor_id: str,
        alert_category: str,
        severity: str,
        evidence: dict,
        recommended_action: str,
    ) -> OperationalAlertModel:
        """Creates a new operational alert or updates last_observed_at on an existing open alert."""
        existing = (
            db.query(OperationalAlertModel)
            .filter(
                OperationalAlertModel.sensor_id == sensor_id,
                OperationalAlertModel.alert_category == alert_category,
                OperationalAlertModel.status.in_(["OPEN", "ACKNOWLEDGED"]),
            )
            .first()
        )

        now = datetime.now(timezone.utc)
        if existing:
            existing.last_observed_at = now
            existing.evidence_payload = evidence
            existing.severity = severity
            return existing

        alert_id = f"OP-ALT-{uuid.uuid4().hex[:12].upper()}"
        alert = OperationalAlertModel(
            alert_id=alert_id,
            sensor_id=sensor_id,
            alert_category=alert_category,
            severity=severity,
            status="OPEN",
            first_observed_at=now,
            last_observed_at=now,
            evidence_payload=evidence,
            recommended_action=recommended_action,
            created_at=now,
        )
        db.add(alert)
        db.flush()

        # Publish SSE operational alert event
        try:
            event_publisher.publish_event(
                event_type="operational_alert_created",
                data={
                    "alert_id": alert.alert_id,
                    "sensor_id": alert.sensor_id,
                    "category": alert.alert_category,
                    "severity": alert.severity,
                },
            )
        except Exception:
            pass

        return alert

    @classmethod
    def auto_resolve_operational_alert(
        cls, db: Session, sensor_id: str, alert_category: str, resolution_notes: str
    ) -> int:
        """Resolves open operational alerts of a specific category when condition clears."""
        open_alerts = (
            db.query(OperationalAlertModel)
            .filter(
                OperationalAlertModel.sensor_id == sensor_id,
                OperationalAlertModel.alert_category == alert_category,
                OperationalAlertModel.status.in_(["OPEN", "ACKNOWLEDGED"]),
            )
            .all()
        )

        now = datetime.now(timezone.utc)
        count = 0
        for alert in open_alerts:
            alert.status = "RESOLVED"
            alert.resolved_by = "system_auto_recovery"
            alert.resolved_at = now
            alert.resolution_notes = resolution_notes
            count += 1

        if count > 0:
            db.flush()
            try:
                event_publisher.publish_event(
                    event_type="operational_alerts_resolved",
                    data={
                        "sensor_id": sensor_id,
                        "category": alert_category,
                        "resolved_count": count,
                    },
                )
            except Exception:
                pass

        return count
