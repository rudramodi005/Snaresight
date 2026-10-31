"""Sensor management, health monitoring, and operational reliability service."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc

from app.db.models.sensor import (
    SensorModel,
    SensorCredentialModel,
    SensorHeartbeatModel,
    SensorConfigurationModel,
    OperationalAlertModel,
    SensorMaintenanceHistoryModel,
    SensorTelemetryMetricModel,
)
from app.modules.sensors.schemas import (
    SensorCreateRequest,
    SensorUpdateRequest,
    SensorConfigurationCreateRequest,
    HeartbeatSubmitRequest,
    SensorOperationsSummary,
)
from app.modules.sensors.auth import generate_sensor_api_key, hash_sensor_key
from app.modules.sensors.health_engine import SensorHealthEngine
from app.modules.security.audit_service import audit_service
from app.streaming.event_publisher import event_publisher


class SensorService:
    """Core orchestration service for honeypot sensor lifecycle, health, config, and operational alerts."""

    @classmethod
    def _log_audit(
        cls,
        db: Session,
        user: Optional[Any],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        actor_username = getattr(user, "username", "system")
        actor_role = getattr(user, "role", "SYSTEM")
        audit_service.log_event(
            db=db,
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            reason=reason,
            request_context=details,
        )

    @classmethod
    def get_summary(cls, db: Session) -> SensorOperationsSummary:
        """Aggregates fleet-wide health, operational status, telemetry stats, and active alerts."""
        sensors = db.query(SensorModel).all()

        total = len(sensors)
        active = sum(1 for s in sensors if s.operational_status == "ACTIVE")
        degraded = sum(1 for s in sensors if s.operational_status == "DEGRADED")
        offline = sum(1 for s in sensors if s.operational_status == "OFFLINE")
        maintenance = sum(1 for s in sensors if s.operational_status == "MAINTENANCE")
        disabled = sum(1 for s in sensors if s.operational_status == "DISABLED")
        retired = sum(1 for s in sensors if s.operational_status == "RETIRED")

        last_telemetry = None
        for s in sensors:
            if s.last_telemetry_at:
                if not last_telemetry or s.last_telemetry_at > last_telemetry:
                    last_telemetry = s.last_telemetry_at

        # Metrics aggregation
        metrics_agg = (
            db.query(
                func.coalesce(func.sum(SensorTelemetryMetricModel.events_received), 0).label("received"),
                func.coalesce(func.sum(SensorTelemetryMetricModel.events_persisted), 0).label("persisted"),
                func.coalesce(func.sum(SensorTelemetryMetricModel.events_rejected), 0).label("rejected"),
            )
            .first()
        )
        total_received = int(metrics_agg.received) if metrics_agg else 0
        total_persisted = int(metrics_agg.persisted) if metrics_agg else 0
        total_rejected = int(metrics_agg.rejected) if metrics_agg else 0

        ingestion_success_rate = 100.0
        if total_received > 0:
            ingestion_success_rate = round((total_persisted / total_received) * 100.0, 2)

        # Operational alerts count
        open_alerts = (
            db.query(OperationalAlertModel)
            .filter(OperationalAlertModel.status.in_(["OPEN", "ACKNOWLEDGED"]))
            .all()
        )
        open_alerts_count = len(open_alerts)
        critical_alerts_count = sum(1 for a in open_alerts if a.severity in ("CRITICAL", "HIGH"))

        by_type: Dict[str, int] = {}
        by_env: Dict[str, int] = {}
        for s in sensors:
            by_type[s.sensor_type] = by_type.get(s.sensor_type, 0) + 1
            by_env[s.deployment_environment] = by_env.get(s.deployment_environment, 0) + 1

        return SensorOperationsSummary(
            total_registered_sensors=total,
            active_sensors=active,
            degraded_sensors=degraded,
            offline_sensors=offline,
            maintenance_sensors=maintenance,
            disabled_sensors=disabled,
            retired_sensors=retired,
            last_telemetry_receipt=last_telemetry,
            total_telemetry_events_received=total_received,
            ingestion_success_rate=ingestion_success_rate,
            open_operational_alerts_count=open_alerts_count,
            critical_operational_alerts_count=critical_alerts_count,
            sensors_by_type=by_type,
            sensors_by_environment=by_env,
        )

    @classmethod
    def list_sensors(
        cls,
        db: Session,
        status: Optional[str] = None,
        sensor_type: Optional[str] = None,
        environment: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> Tuple[int, List[SensorModel]]:
        """Queries sensor inventory with optional filtering, evaluation, and search."""
        query = db.query(SensorModel)

        if status and status != "ALL":
            query = query.filter(SensorModel.operational_status == status)
        if sensor_type and sensor_type != "ALL":
            query = query.filter(SensorModel.sensor_type == sensor_type)
        if environment and environment != "ALL":
            query = query.filter(SensorModel.deployment_environment == environment)
        if search:
            term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SensorModel.sensor_id.ilike(term),
                    SensorModel.name.ilike(term),
                    SensorModel.lab_zone.ilike(term),
                )
            )

        total = query.count()
        sensors = (
            query.order_by(desc(SensorModel.last_heartbeat_at), SensorModel.sensor_id)
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )

        # Run health check on returned sensors
        for s in sensors:
            SensorHealthEngine.evaluate_sensor_health(db, s)
        db.commit()

        return total, sensors

    @classmethod
    def get_sensor(cls, db: Session, sensor_id: str) -> Optional[SensorModel]:
        """Loads a single sensor and re-evaluates its health state."""
        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        if sensor:
            SensorHealthEngine.evaluate_sensor_health(db, sensor)
            db.commit()
        return sensor

    @classmethod
    def register_sensor(
        cls, db: Session, payload: SensorCreateRequest, user: Optional[Any] = None
    ) -> Tuple[SensorModel, SensorCredentialModel, str]:
        """Registers a new sensor, generates initial API credentials, and sets default config."""
        existing = db.query(SensorModel).filter(SensorModel.sensor_id == payload.sensor_id).first()
        if existing:
            raise ValueError(f"Sensor ID '{payload.sensor_id}' already registered")

        now = datetime.now(timezone.utc)
        sensor = SensorModel(
            sensor_id=payload.sensor_id,
            name=payload.name,
            sensor_type=payload.sensor_type,
            sensor_version=payload.sensor_version,
            deployment_environment=payload.deployment_environment,
            lab_zone=payload.lab_zone,
            operational_status="REGISTERED",
            health_status="UNKNOWN",
            heartbeat_interval_seconds=payload.heartbeat_interval_seconds,
            missed_heartbeat_count=0,
            current_config_version="1.0.0",
            supported_telemetry_types=payload.supported_telemetry_types,
            admin_notes=payload.admin_notes,
            created_at=now,
            updated_at=now,
        )
        db.add(sensor)
        db.flush()

        # Generate initial credential
        key_id, raw_key, prefix, hashed = generate_sensor_api_key(payload.sensor_id)
        credential = SensorCredentialModel(
            key_id=key_id,
            sensor_id=payload.sensor_id,
            key_prefix=prefix,
            hashed_api_key=hashed,
            status="ACTIVE",
            created_at=now,
        )
        db.add(credential)

        # Create baseline configuration v1.0.0
        default_config = payload.initial_config or {
            "heartbeat_interval_seconds": payload.heartbeat_interval_seconds,
            "log_level": "INFO",
            "deception_latency_ms": 0,
            "canary_tokens_enabled": True,
            "max_batch_size": 250,
        }
        config = SensorConfigurationModel(
            sensor_id=payload.sensor_id,
            version="1.0.0",
            config_payload=default_config,
            is_current=True,
            change_reason="Initial registration baseline configuration",
            updated_by=getattr(user, "username", "system"),
            created_at=now,
        )
        db.add(config)
        db.commit()

        # Audit log
        cls._log_audit(
            db=db,
            user=user,
            action="CREATE",
            resource_type="sensor",
            resource_id=sensor.sensor_id,
            details={
                "name": sensor.name,
                "type": sensor.sensor_type,
                "environment": sensor.deployment_environment,
                "key_prefix": prefix,
            },
        )

        try:
            event_publisher.publish_event(
                event_type="sensor_registered",
                data={"sensor_id": sensor.sensor_id, "name": sensor.name, "type": sensor.sensor_type},
            )
        except Exception:
            pass

        return sensor, credential, raw_key

    @classmethod
    def rotate_credentials(
        cls, db: Session, sensor_id: str, user: Optional[Any] = None
    ) -> Tuple[SensorCredentialModel, str]:
        """Revokes all existing active credentials and generates a new key pair."""
        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        if not sensor:
            raise ValueError(f"Sensor '{sensor_id}' not found")

        now = datetime.now(timezone.utc)
        # Revoke existing
        active_creds = (
            db.query(SensorCredentialModel)
            .filter(
                SensorCredentialModel.sensor_id == sensor_id,
                SensorCredentialModel.status == "ACTIVE",
            )
            .all()
        )
        for c in active_creds:
            c.status = "REVOKED"
            c.revoked_at = now
            c.revocation_reason = "Rotated by administrator"

        # Generate fresh key
        key_id, raw_key, prefix, hashed = generate_sensor_api_key(sensor_id)
        new_cred = SensorCredentialModel(
            key_id=key_id,
            sensor_id=sensor_id,
            key_prefix=prefix,
            hashed_api_key=hashed,
            status="ACTIVE",
            created_at=now,
        )
        db.add(new_cred)
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="sensor_credential",
            resource_id=key_id,
            details={"sensor_id": sensor_id, "new_key_prefix": prefix},
        )

        return new_cred, raw_key

    @classmethod
    def revoke_credential(
        cls, db: Session, sensor_id: str, key_id: str, reason: str, user: Optional[Any] = None
    ) -> SensorCredentialModel:
        """Revokes a specific sensor credential."""
        cred = (
            db.query(SensorCredentialModel)
            .filter(
                SensorCredentialModel.sensor_id == sensor_id,
                SensorCredentialModel.key_id == key_id,
            )
            .first()
        )
        if not cred:
            raise ValueError(f"Credential '{key_id}' for sensor '{sensor_id}' not found")

        cred.status = "REVOKED"
        cred.revoked_at = datetime.now(timezone.utc)
        cred.revocation_reason = reason
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="DELETE",
            resource_type="sensor_credential",
            resource_id=key_id,
            reason=reason,
            details={"sensor_id": sensor_id, "reason": reason},
        )
        return cred

    @classmethod
    def record_heartbeat(
        cls, db: Session, sensor: SensorModel, payload: HeartbeatSubmitRequest
    ) -> SensorHeartbeatModel:
        """Processes an authenticated heartbeat from a sensor."""
        now = datetime.now(timezone.utc)
        hb = SensorHeartbeatModel(
            sensor_id=sensor.sensor_id,
            timestamp=now,
            status=payload.status,
            latency_ms=payload.latency_ms,
            metrics_payload=payload.metrics_payload,
            error_category=payload.error_category,
        )
        db.add(hb)

        # Update sensor vitals
        sensor.last_heartbeat_at = now
        sensor.missed_heartbeat_count = 0
        if sensor.operational_status in ("REGISTERED", "OFFLINE", "DEGRADED"):
            sensor.operational_status = "ACTIVE"
            sensor.health_status = "HEALTHY"

        # Re-evaluate health engine & auto-resolve overdue alerts
        SensorHealthEngine.evaluate_sensor_health(db, sensor, current_time=now)
        db.commit()

        try:
            event_publisher.publish_event(
                event_type="sensor_heartbeat_received",
                data={
                    "sensor_id": sensor.sensor_id,
                    "status": sensor.operational_status,
                    "health": sensor.health_status,
                },
            )
        except Exception:
            pass

        return hb

    @classmethod
    def record_telemetry_metric(
        cls,
        db: Session,
        sensor_id: str,
        events_count: int,
        persisted_count: int,
        rejected_count: int = 0,
        duplicate_count: int = 0,
        latency_ms: float = 0.0,
    ) -> None:
        """Records telemetry arrival and pipeline persistence stats for reliability tracking."""
        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        now = datetime.now(timezone.utc)
        if sensor:
            sensor.last_telemetry_at = now

        metric = SensorTelemetryMetricModel(
            sensor_id=sensor_id,
            window_start=now - timedelta(minutes=1),
            window_end=now,
            events_received=events_count,
            events_validated=persisted_count + rejected_count,
            events_rejected=rejected_count,
            events_persisted=persisted_count,
            duplicate_events=duplicate_count,
            average_latency_ms=latency_ms,
        )
        db.add(metric)
        db.commit()

    @classmethod
    def update_configuration(
        cls,
        db: Session,
        sensor_id: str,
        payload: SensorConfigurationCreateRequest,
        user: Optional[Any] = None,
    ) -> SensorConfigurationModel:
        """Creates a new versioned configuration and designates it as current."""
        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        if not sensor:
            raise ValueError(f"Sensor '{sensor_id}' not found")

        # Deactivate previous current configuration
        db.query(SensorConfigurationModel).filter(
            SensorConfigurationModel.sensor_id == sensor_id,
            SensorConfigurationModel.is_current == True,
        ).update({"is_current": False})

        now = datetime.now(timezone.utc)
        config = SensorConfigurationModel(
            sensor_id=sensor_id,
            version=payload.version,
            config_payload=payload.config_payload,
            is_current=True,
            change_reason=payload.change_reason,
            updated_by=getattr(user, "username", "system"),
            created_at=now,
        )
        db.add(config)
        sensor.current_config_version = payload.version
        sensor.updated_at = now
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="sensor_configuration",
            resource_id=f"{sensor_id}:{payload.version}",
            reason=payload.change_reason,
            details={"version": payload.version, "reason": payload.change_reason},
        )

        try:
            event_publisher.publish_event(
                event_type="sensor_config_updated",
                data={"sensor_id": sensor_id, "version": payload.version},
            )
        except Exception:
            pass

        return config

    @classmethod
    def rollback_configuration(
        cls,
        db: Session,
        sensor_id: str,
        target_version: str,
        reason: str,
        user: Optional[Any] = None,
    ) -> SensorConfigurationModel:
        """Rolls back to a previously committed configuration version."""
        target = (
            db.query(SensorConfigurationModel)
            .filter(
                SensorConfigurationModel.sensor_id == sensor_id,
                SensorConfigurationModel.version == target_version,
            )
            .first()
        )
        if not target:
            raise ValueError(f"Target configuration version '{target_version}' not found")

        # Deactivate current
        db.query(SensorConfigurationModel).filter(
            SensorConfigurationModel.sensor_id == sensor_id,
            SensorConfigurationModel.is_current == True,
        ).update({"is_current": False})

        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        target.is_current = True
        target.change_reason = f"Rollback to {target_version}: {reason}"
        if sensor:
            sensor.current_config_version = target_version
            sensor.updated_at = datetime.now(timezone.utc)

        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="sensor_configuration",
            resource_id=f"{sensor_id}:{target_version}",
            reason=reason,
            details={"target_version": target_version, "reason": reason},
        )

        return target

    @classmethod
    def set_maintenance_mode(
        cls, db: Session, sensor_id: str, enabled: bool, reason: str, user: Optional[Any] = None
    ) -> SensorModel:
        """Toggles maintenance mode for a sensor, logging into maintenance history."""
        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        if not sensor:
            raise ValueError(f"Sensor '{sensor_id}' not found")

        now = datetime.now(timezone.utc)
        if enabled:
            sensor.operational_status = "MAINTENANCE"
            sensor.health_status = "HEALTHY"
            record = SensorMaintenanceHistoryModel(
                sensor_id=sensor_id,
                maintenance_mode_enabled=True,
                reason=reason,
                initiated_by=getattr(user, "username", "operator"),
                started_at=now,
            )
            db.add(record)
        else:
            sensor.operational_status = "ACTIVE"
            # Close out active maintenance records
            active_rec = (
                db.query(SensorMaintenanceHistoryModel)
                .filter(
                    SensorMaintenanceHistoryModel.sensor_id == sensor_id,
                    SensorMaintenanceHistoryModel.ended_at == None,
                )
                .order_by(desc(SensorMaintenanceHistoryModel.started_at))
                .first()
            )
            if active_rec:
                active_rec.ended_at = now

        sensor.updated_at = now
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="sensor",
            resource_id=sensor_id,
            reason=reason,
            details={"maintenance_enabled": enabled, "reason": reason},
        )

        try:
            event_publisher.publish_event(
                event_type="sensor_maintenance_toggled",
                data={"sensor_id": sensor_id, "maintenance_enabled": enabled},
            )
        except Exception:
            pass

        return sensor

    @classmethod
    def update_sensor_status(
        cls, db: Session, sensor_id: str, new_status: str, reason: str, user: Optional[Any] = None
    ) -> SensorModel:
        """Administratively updates sensor operational status (e.g. DISABLED, RETIRED, ACTIVE)."""
        valid_statuses = ("REGISTERED", "ACTIVE", "DEGRADED", "OFFLINE", "MAINTENANCE", "DISABLED", "RETIRED")
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

        sensor = db.query(SensorModel).filter(SensorModel.sensor_id == sensor_id).first()
        if not sensor:
            raise ValueError(f"Sensor '{sensor_id}' not found")

        old_status = sensor.operational_status
        sensor.operational_status = new_status
        sensor.updated_at = datetime.now(timezone.utc)
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="sensor",
            resource_id=sensor_id,
            reason=reason,
            details={"old_status": old_status, "new_status": new_status, "reason": reason},
        )
        return sensor

    @classmethod
    def list_operational_alerts(
        cls,
        db: Session,
        sensor_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
    ) -> Tuple[int, List[OperationalAlertModel]]:
        """Queries operational alerts separate from threat alerts."""
        query = db.query(OperationalAlertModel)
        if sensor_id:
            query = query.filter(OperationalAlertModel.sensor_id == sensor_id)
        if category and category != "ALL":
            query = query.filter(OperationalAlertModel.alert_category == category)
        if severity and severity != "ALL":
            query = query.filter(OperationalAlertModel.severity == severity)
        if status and status != "ALL":
            query = query.filter(OperationalAlertModel.status == status)

        total = query.count()
        alerts = (
            query.order_by(desc(OperationalAlertModel.last_observed_at))
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return total, alerts

    @classmethod
    def acknowledge_operational_alert(
        cls, db: Session, alert_id: str, user: Optional[Any] = None
    ) -> OperationalAlertModel:
        """Acknowledges an open operational alert."""
        alert = db.query(OperationalAlertModel).filter(OperationalAlertModel.alert_id == alert_id).first()
        if not alert:
            raise ValueError(f"Operational alert '{alert_id}' not found")

        alert.status = "ACKNOWLEDGED"
        alert.acknowledged_by = getattr(user, "username", "operator")
        alert.acknowledged_at = datetime.now(timezone.utc)
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="operational_alert",
            resource_id=alert_id,
            details={"sensor_id": alert.sensor_id, "category": alert.alert_category},
        )
        return alert

    @classmethod
    def resolve_operational_alert(
        cls, db: Session, alert_id: str, notes: str, user: Optional[Any] = None
    ) -> OperationalAlertModel:
        """Resolves an operational alert with analyst resolution notes."""
        alert = db.query(OperationalAlertModel).filter(OperationalAlertModel.alert_id == alert_id).first()
        if not alert:
            raise ValueError(f"Operational alert '{alert_id}' not found")

        alert.status = "RESOLVED"
        alert.resolved_by = getattr(user, "username", "operator")
        alert.resolved_at = datetime.now(timezone.utc)
        alert.resolution_notes = notes
        db.commit()

        cls._log_audit(
            db=db,
            user=user,
            action="UPDATE",
            resource_type="operational_alert",
            resource_id=alert_id,
            reason=notes,
            details={"sensor_id": alert.sensor_id, "resolution_notes": notes},
        )
        return alert


sensor_service = SensorService()
