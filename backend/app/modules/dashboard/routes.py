"""FastAPI REST routes for SnareSight SOC Dashboard & Security Operations Overview (Task P25)."""

import uuid
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.db.models.alert import AlertModel, AlertEvidenceModel
from app.modules.dashboard.schemas import (
    DashboardOverviewResponse,
    GlobalSearchResponse,
    NotificationListResponse,
    PipelineHealthSummary,
    RecentAlertItem,
)
from app.modules.dashboard.service import DashboardService


router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard"])


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    summary="Get aggregated SOC dashboard overview",
)
def get_dashboard_overview(
    range: str = Query(
        "24h",
        pattern="^(1h|24h|7d|30d)$",
        description="Aggregation time window: 1h, 24h, 7d, or 30d",
    ),
    db: Session = Depends(get_db),
) -> DashboardOverviewResponse:
    """Returns aggregated SOC dashboard overview metrics, activity trends,

    severity distributions, top detection categories, sensor freshness, and health.
    """
    service = DashboardService(db)
    return service.get_overview(time_range=range)


@router.get(
    "/search",
    response_model=GlobalSearchResponse,
    summary="Execute global entity search",
)
def global_search(
    q: str = Query(..., min_length=1, description="Search query string"),
    limit: int = Query(5, ge=1, le=20, description="Max results per entity category"),
    db: Session = Depends(get_db),
) -> GlobalSearchResponse:
    """Bounded, indexed search across alerts, events, sessions, profiles, and investigations."""
    service = DashboardService(db)
    return service.global_search(query=q, limit=limit)


@router.get(
    "/notifications",
    response_model=NotificationListResponse,
    summary="Get in-app SOC notifications",
)
def get_notifications(
    limit: int = Query(10, ge=1, le=50, description="Max notifications to retrieve"),
    db: Session = Depends(get_db),
) -> NotificationListResponse:
    """Retrieves lightweight in-app notifications synthesized from real system events."""
    service = DashboardService(db)
    return service.get_notifications(limit=limit)


@router.get(
    "/health",
    response_model=PipelineHealthSummary,
    summary="Operational health diagnostics",
)
def get_dashboard_health(
    db: Session = Depends(get_db),
) -> PipelineHealthSummary:
    """Returns operational status across DB, ingestion, and real-time streaming."""
    service = DashboardService(db)
    now = service._resolve_time_window("24h", service.db.bind.engine)[0]  # dummy trigger
    from datetime import datetime, timezone
    return service._get_pipeline_health_summary(datetime.now(timezone.utc))


@router.get(
    "/alerts",
    summary="List security alerts with filtering",
)
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieves paginated security alerts with optional severity filtering."""
    query = db.query(AlertModel)
    if severity:
        query = query.filter(AlertModel.severity == severity.upper())

    total = query.count()
    items = query.order_by(desc(AlertModel.generated_at)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "alert_id": str(a.alert_id),
                "title": a.title,
                "summary": a.summary,
                "severity": a.severity,
                "confidence": a.confidence,
                "assessment_status": a.assessment_status,
                "evidence_strength": a.evidence_strength,
                "source_address": a.source_address,
                "observed_source_id": a.observed_source_id,
                "decoy_id": a.decoy_id,
                "target_service": a.target_service,
                "first_observed_at": a.first_observed_at.isoformat() if a.first_observed_at else None,
                "last_observed_at": a.last_observed_at.isoformat() if a.last_observed_at else None,
                "generated_at": a.generated_at.isoformat() if a.generated_at else None,
                "detection_rule_id": a.detection_rule_id,
            }
            for a in items
        ],
    }


@router.get(
    "/alerts/{alert_id}",
    summary="Get detailed alert information by UUID or alert ID",
)
def get_alert_detail(
    alert_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Fetches full alert forensic record including explanation, recommendations, and evidence links."""
    alert = None
    try:
        val_uuid = uuid.UUID(alert_id)
        alert = db.query(AlertModel).filter(
            (AlertModel.alert_id == val_uuid) | (AlertModel.id == val_uuid)
        ).first()
    except ValueError:
        pass

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found",
        )

    evidence_links = db.query(AlertEvidenceModel).filter(
        AlertEvidenceModel.alert_id == alert.alert_id
    ).all()

    return {
        "alert_id": str(alert.alert_id),
        "title": alert.title,
        "summary": alert.summary,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "assessment_status": alert.assessment_status,
        "evidence_strength": alert.evidence_strength,
        "source_address": alert.source_address,
        "observed_source_id": alert.observed_source_id,
        "decoy_id": alert.decoy_id,
        "target_service": alert.target_service,
        "first_observed_at": alert.first_observed_at.isoformat() if alert.first_observed_at else None,
        "last_observed_at": alert.last_observed_at.isoformat() if alert.last_observed_at else None,
        "generated_at": alert.generated_at.isoformat() if alert.generated_at else None,
        "detection_rule_id": alert.detection_rule_id,
        "detection_rule_version": alert.detection_rule_version,
        "detection_explanation": alert.detection_explanation,
        "recommendations": alert.recommendations,
        "evidence_count": len(evidence_links),
        "evidence_links": [
            {
                "event_id": str(el.event_id),
                "evidence_role": el.evidence_role,
            }
            for el in evidence_links
        ],
    }

