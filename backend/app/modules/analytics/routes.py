"""FastAPI endpoints for SOC Analytics, Reporting and Executive Overview (Task P30)."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Response
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.analytics.schemas import (
    AnalyticsFilterQuery,
    AnalyticsOverviewResponse,
    EventTimelineResponse,
    AlertTimelineResponse,
    EventAlertOverviewResponse,
    DetectionAnalyticsResponse,
    SeverityAnalyticsResponse,
    ConfidenceAnalyticsResponse,
    SessionAnalyticsResponse,
    SourceAnalyticsResponse,
    InvestigationAnalyticsResponse,
    AttackAnalyticsResponse,
    SensorAnalyticsResponse,
    PipelineHealthAnalyticsResponse,
    ExecutiveSummaryResponse,
    ReportGenerationRequest,
    ReportMetadataResponse,
)
from app.modules.analytics.service import AnalyticsService

analytics_router = APIRouter(prefix="/analytics", tags=["SOC Analytics"])
reports_router = APIRouter(prefix="/reports", tags=["Security Reports"])


def _build_filter_query(
    time_range: str = Query("24h", description="15m, 1h, 24h, 7d, 30d, custom"),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    sensor_id: Optional[str] = Query(None),
    event_category: Optional[str] = Query(None),
    detection_category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    investigation_id: Optional[str] = Query(None),
    tactic_id: Optional[str] = Query(None),
) -> AnalyticsFilterQuery:
    return AnalyticsFilterQuery(
        time_range=time_range,
        start_time=start_time,
        end_time=end_time,
        sensor_id=sensor_id,
        event_category=event_category,
        detection_category=detection_category,
        severity=severity,
        session_id=session_id,
        investigation_id=investigation_id,
        tactic_id=tactic_id,
    )


@analytics_router.get("/overview", response_model=AnalyticsOverviewResponse)
def get_analytics_overview(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns high-level security activity summary metrics with previous period comparisons."""
    return AnalyticsService.get_overview(db, filters)


@analytics_router.get("/events/timeline", response_model=EventTimelineResponse)
def get_events_timeline(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns time-series volume of observed events grouped by time interval."""
    return AnalyticsService.get_events_timeline(db, filters)


@analytics_router.get("/alerts/timeline", response_model=AlertTimelineResponse)
def get_alerts_timeline(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns time-series volume of generated alerts grouped by time interval."""
    return AnalyticsService.get_alerts_timeline(db, filters)


@analytics_router.get("/event-alert-overview", response_model=EventAlertOverviewResponse)
def get_event_alert_overview(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns event-to-alert correlation density and evidence coverage metrics."""
    return AnalyticsService.get_event_alert_overview(db, filters)


@analytics_router.get("/detections", response_model=DetectionAnalyticsResponse)
def get_detection_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns detection rule trigger performance, active/inactive rules, and categories."""
    return AnalyticsService.get_detection_analytics(db, filters)


@analytics_router.get("/severity", response_model=SeverityAnalyticsResponse)
def get_severity_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns alert severity distribution across CRITICAL, HIGH, MEDIUM, LOW, and INFO."""
    return AnalyticsService.get_severity_analytics(db, filters)


@analytics_router.get("/confidence", response_model=ConfidenceAnalyticsResponse)
def get_confidence_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns detection confidence distribution independently from severity."""
    return AnalyticsService.get_confidence_analytics(db, filters)


@analytics_router.get("/sessions", response_model=SessionAnalyticsResponse)
def get_session_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns session telemetry metrics, duration distributions, and behavioral sequence counts."""
    return AnalyticsService.get_session_analytics(db, filters)


@analytics_router.get("/sources", response_model=SourceAnalyticsResponse)
def get_source_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns source intelligence profile recurrence and top network origins."""
    return AnalyticsService.get_source_analytics(db, filters)


@analytics_router.get("/investigations", response_model=InvestigationAnalyticsResponse)
def get_investigation_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns campaign investigation clusters and associated evidence counts."""
    return AnalyticsService.get_investigation_analytics(db, filters)


@analytics_router.get("/attack-coverage", response_model=AttackAnalyticsResponse)
def get_attack_coverage(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns ATT&CK enterprise matrix coverage and tactic-by-tactic mapping status."""
    return AnalyticsService.get_attack_coverage_analytics(db, filters)


@analytics_router.get("/sensors", response_model=SensorAnalyticsResponse)
def get_sensor_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns operational honeypot sensor status and telemetry freshness."""
    return AnalyticsService.get_sensor_analytics(db, filters)


@analytics_router.get("/pipeline-health", response_model=PipelineHealthAnalyticsResponse)
def get_pipeline_health_analytics(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns event processing error counts, duplicate filtration, and SSE status."""
    return AnalyticsService.get_pipeline_health_analytics(db, filters)


@analytics_router.get("/executive-summary", response_model=ExecutiveSummaryResponse)
def get_executive_summary(
    filters: AnalyticsFilterQuery = Depends(_build_filter_query),
    db: Session = Depends(get_db),
):
    """Returns deterministic, metric-grounded executive narrative summary."""
    return AnalyticsService.get_executive_summary(db, filters)


# =============================================================================
# Report Generation Routes
# =============================================================================

@reports_router.post("/generate", response_model=ReportMetadataResponse)
def generate_security_report(
    req: ReportGenerationRequest,
    db: Session = Depends(get_db),
):
    """Generates an exportable PDF or CSV security report with audit logging and sensitive data redaction."""
    return AnalyticsService.generate_report(db, req)


@reports_router.get("/{report_id}", response_model=ReportMetadataResponse)
def get_report_metadata(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves report generation status and metadata by ID."""
    record = AnalyticsService.get_report_record(db, report_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return ReportMetadataResponse(
        report_id=str(record.id),
        report_title=record.report_title,
        report_type=record.report_type,
        time_range=record.time_range_label,
        generated_by=record.generated_by,
        file_format=record.file_format,
        file_size_bytes=record.file_size_bytes,
        status=record.status,
        created_at=record.created_at.isoformat(),
        download_url=f"/api/v1/reports/{record.id}/download",
    )


@reports_router.get("/{report_id}/download")
def download_security_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Streams the generated PDF binary or CSV file directly to the client."""
    record = AnalyticsService.get_report_record(db, report_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    if record.file_format.upper() == "PDF":
        if not record.pdf_content:
            raise HTTPException(status_code=404, detail="PDF content not available for this report.")
        filename = f"snaresight_report_{record.id}.pdf"
        return Response(
            content=record.pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        if not record.csv_content:
            raise HTTPException(status_code=404, detail="CSV content not available for this report.")
        filename = f"snaresight_report_{record.id}.csv"
        return Response(
            content=record.csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

