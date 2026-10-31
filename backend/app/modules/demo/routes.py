"""FastAPI REST routes for SnareSight Demonstration Lab & Synthetic Evaluation."""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.security.dependencies import AuthenticatedUser, require_permission
from app.modules.security.permissions import Permission
from app.modules.demo.schemas import (
    DemoCleanupRequest,
    DemoCleanupResponse,
    DemoExportResponse,
    EvaluationSummaryResponse,
    ScenarioMeta,
    ScenarioRunRequest,
    ScenarioRunResponse,
)
from app.modules.demo.scenarios import get_scenario_catalog
from app.modules.demo.service import demo_service

demo_router = APIRouter(prefix="/demo", tags=["Demonstration Lab & Synthetic Evaluation"])


@demo_router.get(
    "/scenarios",
    response_model=List[ScenarioMeta],
    summary="List all available demonstration scenarios",
)
def list_scenarios(
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> List[ScenarioMeta]:
    """Returns the catalog of safe demonstration scenarios with MITRE mappings."""
    return get_scenario_catalog()


@demo_router.post(
    "/scenarios/run",
    response_model=ScenarioRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute a safe synthetic demonstration scenario",
)
def run_scenario(
    request: ScenarioRunRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.GENERATE_REPORTS)),
) -> ScenarioRunResponse:
    """Ingests synthetic demonstration telemetry and evaluates threat detection in real time."""
    return demo_service.run_scenario(
        db=db,
        request=request,
        current_username=current_user.username,
    )


@demo_router.get(
    "/evaluation",
    response_model=EvaluationSummaryResponse,
    summary="Retrieve detection quality evaluation metrics",
)
def get_evaluation(
    current_user: AuthenticatedUser = Depends(require_permission(Permission.VIEW_DASHBOARD)),
) -> EvaluationSummaryResponse:
    """Returns True Positive, False Positive, Precision, Recall, and F1 benchmarks."""
    return demo_service.get_latest_evaluation()


@demo_router.post(
    "/cleanup",
    response_model=DemoCleanupResponse,
    summary="Selectively clean up synthetic demonstration data",
)
def cleanup_data(
    request: DemoCleanupRequest,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.MODIFY_SYSTEM_CONFIGURATION)),
) -> DemoCleanupResponse:
    """Safely purges synthetic demonstration events while respecting active evidence holds."""
    return demo_service.cleanup_demonstration_data(db=db, request=request)


@demo_router.get(
    "/export",
    response_model=DemoExportResponse,
    summary="Export demonstration data marked with synthetic watermark",
)
def export_data(
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_permission(Permission.EXPORT_DATA)),
) -> DemoExportResponse:
    """Exports demonstration records labeled with SYNTHETIC DEMONSTRATION DATA watermark."""
    return demo_service.export_data(db=db)
