"""FastAPI routes for application health probes and operational monitoring."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.monitoring.service import health_service

router = APIRouter(prefix="/health", tags=["Health & Monitoring"])


@router.get(
    "",
    summary="Overall health probe",
    status_code=status.HTTP_200_OK,
)
@router.get(
    "/",
    summary="Overall health probe",
    status_code=status.HTTP_200_OK,
)
async def overall_health_probe():
    """Confirms overall API health for container orchestration and reverse proxies."""
    return health_service.check_liveness()


@router.get(
    "/live",
    summary="Process liveness probe",
    status_code=status.HTTP_200_OK,
)
async def liveness_probe():
    """Confirms that the SnareSight backend process is running and responsive."""
    return health_service.check_liveness()


@router.get(
    "/ready",
    summary="Persistent dependency readiness probe",
    status_code=status.HTTP_200_OK,
)
async def readiness_probe(db: Session = Depends(get_db)):
    """Verifies that database connectivity and required dependencies are operational."""
    return health_service.check_readiness(db=db)


@router.get(
    "/pipeline",
    summary="Event pipeline operational metrics",
    status_code=status.HTTP_200_OK,
)
async def pipeline_health(db: Session = Depends(get_db)):
    """Returns aggregated pipeline operational health and throughput metrics."""
    return health_service.get_pipeline_health(db=db)


@router.get(
    "/components",
    summary="Component-level health breakdown",
    status_code=status.HTTP_200_OK,
)
async def component_health(db: Session = Depends(get_db)):
    """Returns detailed operational health across all platform modules."""
    return health_service.get_component_health(db=db)

