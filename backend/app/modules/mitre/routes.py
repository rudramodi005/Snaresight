"""FastAPI REST routes for MITRE ATT&CK catalogue exploration and controlled import."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.modules.mitre.exceptions import (
    MitreAuthorizationError,
    MitreError,
    MitreNotFoundError,
    MitreParsingError,
)
from app.modules.mitre.schemas import (
    CatalogueStatusResponse,
    DatasetVersionResponse,
    DryRunPreviewResponse,
    ImportExecutionResponse,
    PaginatedTechniquesResponse,
    RollbackRequest,
    RollbackResponse,
    SubtechniqueSchema,
    TacticSchema,
    TechniqueSchema,
)
from app.modules.mitre.service import MitreService

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


# Helper: Administrative authorization gate
def verify_admin_access(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Verifies that the caller possesses authorized administrator credentials."""
    # Check API key or Bearer token against authorized administration tokens
    valid_tokens = {"snare-collector-key-dev-2026", "snaresight_admin_token_2026", "valid_test_token"}
    provided_token = x_api_key
    if not provided_token and authorization and authorization.startswith("Bearer "):
        provided_token = authorization[7:].strip()

    if not provided_token or provided_token not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative authorization required for MITRE ATT&CK dataset operations",
        )
    return "admin"


# =============================================================================
# Read-Only Catalogue Endpoints
# =============================================================================

@router.get("/status", response_model=CatalogueStatusResponse)
def get_catalogue_status(db: Session = Depends(get_db)) -> CatalogueStatusResponse:
    """Returns the operational status, active release version, and summary counts."""
    return MitreService.get_status(db)


@router.get("/versions", response_model=List[DatasetVersionResponse])
def list_dataset_versions(db: Session = Depends(get_db)) -> List[DatasetVersionResponse]:
    """Lists all imported or candidate MITRE ATT&CK dataset versions."""
    return MitreService.list_versions(db)


@router.get("/tactics", response_model=List[TacticSchema])
def list_tactics(
    version: Optional[str] = Query(None, description="Target dataset version (defaults to active)"),
    include_deprecated: bool = Query(False, description="Include deprecated or revoked tactics"),
    db: Session = Depends(get_db),
) -> List[TacticSchema]:
    """Returns tactics belonging to the active (or requested) framework version."""
    return MitreService.list_tactics(db, version=version, include_deprecated=include_deprecated)


@router.get("/tactics/{tactic_id}", response_model=TacticSchema)
def get_tactic_details(
    tactic_id: str,
    version: Optional[str] = Query(None, description="Target dataset version"),
    db: Session = Depends(get_db),
) -> TacticSchema:
    """Retrieves a single tactic by external ID (e.g. TA0001) or shortname."""
    try:
        return MitreService.get_tactic(db, tactic_id=tactic_id, version=version)
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/techniques", response_model=PaginatedTechniquesResponse)
def list_techniques(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    search: Optional[str] = Query(None, description="Keyword search in ID, name, or description"),
    tactic: Optional[str] = Query(None, description="Filter by tactic ID or name"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    status_filter: Optional[str] = Query(None, description="Filter by lifecycle (ACTIVE, DEPRECATED, REVOKED)"),
    version: Optional[str] = Query(None, description="Target dataset version"),
    db: Session = Depends(get_db),
) -> PaginatedTechniquesResponse:
    """Queries paginated techniques with multi-attribute filtering."""
    return MitreService.list_techniques(
        db=db,
        page=page,
        page_size=page_size,
        search=search,
        tactic=tactic,
        platform=platform,
        status_filter=status_filter,
        version=version,
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueSchema)
def get_technique_details(
    technique_id: str,
    version: Optional[str] = Query(None, description="Target dataset version"),
    db: Session = Depends(get_db),
) -> TechniqueSchema:
    """Retrieves a single technique and its child sub-techniques."""
    try:
        return MitreService.get_technique(db, technique_id=technique_id, version=version)
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/techniques/{technique_id}/subtechniques", response_model=List[SubtechniqueSchema])
def list_technique_subtechniques(
    technique_id: str,
    version: Optional[str] = Query(None, description="Target dataset version"),
    db: Session = Depends(get_db),
) -> List[SubtechniqueSchema]:
    """Retrieves all sub-techniques belonging to a parent technique."""
    try:
        tech = MitreService.get_technique(db, technique_id=technique_id, version=version)
        return tech.subtechniques
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/subtechniques/{subtechnique_id}", response_model=SubtechniqueSchema)
def get_subtechnique_details(
    subtechnique_id: str,
    version: Optional[str] = Query(None, description="Target dataset version"),
    db: Session = Depends(get_db),
) -> SubtechniqueSchema:
    """Retrieves details of a single sub-technique (e.g. T1110.001)."""
    try:
        return MitreService.get_subtechnique(db, subtechnique_id=subtechnique_id, version=version)
    except MitreNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.message)


@router.get("/imports", response_model=List[Dict[str, Any]])
def list_import_history(
    limit: int = Query(20, ge=1, le=100),
    caller: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns historical import operations and dry-runs for authorized administrators."""
    return MitreService.list_imports(db, limit=limit)


# =============================================================================
# Administrative Import & Rollback Endpoints
# =============================================================================

@router.post("/import/dry-run", response_model=DryRunPreviewResponse)
def dry_run_import(
    payload: Dict[str, Any],
    version: str = Query("14.1", description="Dataset version identifier"),
    domain: str = Query("enterprise-attack", description="Framework domain"),
    caller: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
) -> DryRunPreviewResponse:
    """Executes a non-destructive dry-run preview parse of an external STIX 2.1 bundle."""
    try:
        return MitreService.execute_dry_run(
            db=db,
            raw_content=payload,
            version=version,
            domain=domain,
        )
    except MitreParsingError as mpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=mpe.message)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Dry run error: {str(exc)}")


@router.post("/import/approve", response_model=ImportExecutionResponse)
def approve_and_import(
    payload: Dict[str, Any],
    version: str = Query("14.1", description="Dataset version identifier"),
    domain: str = Query("enterprise-attack", description="Framework domain"),
    caller: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
) -> ImportExecutionResponse:
    """Applies an approved external STIX 2.1 dataset import and activates the release."""
    try:
        return MitreService.execute_import(
            db=db,
            raw_content=payload,
            version=version,
            domain=domain,
            initiated_by=caller,
            activate_immediately=True,
        )
    except MitreParsingError as mpe:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=mpe.message)
    except MitreError as me:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=me.message)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Import error: {str(exc)}")


@router.post("/import/rollback", response_model=RollbackResponse)
def rollback_active_version(
    req: RollbackRequest,
    caller: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
) -> RollbackResponse:
    """Restores the previously active dataset version without deleting historical records."""
    try:
        return MitreService.execute_rollback(
            db=db,
            target_version=req.target_version,
            reason=req.reason,
        )
    except MitreError as me:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=me.message)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Rollback error: {str(exc)}")

