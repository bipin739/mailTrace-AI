from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.evidence import (
    EvidenceRecordResponse,
    AuditLogListResponse,
    InvestigationTimelineResponse
)
from backend.services.audit_service import AuditService

router = APIRouter(prefix="/api/audit", tags=["Evidence & Audit Trail"])


@router.get(
    "",
    response_model=AuditLogListResponse,
    summary="Query append-only forensic audit trail",
    description="Returns immutable historical audit logs with filtering by resource type, resource ID, action, or case."
)
def list_audit_logs(
    resource_type: Optional[str] = Query(None, description="Filter by resource type: email, case, report, evidence"),
    resource_id: Optional[str] = Query(None, description="Filter by resource identifier"),
    action: Optional[str] = Query(None, description="Filter by action code, e.g. EMAIL_UPLOADED, CASE_CREATED"),
    case_id: Optional[str] = Query(None, description="Filter by linked case UUID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    items, total = AuditService.list_audit_logs(
        db=db,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        case_id=case_id,
        skip=skip,
        limit=limit
    )
    return AuditLogListResponse(items=items, total=total)


@router.get(
    "/timeline/{identifier:path}",
    response_model=InvestigationTimelineResponse,
    summary="Get investigation timeline for an email, evidence, or case",
    description="Returns ordered chain-of-custody chronological timeline events for a given evidence ID, email SHA-256, or case ID."
)
def get_investigation_timeline(
    identifier: str,
    db: Session = Depends(get_db)
):
    timeline = AuditService.get_timeline(db, identifier=identifier)
    return timeline


# Evidence sub-router mounted under /api/evidence
evidence_router = APIRouter(prefix="/api/evidence", tags=["Evidence Integrity"])


@evidence_router.get(
    "/{identifier:path}/timeline",
    response_model=InvestigationTimelineResponse,
    summary="Get chain-of-custody investigation timeline for an evidence item"
)
def get_evidence_timeline_alias(
    identifier: str,
    db: Session = Depends(get_db)
):
    return AuditService.get_timeline(db, identifier=identifier)


@evidence_router.get(
    "/{identifier:path}",
    response_model=EvidenceRecordResponse,
    summary="Fetch evidence record and chain-of-custody details",
    description="Retrieves evidence details by evidence ID, SHA-256 hash, or internal UUID."
)
def get_evidence_record(
    identifier: str,
    db: Session = Depends(get_db)
):
    evidence = AuditService.get_evidence(db, identifier=identifier)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record '{identifier}' not found."
        )
    return EvidenceRecordResponse.model_validate(evidence)
