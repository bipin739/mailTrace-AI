from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.case_service import CaseService
from backend.schemas.case import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseEmailCreateRequest,
    CaseNoteCreateRequest,
    CaseFindingCreateRequest,
    CaseListResponse,
    CaseDetailResponse,
    CaseEmailResponse,
    CaseNoteResponse,
    CaseFindingResponse
)

router = APIRouter(prefix="/api/cases", tags=["Case Management"])


@router.post(
    "",
    response_model=CaseDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new investigation case",
    description="Initializes a new SOC investigation case with a human-readable case number (e.g. CASE-2026-000001)."
)
def create_case_endpoint(
    request: CaseCreateRequest,
    db: Session = Depends(get_db)
):
    case = CaseService.create_case(db, request)
    return CaseService.get_case_detail(db, case.id)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List investigation cases",
    description="Returns paginated list of cases with optional status, severity, and search filters."
)
def list_cases_endpoint(
    status: Optional[str] = Query(None, description="Filter by status: open, investigating, resolved, escalated"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    search: Optional[str] = Query(None, description="Search query matching title, case number, or description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    items, total = CaseService.list_cases(
        db,
        status_filter=status,
        severity_filter=severity,
        search_query=search,
        skip=skip,
        limit=limit
    )
    return CaseListResponse(cases=items, total=total)


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get case details",
    description="Fetches full investigation case details, linked emails, notes, findings, timeline, and aggregated indicators."
)
def get_case_endpoint(
    case_id: str,
    db: Session = Depends(get_db)
):
    return CaseService.get_case_detail(db, case_id)


@router.patch(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Update case metadata, status, or severity",
    description="Modifies case attributes and logs transitions to the audit log."
)
def update_case_endpoint(
    case_id: str,
    request: CaseUpdateRequest,
    db: Session = Depends(get_db)
):
    CaseService.update_case(db, case_id, request)
    return CaseService.get_case_detail(db, case_id)


@router.post(
    "/{case_id}/emails",
    response_model=CaseEmailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyzed email to a case",
    description="Links an analyzed email to an investigation case. Rejects duplicates with 400 Bad Request."
)
def add_email_to_case_endpoint(
    case_id: str,
    request: CaseEmailCreateRequest,
    db: Session = Depends(get_db)
):
    return CaseService.add_email_to_case(db, case_id, request)


@router.delete(
    "/{case_id}/emails/{email_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove an email from a case",
    description="Detaches a linked email from an investigation case."
)
def remove_email_from_case_endpoint(
    case_id: str,
    email_id: str,
    db: Session = Depends(get_db)
):
    CaseService.remove_email_from_case(db, case_id, email_id)
    return None


@router.post(
    "/{case_id}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to a case",
    description="Records an analyst evidentiary observation or task note in the case."
)
def add_note_endpoint(
    case_id: str,
    request: CaseNoteCreateRequest,
    db: Session = Depends(get_db)
):
    return CaseService.add_note(db, case_id, request)


@router.post(
    "/{case_id}/findings",
    response_model=CaseFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a structured finding to a case",
    description="Flags a forensic finding (e.g. lookalike domain, credential harvesting) in the case."
)
def add_finding_endpoint(
    case_id: str,
    request: CaseFindingCreateRequest,
    db: Session = Depends(get_db)
):
    return CaseService.add_finding(db, case_id, request)
