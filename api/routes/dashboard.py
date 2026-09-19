from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.dashboard_service import DashboardService
from backend.schemas.dashboard import (
    DashboardSummaryResponse,
    DashboardEmailListResponse
)

router = APIRouter(prefix="/api/dashboard", tags=["Analyst Dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get SOC analyst dashboard telemetry summary",
    description="Returns aggregated metrics, severity distribution, analysis trend, top suspicious domains, infrastructure countries, auth failure breakdown, recent cases, and recent email analyses based on real database records."
)
def get_dashboard_summary(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in trend telemetry"),
    recent_limit: int = Query(5, ge=1, le=50, description="Max recent cases and emails to include"),
    db: Session = Depends(get_db)
):
    return DashboardService.get_summary(db=db, days=days, recent_limit=recent_limit)


@router.get(
    "/emails",
    response_model=DashboardEmailListResponse,
    status_code=status.HTTP_200_OK,
    summary="List analyzed emails with pagination",
    description="Returns paginated list of analyzed emails for SOC inspection."
)
def list_dashboard_emails(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db)
):
    items, total = DashboardService.list_emails(db=db, skip=skip, limit=limit)
    return DashboardEmailListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit
    )
