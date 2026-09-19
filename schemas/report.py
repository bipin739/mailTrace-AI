from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ReportGenerateRequest(BaseModel):
    analysis: Dict[str, Any] = Field(..., description="Full EmailAnalysisResponse payload or dictionary")
    case_id: Optional[str] = Field(None, description="Optional Case ID to associate with report")
    analyst_name: Optional[str] = Field("SOC Lead Analyst", description="Analyst name or investigator signature")
    classification_override: Optional[str] = Field(None, description="Optional analyst classification override")
    notes: Optional[str] = Field(None, description="Optional investigator notes or recommendations")


class ReportListItemResponse(BaseModel):
    id: str
    report_number: str
    title: str
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    email_sha256: Optional[str] = None
    threat_score: Optional[float] = 0.0
    severity: Optional[str] = "low"
    analyst_name: Optional[str] = "SOC Analyst"
    summary: Optional[str] = ""
    file_size_bytes: Optional[int] = 0
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    reports: List[ReportListItemResponse] = Field(default_factory=list)
    total: int = 0
