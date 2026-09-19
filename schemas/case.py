from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class CaseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# -------------------------------------------------------------------------
# Sub-entity Schemas
# -------------------------------------------------------------------------

class CaseEmailBase(BaseModel):
    email_id: str = Field(..., description="Unique email identifier or filename")
    email_sha256: Optional[str] = Field(None, description="SHA-256 hash of email")
    subject: Optional[str] = Field("Untitled Email", description="Subject line")
    sender: Optional[str] = Field("unknown", description="Sender address")
    threat_score: Optional[float] = Field(0.0, description="Evaluated threat score (0-100)")
    severity: Optional[str] = Field("low", description="Evaluated threat severity")


class CaseEmailCreateRequest(CaseEmailBase):
    indicators: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Extracted indicators for aggregation")


class CaseEmailResponse(CaseEmailBase):
    id: str
    case_id: str
    added_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseNoteCreateRequest(BaseModel):
    author: Optional[str] = Field("SOC Analyst", description="Analyst name or username")
    note_text: str = Field(..., description="Analyst note or evidentiary observation")


class CaseNoteResponse(BaseModel):
    id: str
    case_id: str
    author: str
    note_text: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseFindingCreateRequest(BaseModel):
    finding_type: str = Field(..., description="Classification category (e.g. lookalike_domain, credential_harvesting)")
    title: str = Field(..., description="Concise finding headline")
    description: str = Field(..., description="Detailed forensic description of finding")
    severity: Optional[CaseSeverity] = Field(CaseSeverity.MEDIUM, description="Finding severity level")


class CaseFindingResponse(BaseModel):
    id: str
    case_id: str
    finding_type: str
    title: str
    description: str
    severity: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: str
    case_id: str
    action: str
    details: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AggregatedIndicators(BaseModel):
    domains: List[str] = Field(default_factory=list, description="Unique domains across linked emails")
    ips: List[str] = Field(default_factory=list, description="Unique IPs across linked emails")
    urls: List[str] = Field(default_factory=list, description="Unique URLs across linked emails")
    attachments: List[str] = Field(default_factory=list, description="Unique attachment filenames or hashes")


# -------------------------------------------------------------------------
# Case CRUD Schemas
# -------------------------------------------------------------------------

class CaseCreateRequest(BaseModel):
    title: str = Field(..., description="Case title")
    description: Optional[str] = Field("", description="Detailed incident description")
    severity: Optional[CaseSeverity] = Field(CaseSeverity.MEDIUM, description="Initial case severity")
    status: Optional[CaseStatus] = Field(CaseStatus.OPEN, description="Initial case status")
    initial_email: Optional[CaseEmailCreateRequest] = Field(None, description="Optional email to immediately attach to new case")


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, description="Updated case title")
    description: Optional[str] = Field(None, description="Updated description")
    status: Optional[CaseStatus] = Field(None, description="Updated status")
    severity: Optional[CaseSeverity] = Field(None, description="Updated severity")


class CaseListItemResponse(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str] = ""
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    email_count: int = 0
    note_count: int = 0
    finding_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class CaseDetailResponse(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str] = ""
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    emails: List[CaseEmailResponse] = Field(default_factory=list)
    notes: List[CaseNoteResponse] = Field(default_factory=list)
    findings: List[CaseFindingResponse] = Field(default_factory=list)
    audit_logs: List[AuditLogResponse] = Field(default_factory=list)
    aggregated_indicators: AggregatedIndicators = Field(default_factory=AggregatedIndicators)

    model_config = ConfigDict(from_attributes=True)


class CaseListResponse(BaseModel):
    cases: List[CaseListItemResponse] = Field(default_factory=list)
    total: int = 0
