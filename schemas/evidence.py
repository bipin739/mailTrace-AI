from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class EvidenceRecordResponse(BaseModel):
    id: str = Field(..., description="Internal UUID of the evidence record")
    evidence_id: str = Field(..., description="Unique chain-of-custody evidence identifier, e.g. EVD-A1B2C3D4")
    sha256: str = Field(..., description="Cryptographic SHA-256 digest of original email bytes")
    original_filename: str = Field(..., description="Original file name when uploaded")
    upload_timestamp: datetime = Field(..., description="UTC timestamp when evidence was recorded")
    size: int = Field(..., description="File size in bytes")
    uploader: Optional[str] = Field("SOC Analyst", description="Uploader or analyst identity")

    model_config = ConfigDict(from_attributes=True)


class AuditLogItemResponse(BaseModel):
    id: str = Field(..., description="Audit record UUID")
    timestamp: datetime = Field(..., description="Event timestamp in UTC")
    user: Optional[str] = Field("SOC Analyst", description="Actor or service executing the action")
    action: str = Field(..., description="Meaningful forensic action code, e.g. EMAIL_UPLOADED, CASE_CREATED")
    resource_type: str = Field(..., description="Target resource type, e.g. email, case, report, evidence")
    resource_id: str = Field(..., description="Target resource identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized audit metadata (no raw email bodies or secrets)")
    case_id: Optional[str] = Field(None, description="Linked case ID if applicable")
    details: Optional[str] = Field(None, description="Human-readable description snippet")

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    items: List[AuditLogItemResponse] = Field(default_factory=list)
    total: int = Field(0, description="Total matching audit logs count")


class InvestigationTimelineItem(BaseModel):
    id: str = Field(..., description="Audit entry ID")
    timestamp: datetime = Field(..., description="Exact event UTC timestamp")
    time_display: str = Field(..., description="Formatted local/UTC time string, e.g. 10:31")
    action: str = Field(..., description="Action code, e.g. EMAIL_UPLOADED")
    title: str = Field(..., description="Concise human-readable timeline action title, e.g. 'Email uploaded'")
    description: Optional[str] = Field(None, description="Additional contextual details")
    user: Optional[str] = Field("SOC Analyst", description="Analyst or system component responsible")
    resource_type: str = Field(..., description="Resource category")
    resource_id: str = Field(..., description="Identifier of primary resource")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized metadata")


class InvestigationTimelineResponse(BaseModel):
    evidence_id: Optional[str] = Field(None, description="Associated evidence identifier")
    sha256: Optional[str] = Field(None, description="Cryptographic SHA-256 digest")
    events: List[InvestigationTimelineItem] = Field(default_factory=list, description="Chronological timeline events")
    total: int = Field(0, description="Count of timeline events")
