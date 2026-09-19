from typing import List, Optional
from pydantic import BaseModel, Field


class AIAnalystAssessment(BaseModel):
    """
    Structured AI Analyst assessment derived strictly from deterministic forensic telemetry.
    The LLM consumes existing findings without being the source of truth or hallucinating unverified indicators.
    """
    summary: str = Field(..., description="Concise executive forensic summary of the findings")
    likely_attack_type: str = Field(..., description="Primary suspected attack classification (e.g. Credential Harvesting, Business Email Compromise, Malware Delivery, Brand Impersonation, Benign)")
    likely_objective: str = Field(..., description="Anticipated adversary motivation or target objective")
    key_evidence: List[str] = Field(default_factory=list, description="Grounding forensic signals and evidence corroborating the assessment")
    recommended_actions: List[str] = Field(default_factory=list, description="Prescriptive next steps and containment guidance for SOC analysts")
    limitations: List[str] = Field(default_factory=list, description="Known visibility boundaries, missing artifacts, or analytic caveats")
    available: bool = Field(True, description="Whether the AI analyst service successfully produced an assessment")
    provider: Optional[str] = Field(None, description="LLM provider identifier (e.g. gemini, openai, mock)")
    model: Optional[str] = Field(None, description="Model identifier used for assessment")
    error: Optional[str] = Field(None, description="Error reason or status explanation if unavailable")


class AIAnalystRequest(BaseModel):
    """
    Optional direct invocation request for AI Analyst assessment on an existing analysis object.
    """
    analysis_id: Optional[str] = Field(None, description="Reference ID for previously analyzed email")
