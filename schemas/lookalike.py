from typing import List, Optional
from pydantic import BaseModel, Field


class LookalikeDetectionResult(BaseModel):
    """Result of suspicious domain similarity and brand impersonation analysis."""
    domain: str = Field(..., description="The observed domain or hostname")
    suspected_brand: str = Field(..., description="Reference legitimate brand domain (e.g. microsoft.com)")
    brand_name: str = Field(..., description="Human-readable brand name (e.g. Microsoft)")
    similarity: float = Field(..., description="Normalized similarity score between 0.0 and 1.0")
    techniques: List[str] = Field(default_factory=list, description="List of detected lookalike techniques")
    confidence_label: str = Field("Potential brand impersonation", description="Assessment confidence label")
    details: Optional[str] = Field(None, description="Detailed explanation of the findings")
