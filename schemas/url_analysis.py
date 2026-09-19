from typing import List, Optional
from pydantic import BaseModel, Field
from backend.schemas.lookalike import LookalikeDetectionResult


class URLFeatures(BaseModel):
    scheme: str = Field(..., description="URL scheme e.g. http, https")
    hostname: str = Field(..., description="Full hostname or IP address")
    registered_domain: str = Field("", description="Public-suffix aware registered apex domain (SLD + TLD)")
    subdomain: str = Field("", description="Subdomain prefix")
    subdomain_count: int = Field(0, description="Count of subdomain labels")
    port: Optional[int] = Field(None, description="Explicit port number if present")
    has_non_standard_port: bool = Field(False, description="Whether port is non-standard for the scheme")
    path: str = Field("", description="URL path component")
    path_length: int = Field(0, description="Length of path string")
    query: str = Field("", description="URL query string")
    query_length: int = Field(0, description="Length of query string")
    total_length: int = Field(0, description="Total character length of the URL")
    is_ip_host: bool = Field(False, description="Whether hostname is an IP address")
    ip_version: Optional[int] = Field(None, description="IP version (4 or 6) if host is an IP")
    is_punycode: bool = Field(False, description="Whether hostname uses punycode (xn--)")
    excessive_subdomains: bool = Field(False, description="Whether subdomain label count exceeds normal threshold (>= 3)")
    has_credentials: bool = Field(False, description="Whether URL authority contains embedded user credentials (user:pass@)")
    suspicious_keywords: List[str] = Field(default_factory=list, description="Suspicious keywords detected in URL path, query, or host")
    has_percent_encoding: bool = Field(False, description="Whether path or query contains percent-encoded characters")
    percent_encoding_count: int = Field(0, description="Count of percent-encoded byte sequences")
    unusual_char_density: bool = Field(False, description="Whether URL contains unusually high special character density")
    is_shortener: bool = Field(False, description="Whether domain matches a known URL shortening service")
    display_link_mismatch: bool = Field(False, description="Whether HTML visible text domain mismatches actual href domain")
    visible_text: Optional[str] = Field(None, description="Visible text from HTML anchor tag, if applicable")
    visible_text_domain: Optional[str] = Field(None, description="Domain extracted from HTML visible text, if any")
    lookalike: Optional[LookalikeDetectionResult] = Field(None, description="Lookalike brand impersonation findings for this domain")


class URLAnalysisResult(BaseModel):
    url: str = Field(..., description="Target URL analyzed")
    domain: str = Field(..., description="Registered domain or hostname")
    features: URLFeatures = Field(..., description="Extracted static non-invasive features")
    observations: List[str] = Field(default_factory=list, description="Forensic observations from static analysis")
    suspicion_score: int = Field(0, description="Static URL suspicion score (0 to 100)")
    suspicion_level: str = Field("low", description="Suspicion classification: low, suspicious, or high")
    score_reasons: List[str] = Field(default_factory=list, description="Transparent reasons contributing to the suspicion score")


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="URL string to analyze")
    visible_text: Optional[str] = Field(None, description="Optional visible anchor text from HTML link")
