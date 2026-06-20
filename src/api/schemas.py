"""
Pydantic request/response models for the Phishing Detection API.
Encapsulates data contracts and input validation (Encapsulation).
"""
from typing import Literal, Optional

from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    """Request body for the /predict endpoint.

    Encapsulates input data with validation constraints to prevent
    oversized payloads from causing DoS or OOM issues.
    """

    url: str
    html_content: str = ""
    screenshot_base64: str = ""

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 characters)")
        return v.strip()

    @field_validator("html_content")
    @classmethod
    def validate_html(cls, v: str) -> str:
        if len(v) > 500_000:
            # Truncate HTML instead of crashing the request
            return v[:500_000]
        return v

    @field_validator("screenshot_base64")
    @classmethod
    def validate_screenshot(cls, v: str) -> str:
        if len(v) > 15_000_000:
            # Drop oversized screenshots gracefully so other analyzers can still run
            return ""
        return v


class AnalysisReason(BaseModel):
    """A single reason contributing to the final verdict."""

    message: str
    type: Literal["safe", "danger", "warning"]


class AnalysisDetails(BaseModel):
    """Detailed analysis breakdown from all modules."""

    url_score: float = 0.0
    url_threshold: Optional[float] = None
    text_score: float = 0.0
    text_threshold: Optional[float] = None
    text_backend: Optional[str] = None
    logo_detected: list[str] = []
    logo_mismatch: bool = False
    modules_run: list[str] = []
    reasons: list[AnalysisReason] = []


class ScanResponse(BaseModel):
    """Response body for the /predict endpoint."""

    url: str
    final_verdict: Literal["SAFE", "WARNING", "PHISHING", "ERROR"]
    confidence: float
    details: AnalysisDetails
