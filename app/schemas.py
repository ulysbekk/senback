"""Request and response models for POST /analyze.

The field names and accepted values match sentinel-frontend's API contract. The
frontend is tolerant of extra fields, but keeping this strict catches mistakes in
our own code before they reach the UI.
"""

from __future__ import annotations

from typing import List, Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

RiskLevel = Literal["low", "medium", "high", "critical"]

MAX_MESSAGE_LENGTH = 5_000
MAX_URL_LENGTH = 2_048


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    message: str = Field(description="The message to check.")
    url: Optional[str] = Field(default=None, description="Optional link from the message.")

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Paste the message you want to check.")
        if len(value) > MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"This message is {len(value)} characters. "
                f"Shorten it to {MAX_MESSAGE_LENGTH} or fewer."
            )
        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if len(value) > MAX_URL_LENGTH:
            raise ValueError(f"Links can be up to {MAX_URL_LENGTH} characters.")
        if any(char.isspace() for char in value):
            raise ValueError("That doesn't look like a web address.")

        try:
            parsed = urlsplit(value)
        except ValueError as error:
            raise ValueError("That doesn't look like a web address.") from error
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only http:// and https:// links can be checked.")
        return value


class Warning(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[RiskLevel] = None
    evidence: List[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    warnings: List[Warning] = Field(default_factory=list)
