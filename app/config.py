"""Environment-backed settings.

Every value has a safe default, so `uvicorn app.main:app` works without any
configuration. Production deployments should set CORS_ORIGINS and, if an LLM is
used, LLM_API_KEY.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Tuple


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except ValueError:
        return default


def _origins() -> Tuple[str, ...]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return tuple(origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = "Sentinel API"
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    cors_origins: Tuple[str, ...] = field(default_factory=_origins)
    trust_proxy_headers: bool = field(default_factory=lambda: _bool("TRUST_PROXY_HEADERS", False))
    rate_limit_per_minute: int = field(default_factory=lambda: _int("RATE_LIMIT_PER_MINUTE", 30, 1))
    max_request_bytes: int = field(default_factory=lambda: _int("MAX_REQUEST_BYTES", 32_768, 1_024))
    max_message_length: int = 5_000
    max_url_length: int = 2_048
    lexicon_enabled: bool = field(default_factory=lambda: _bool("LEXICON_ENABLED", True))
    # Optional LLM second opinion. The rule engine always runs; this only adds
    # warnings and can raise (never lower) the rule-based score.
    llm_enabled: bool = field(default_factory=lambda: _bool("LLM_ENABLED", False))
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_base_url: str = field(
        default_factory=lambda: os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    )
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "gpt-4o-mini"))
    llm_timeout_seconds: float = field(
        default_factory=lambda: _float("LLM_TIMEOUT_SECONDS", 12.0, 1.0)
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
