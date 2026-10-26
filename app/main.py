from __future__ import annotations
import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .analysis.engine import AnalysisEngine
from .config import Settings, get_settings
from .limits import SlidingWindowLimiter
from .schemas import AnalyzeRequest, AnalyzeResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sentinel")

settings: Settings = get_settings()
engine = AnalysisEngine(settings)
limiter = SlidingWindowLimiter(settings.rate_limit_per_minute)

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Explainable investment-scam risk scoring for Sentinel.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


@app.middleware("http")
async def request_guard(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = request_id

    if request.method == "POST" and request.url.path == "/analyze":
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_large = int(content_length) > settings.max_request_bytes
            except ValueError:
                too_large = False
            if too_large:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large."},
                    headers={"X-Request-ID": request_id},
                )

        retry_after = limiter.retry_after(_client_ip(request, settings))
        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Wait a moment and try again."},
                headers={
                    "X-Request-ID": request_id,
                    "Retry-After": str(retry_after),
                },
            )

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    started = time.perf_counter()
    result = await engine.analyze(payload.message, payload.url)
    duration_ms = (time.perf_counter() - started) * 1000
    logger.info(
        "analyze request_id=%s score=%s level=%s warnings=%d message_len=%d has_url=%s ms=%.1f",
        getattr(request.state, "request_id", "-"),
        result.risk_score,
        result.risk_level,
        len(result.warnings),
        len(payload.message),
        payload.url is not None,
        duration_ms,
    )
    return result


@app.exception_handler(Exception)
async def unhandled_error(request: Request, error: Exception) -> JSONResponse:
    logger.exception(
        "unhandled error request_id=%s",
        getattr(request.state, "request_id", "-"),
        exc_info=error,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "The analysis service ran into a problem. Try again in a moment."},
    )


def _client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",", 1)[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"
