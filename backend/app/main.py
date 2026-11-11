"""FastAPI application factory."""

import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import text
from sqlalchemy.exc import DataError, DBAPIError, IntegrityError

from app.api.router import api_router
from app.core import ratelimit
from app.core.clientip import client_ip
from app.core.config import get_settings
from app.core.context import RequestContext, set_request_context
from app.core.errors import AppError, RateLimited
from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine, get_engine

log = get_logger("ctem.api")

REQUESTS = Counter("ctem_http_requests_total", "HTTP requests", ["method", "route", "status"])
LATENCY = Histogram("ctem_http_request_duration_seconds", "HTTP request latency", ["method", "route"])

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)


def _error(status: int, code: str, message: str, details: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message, "details": details or {}}})


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    get_engine()
    yield
    dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CTEM Platform API",
        version="0.1.0",
        description="Continuous Threat Exposure Management with AI exposure management.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
        )

    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        ip = client_ip(request)
        set_request_context(RequestContext(request_id=request_id, ip_address=ip,
                                           user_agent=request.headers.get("user-agent")))
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        path = request.url.path
        start = time.perf_counter()
        try:
            if path.startswith("/api/v1/auth/") and request.method == "POST":
                ratelimit.hit(f"auth:{ip}", settings.rate_limit_auth)
            elif path.startswith("/api/"):
                ratelimit.hit(f"api:{ip}", settings.rate_limit_api)
            response: Response = await call_next(request)
        except RateLimited as exc:
            response = _error(429, exc.code, exc.message, exc.details)
            response.headers["Retry-After"] = str(exc.details.get("retry_after_seconds", 60))
        route = getattr(request.scope.get("route"), "path", "unmatched")
        elapsed = time.perf_counter() - start
        REQUESTS.labels(request.method, route, response.status_code).inc()
        LATENCY.labels(request.method, route).observe(elapsed)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if path == "/api/docs":
            response.headers["Content-Security-Policy"] = DOCS_CSP
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers["X-Request-ID"] = request_id
        if path not in ("/healthz", "/readyz", "/metrics"):
            principal = getattr(request.state, "principal", None)
            log.info("http_request", method=request.method, path=path, status=response.status_code,
                     duration_ms=round(elapsed * 1000, 1), ip=ip,
                     user_id=str(principal.user_id) if principal else None,
                     organization_id=str(principal.organization_id) if principal else None)
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(_request: Request, exc: AppError):
        return _error(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError):
        issues = [{"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        return _error(422, "validation_failed", "Request validation failed", {"issues": issues})

    @app.exception_handler(IntegrityError)
    async def integrity_handler(_request: Request, exc: IntegrityError):
        log.warning("integrity_error", error=str(exc.orig)[:300])
        return _error(409, "conflict", "The request conflicts with existing data")

    @app.exception_handler(DBAPIError)
    async def db_handler(_request: Request, exc: DBAPIError):
        # RLS WITH CHECK violations surface here; never leak SQL to the client.
        if isinstance(exc, DataError):  # malformed input that reached the database (e.g. NUL bytes, out-of-range values)
            return _error(422, "validation_failed", "The request contains a value that cannot be processed")
        log.error("database_error", error=str(exc.orig)[:300])
        if "row-level security" in str(exc.orig):
            return _error(403, "forbidden", "Operation not permitted for this organization")
        return _error(500, "internal_error", "A database error occurred")

    @app.exception_handler(Exception)
    async def unhandled_handler(_request: Request, exc: Exception):
        log.error("unhandled_exception", exc_info=exc)
        return _error(500, "internal_error", "An unexpected error occurred")

    @app.get("/healthz", include_in_schema=False)
    def liveness() -> dict:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readiness() -> JSONResponse:
        checks: dict[str, str] = {}
        try:
            with get_engine().connect() as conn:
                conn.execute(text("select 1"))
                checks["database"] = "ok"
        except Exception as exc:  # readiness must report, not raise
            checks["database"] = f"error: {type(exc).__name__}"
        redis_state = ratelimit.redis_healthy()
        checks["redis"] = "not_configured" if redis_state is None else ("ok" if redis_state else "error")
        ok = checks["database"] == "ok" and checks["redis"] != "error"
        return JSONResponse(status_code=200 if ok else 503, content={"status": "ready" if ok else "degraded", "checks": checks})

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(api_router, prefix="/api/v1")

    if settings.otel_exporter_otlp_endpoint:
        from app.core.telemetry import instrument

        instrument(app)
    return app


app = create_app()
