"""FastAPI application factory for the control plane + console API + console UI."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from neurawall import __version__
from neurawall.core.config import Settings, get_settings
from neurawall.core.errors import (
    IntegrityFailure,
    ModelFault,
    NeuraWallError,
    NotFound,
    PolicyViolation,
    RecoverableError,
    ValidationFailure,
)
from neurawall.core.logging import configure_logging, get_logger, new_trace_id, set_trace_id
from neurawall.core.telemetry import REGISTRY
from neurawall.security.ratelimit import KeyedRateLimiter
from neurawall.services.control_plane.api.deps import Unauthenticated
from neurawall.services.control_plane.api.routes import agent, api, public
from neurawall.services.control_plane.service import ControlPlane

log = get_logger(__name__)
_requests = REGISTRY.counter("neurawall_http_requests_total", "HTTP requests by status class")
_latency = REGISTRY.histogram("neurawall_http_request_seconds", "HTTP request latency")

MAX_BODY_BYTES = 8 * 1024 * 1024
STATIC_DIR = Path(__file__).parent / "static"

_STATUS: list[tuple[type[NeuraWallError], int]] = [
    (Unauthenticated, 401),
    (NotFound, 404),
    (ValidationFailure, 422),
    (IntegrityFailure, 409),
    (PolicyViolation, 403),
    (ModelFault, 502),
    (RecoverableError, 503),
]

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' "
    "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
    "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)


def create_app(
    settings: Settings | None = None,
    *,
    control_plane: ControlPlane | None = None,
    start_background: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json_output=settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cp = control_plane or ControlPlane(settings)
        app.state.cp = cp
        if start_background:
            cp.start_background()
        log.info(
            "control plane started",
            version=__version__,
            env=settings.environment,
            advisor=cp.advisor.mode,
            bundle=cp.latest_version(),
        )
        yield
        cp.stop()

    app = FastAPI(
        title="NeuraWall Control Plane",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.login_limiter = KeyedRateLimiter(
        settings.auth.login_rate_per_minute / 60, burst=settings.auth.login_rate_per_minute
    )
    api_limiter = KeyedRateLimiter(rate_per_second=50, burst=200)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.middleware("http")
    async def envelope(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        trace = request.headers.get("x-trace-id", "")[:32] or new_trace_id()
        token = set_trace_id(trace)
        try:
            length = request.headers.get("content-length")
            if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
                return JSONResponse({"error": "payload_too_large"}, status_code=413)
            client = request.client.host if request.client else "unknown"
            if request.url.path.startswith("/api/") and not api_limiter.allow(client):
                return JSONResponse(
                    {"error": "rate_limited", "message": "slow down"}, status_code=429
                )
            with _latency.time():
                response = await call_next(request)
            _requests.inc(status=f"{response.status_code // 100}xx")
            response.headers["X-Trace-Id"] = trace
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
            if not request.url.path.startswith("/api/docs"):
                response.headers["Content-Security-Policy"] = _CSP
            if settings.public_url.startswith("https://"):
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )
            if request.url.path.startswith("/api/"):
                response.headers["Cache-Control"] = "no-store"
            return response
        finally:
            set_trace_id(None)
            del token

    @app.exception_handler(NeuraWallError)
    async def domain_error(_: Request, exc: NeuraWallError) -> JSONResponse:
        status = next((code for cls, code in _STATUS if isinstance(exc, cls)), 400)
        if status >= 500:
            log.warning("request failed", error=exc.message, code=exc.code)
        return JSONResponse({"error": exc.code, "message": exc.message}, status_code=status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", []))[-3:], "msg": str(e.get("msg", ""))[:200]}
            for e in exc.errors()[:10]
        ]
        return JSONResponse(
            {"error": "validation_failure", "message": "invalid request", "details": errors},
            status_code=422,
        )

    app.include_router(public)
    app.include_router(api)
    app.include_router(agent)
    _mount_console(app)
    return app


def _mount_console(app: FastAPI) -> None:
    index = STATIC_DIR / "index.html"
    if not index.exists():

        @app.get("/", include_in_schema=False)
        def no_console() -> JSONResponse:
            return JSONResponse(
                {
                    "service": "neurawall",
                    "version": __version__,
                    "console": "not built — run `npm run build` in console/",
                    "api_docs": "/api/docs",
                }
            )

        return
    if (STATIC_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> Response:
        if path.startswith(("api/", "healthz", "readyz", "metrics")):
            return JSONResponse({"error": "not_found"}, status_code=404)
        root = os.path.realpath(STATIC_DIR)
        try:
            full = os.path.realpath(os.path.join(root, path))
        except (ValueError, OSError):  # e.g. an embedded NUL byte: not a file, not a 500
            return JSONResponse({"error": "not_found"}, status_code=404)
        if path and full.startswith(root + os.sep) and os.path.isfile(full):
            return FileResponse(full)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
