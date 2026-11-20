"""Isolated TLS ingest ASGI entrypoint, including bounded audit and rate limit.

No CVE/global API, local inventory management, UI, Swagger or OpenAPI routes.
A failed audit write fails the request closed (client can safely retry because
the importer is idempotent), rather than claiming unrecorded success.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.ingest_api import build_ingest_router
from vulnfolio.ingest_audit import init_audit, record_audit
from vulnfolio.ingest_security import IngestRateLimiter


def create_ingest_app(
    db_path: str | Path | None = None,
    limiter: IngestRateLimiter | None = None,
) -> FastAPI:
    app = FastAPI(
        title="vulnfolio collector ingest",
        version="0.3.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    repo = AssetRepository(db_path)
    init_audit(repo)
    throttle = limiter if limiter is not None else IngestRateLimiter()
    app.include_router(build_ingest_router(repo, throttle))

    @app.middleware("http")
    async def audit_ingest(request: Request, call_next):
        # This app intentionally handles only ingestion. Never audit arbitrary
        # probe URL text, headers, body, credentials or client IP.
        audited_path = request.method == "POST" and request.url.path.startswith(
            "/api/v1/ingest/profiles/"
        ) and request.url.path.endswith("/imports")
        if not audited_path:
            return await call_next(request)
        try:
            result = await call_next(request)
            status = result.status_code
        except Exception:
            # No request data is persisted on unexpected errors.
            if not getattr(request.state, "audit_suppressed", False):
                record_audit(
                    repo, status=500,
                    profile_id=getattr(request.state, "audit_profile_id", None),
                    token_id=getattr(request.state, "audit_token_id", None),
                )
            raise
        result.headers["Cache-Control"] = "no-store"
        if not getattr(request.state, "audit_suppressed", False):
            try:
                record_audit(
                    repo, status=status,
                    profile_id=getattr(request.state, "audit_profile_id", None),
                    token_id=getattr(request.state, "audit_token_id", None),
                    duplicate=getattr(request.state, "audit_duplicate", False),
                    assets_seen=getattr(request.state, "audit_assets_seen", None),
                )
            except Exception:
                # Import might already be committed. Report a transient failure;
                # the uploader retries the same JSON, which is idempotent.
                return JSONResponse(
                    {"detail": "Ingestion audit unavailable"},
                    status_code=503,
                    headers={"Cache-Control": "no-store"},
                )
        return result

    return app


app = create_ingest_app()
