"""Minimal authenticated upload-only ASGI entrypoint.

Use this app for a network-facing DIRECT TLS listener. It does not register
CVE APIs, asset management APIs, UI assets, Swagger or OpenAPI routes.

It is intentionally separate from vulnerability_api:app, which must remain
loopback-only until a production-grade authorization model exists.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.ingest_api import build_ingest_router


def create_ingest_app(db_path: str | Path | None = None) -> FastAPI:
    app = FastAPI(
        title="vulnfolio collector ingest",
        version="0.2.4",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    repo = AssetRepository(db_path)
    app.include_router(build_ingest_router(repo))
    return app


app = create_ingest_app()
