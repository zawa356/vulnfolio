"""TLS-only, profile-scoped, bearer-authenticated ingest endpoint.

The legacy asset UI/API remains loopback-only. This is a SEPARATE write-only
route for bastion uploaders; it does not grant read access to inventories.
Run Uvicorn with direct TLS and --no-proxy-headers: proxy-origin assertions
are not a substitute for cryptographically authenticated TLS termination.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from fastapi import APIRouter, HTTPException, Request, Response

from vulnfolio.asset_storage import AssetRepository, NotFound
from vulnfolio.ingest_credentials import CredentialsError, authorized
from vulnfolio.ingest_http import read_inventory_json
from vulnfolio.inventory_import import ImportValidationError, InventoryImporter

ID32 = re.compile(r"^[0-9a-f]{32}$")


def build_ingest_router(repo: AssetRepository) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ingest", tags=["Authenticated HTTPS collector upload"])
    importer = InventoryImporter(repo)

    @router.post("/profiles/{profile_id}/imports", status_code=201)
    async def upload(profile_id: str, request: Request, response: Response):
        # Reject plaintext before attempting auth, without trusting Origin/Host.
        # With direct Uvicorn TLS, ASGI scope["scheme"] reflects the actual connection.
        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=403, detail="Direct HTTPS transport is required")
        # No CORS: collectors use server-to-server credentials, never browsers.
        if request.headers.get("origin"):
            raise HTTPException(status_code=403, detail="Browser-origin uploads are not supported")
        if not ID32.fullmatch(profile_id):
            raise HTTPException(status_code=404, detail="Upload endpoint not found")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") and len(auth) < 256 else ""
        store_filename = os.environ.get("VULNFOLIO_INGEST_TOKENS_FILE")
        if not store_filename:
            raise HTTPException(status_code=503, detail="Authenticated ingestion is not configured")
        try:
            allowed = authorized(Path(store_filename), token, profile_id)
        except (CredentialsError, OSError):
            # Never weaken auth or expose token paths when configuration is bad.
            raise HTTPException(status_code=503, detail="Ingestion credentials unavailable") from None
        if not allowed:
            raise HTTPException(status_code=401, detail="Invalid collector credentials",
                                headers={"WWW-Authenticate": "Bearer"})
        document = await read_inventory_json(request)
        try:
            data = importer.import_envelope(profile_id, document)
        except ImportValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        response.headers["Cache-Control"] = "no-store"
        return data

    return router
