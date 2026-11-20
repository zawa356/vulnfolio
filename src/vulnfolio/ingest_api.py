"""Direct-TLS, profile-scoped, upload-only endpoint.

Credential expiry and bounded single-process throttling are enforced here;
safe structured auditing is done in the dedicated ingest_server application.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from fastapi import APIRouter, HTTPException, Request, Response

from vulnfolio.asset_storage import AssetRepository, NotFound
from vulnfolio.ingest_credentials import CredentialsError, authenticate_token
from vulnfolio.ingest_http import read_inventory_json
from vulnfolio.ingest_security import IngestRateLimiter
from vulnfolio.inventory_import import ImportValidationError, InventoryImporter

ID32 = re.compile(r"^[0-9a-f]{32}$")


def _too_many(wait: int) -> None:
    raise HTTPException(status_code=429, detail="Upload rate limit exceeded",
                        headers={"Retry-After": str(wait)})


def build_ingest_router(repo: AssetRepository, limiter: IngestRateLimiter) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ingest", tags=["Authenticated HTTPS collector upload"])
    importer = InventoryImporter(repo)

    @router.post("/profiles/{profile_id}/imports", status_code=201)
    async def upload(profile_id: str, request: Request, response: Response):
        # Audit only a validated profile identifier, never arbitrary URL input.
        if ID32.fullmatch(profile_id):
            request.state.audit_profile_id = profile_id
        if request.scope.get("scheme") != "https":
            raise HTTPException(status_code=403, detail="Direct HTTPS transport is required")
        if request.headers.get("origin"):
            raise HTTPException(status_code=403, detail="Browser-origin uploads are not supported")

        peer = request.client.host if request.client else "unknown"
        wait, first = limiter.check_peer(peer)
        if wait:
            request.state.audit_suppressed = not first  # Avoid DB writes on every blocked request.
            _too_many(wait)
        if not ID32.fullmatch(profile_id):
            raise HTTPException(status_code=404, detail="Upload endpoint not found")

        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") and len(auth) < 256 else ""
        store_filename = os.environ.get("VULNFOLIO_INGEST_TOKENS_FILE")
        if not store_filename:
            raise HTTPException(status_code=503, detail="Authenticated ingestion is not configured")
        try:
            token_id = authenticate_token(Path(store_filename), token, profile_id)
        except (CredentialsError, OSError):
            raise HTTPException(status_code=503, detail="Ingestion credentials unavailable") from None
        if token_id is None:
            # Same response for nonexistent, wrong-profile, revoked or expired tokens.
            raise HTTPException(status_code=401, detail="Invalid collector credentials",
                                headers={"WWW-Authenticate": "Bearer"})

        request.state.audit_token_id = token_id
        wait, first = limiter.check_token(token_id)
        if wait:
            request.state.audit_suppressed = not first
            _too_many(wait)

        document = await read_inventory_json(request)
        try:
            data = importer.import_envelope(profile_id, document)
        except (ImportValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        request.state.audit_duplicate = bool(data.get("duplicate", False))
        request.state.audit_assets_seen = data.get("assets_seen")
        response.headers["Cache-Control"] = "no-store"
        return data

    return router
