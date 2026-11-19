"""Private M1 profile/asset APIs. Local-only gate is not full authentication."""
from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from vulnfolio.asset_storage import AssetRepository, Conflict, NotFound
from vulnfolio.inventory_import import InventoryImporter, ImportValidationError
from vulnfolio.ingest_http import read_inventory_json

PRIVATE_PREFIX = "/api/v1"


def require_local(request: Request) -> None:
    """Reject non-loopback peers and cross-origin browser requests.

    Do not expose this proof of concept through a reverse proxy: reverse
    proxies can make remote traffic appear loopback. Production needs auth.
    """
    peer = request.client.host if request.client else ""
    try:
        if not ip_address(peer).is_loopback:
            raise HTTPException(403, detail="Private inventory is restricted to loopback")
    except ValueError as exc:
        raise HTTPException(403, detail="Private inventory is restricted to loopback") from exc
    origin = request.headers.get("origin")
    if origin:
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
        if origin != expected:
            raise HTTPException(403, detail="Cross-origin private requests are not allowed")


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProfileInput(StrictInput):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)


class AssetInput(StrictInput):
    name: str = Field(min_length=1, max_length=180)
    os_family: str = Field(default="", max_length=80)
    os_version: str = Field(default="", max_length=120)


class ProductInput(StrictInput):
    name: str = Field(min_length=1, max_length=180)
    vendor: str = Field(default="", max_length=180)
    version: str = Field(default="", max_length=120)


class AssessmentInput(StrictInput):
    status: str = Field(min_length=1, max_length=32)
    note: str = Field(default="", max_length=1000)


def translate_error(error: Exception) -> None:
    if isinstance(error, NotFound):
        raise HTTPException(status_code=404, detail=str(error)) from error
    if isinstance(error, Conflict):
        raise HTTPException(status_code=409, detail=str(error)) from error
    if isinstance(error, ValueError):
        raise HTTPException(status_code=422, detail=str(error)) from error
    raise error


def build_asset_router(repo: AssetRepository) -> APIRouter:
    importer = InventoryImporter(repo)
    router = APIRouter(prefix=PRIVATE_PREFIX, dependencies=[Depends(require_local)],
                       tags=["Private inventory (local-only PoC)"])

    @router.get("/profiles")
    def profiles():
        return {"data": repo.list_profiles()}

    @router.post("/profiles", status_code=201)
    def create_profile(data: ProfileInput):
        try:
            return repo.create_profile(data.name, data.description)
        except (NotFound, Conflict, ValueError) as exc:
            translate_error(exc)

    @router.get("/profiles/{profile_id}")
    def profile(profile_id: str):
        try:
            return repo.get_profile(profile_id)
        except NotFound as exc:
            translate_error(exc)

    @router.get("/profiles/{profile_id}/assets")
    def assets(profile_id: str):
        try:
            return {"data": repo.list_assets(profile_id)}
        except NotFound as exc:
            translate_error(exc)

    @router.post("/profiles/{profile_id}/assets", status_code=201)
    def create_asset(profile_id: str, data: AssetInput):
        try:
            return repo.add_asset(profile_id, data.name, data.os_family, data.os_version)
        except (NotFound, Conflict, ValueError) as exc:
            translate_error(exc)

    @router.get("/assets/{asset_id}/products")
    def products(asset_id: str):
        try:
            return {"data": repo.list_products(asset_id)}
        except NotFound as exc:
            translate_error(exc)

    @router.post("/assets/{asset_id}/products", status_code=201)
    def add_product(asset_id: str, data: ProductInput):
        try:
            return repo.add_product(asset_id, data.name, data.vendor, data.version)
        except (NotFound, Conflict, ValueError) as exc:
            translate_error(exc)

    @router.delete("/products/{product_id}", status_code=204)
    def delete_product(product_id: str):
        try:
            repo.delete_product(product_id)
        except NotFound as exc:
            translate_error(exc)
        return Response(status_code=204)

    @router.post("/profiles/{profile_id}/imports", status_code=201)
    async def import_inventory(profile_id: str, request: Request):
        """Accept a validated canonical JSON envelope, never scanner-specific raw output."""
        document = await read_inventory_json(request)
        try:
            return importer.import_envelope(profile_id, document)
        except (ImportValidationError, NotFound, ValueError) as exc:
            translate_error(exc)

    @router.get("/profiles/{profile_id}/imports")
    def imports(profile_id: str):
        try:
            return {"data": importer.list_imports(profile_id)}
        except NotFound as exc:
            translate_error(exc)

    @router.get("/assets/{asset_id}/inventory")
    def inventory_snapshot(asset_id: str):
        try:
            return {"snapshot": importer.asset_snapshot(asset_id)}
        except NotFound as exc:
            translate_error(exc)

    @router.get("/profiles/{profile_id}/candidates")
    def candidates(profile_id: str, include_closed: bool = False):
        try:
            return repo.candidates(profile_id, include_closed=include_closed)
        except NotFound as exc:
            translate_error(exc)

    @router.put("/assets/{asset_id}/assessments/{cve_id}")
    def assessment(asset_id: str, cve_id: str, data: AssessmentInput):
        try:
            return repo.record_assessment(asset_id, cve_id, data.status, data.note)
        except (NotFound, ValueError) as exc:
            translate_error(exc)

    @router.get("/assets/{asset_id}/assessments/{cve_id}/history")
    def assessment_history(asset_id: str, cve_id: str):
        try:
            return {"data": repo.list_assessment_history(asset_id, cve_id)}
        except (NotFound, ValueError) as exc:
            translate_error(exc)

    return router
