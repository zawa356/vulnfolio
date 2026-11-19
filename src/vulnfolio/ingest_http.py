"""Shared bounded JSON reader for local and remote inventory ingestion."""
from __future__ import annotations

import json

from fastapi import HTTPException, Request

MAX_IMPORT_BYTES = 2 * 1024 * 1024


async def read_inventory_json(request: Request):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_IMPORT_BYTES:
                raise HTTPException(status_code=413, detail="Maximum upload size is 2 MiB")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    parts: list[bytes] = []
    total = 0
    async for part in request.stream():
        total += len(part)
        if total > MAX_IMPORT_BYTES:
            raise HTTPException(status_code=413, detail="Maximum upload size is 2 MiB")
        parts.append(part)
    try:
        return json.loads(b"".join(parts).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid UTF-8 JSON envelope") from exc
