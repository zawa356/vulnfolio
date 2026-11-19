"""Upload an existing CollectionEnvelope over verified HTTPS.

This module NEVER collects from hosts, and NEVER deletes the local source
JSON file. It uses a private token file, no insecure TLS option, no redirects,
and retries only transient failures.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.parse import urlsplit

import httpx

from vulnfolio.ingest_credentials import CredentialsError, read_token
from vulnfolio.ingest_http import MAX_IMPORT_BYTES
from vulnfolio.inventory_import import ImportValidationError, validate_envelope

ID32 = re.compile(r"^[0-9a-f]{32}$")
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


class UploadError(ValueError):
    pass


def endpoint_url(base_url: str, profile_id: str) -> str:
    if not ID32.fullmatch(profile_id):
        raise UploadError("Invalid Profile ID; expected a lowercase 32-character hex identifier")
    try:
        value = urlsplit(base_url)
    except ValueError as exc:
        raise UploadError("Invalid upload URL") from exc
    if (value.scheme != "https" or not value.hostname or value.username or value.password
            or value.query or value.fragment or value.path not in ("", "/")):
        raise UploadError("Upload base URL must be an HTTPS origin without credentials, path or query")
    try:
        port = value.port
    except ValueError as exc:
        raise UploadError("Invalid upload URL port") from exc
    host = f"[{value.hostname}]" if ":" in value.hostname else value.hostname
    origin = f"https://{host}" + (f":{port}" if port is not None else "")
    return origin + f"/api/v1/ingest/profiles/{profile_id}/imports"


def envelope_bytes(path: Path, profile_id: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise UploadError("Inventory JSON must be an existing regular file, not a symlink")
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise UploadError("Inventory JSON exceeds the 2 MiB server limit")
    data = path.read_bytes()
    if len(data) > MAX_IMPORT_BYTES:
        raise UploadError("Inventory JSON exceeds the 2 MiB server limit")
    try:
        document = json.loads(data.decode("utf-8"))
        validate_envelope(document, profile_id)
    except (UnicodeError, ValueError, ImportValidationError) as exc:
        raise UploadError(f"Invalid CollectionEnvelope JSON: {exc}") from exc
    return data


def send(
    base_url: str, profile_id: str, document: bytes, token: str,
    ca_file: Path | None = None, attempts: int = 3,
    _transport: httpx.BaseTransport | None = None,
) -> dict:
    url = endpoint_url(base_url, profile_id)
    if not 1 <= attempts <= 5:
        raise UploadError("Retry attempts must be 1..5")
    if not token.startswith("vf_"):
        raise UploadError("Invalid token format")
    # Always verify certificates and server name. A supplied CA is trusted
    # in addition to standard system roots as applicable to the SSL context.
    try:
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    except (OSError, ssl.SSLError) as exc:
        raise UploadError("Cannot load TLS trust certificates") from exc
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "vulnfolio-collector/0.2",
    }
    # trust_env=False avoids unintended environment proxying of bearer secrets.
    with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=12,
                      transport=_transport) as client:
        for attempt in range(1, attempts + 1):
            try:
                result = client.post(url, content=document, headers=headers)
            except httpx.TransportError as exc:
                if attempt == attempts:
                    raise UploadError("HTTPS transport failed; local JSON remains available") from exc
                time.sleep(min(2 ** (attempt - 1), 8))
                continue
            if result.status_code in (200, 201):
                try:
                    body = result.json()
                except ValueError as exc:
                    raise UploadError("Server response is not valid JSON") from exc
                if not isinstance(body, dict) or "import_id" not in body:
                    raise UploadError("Server returned an unexpected import acknowledgement")
                return body
            if result.status_code in RETRYABLE_STATUSES and attempt < attempts:
                time.sleep(min(2 ** (attempt - 1), 8))
                continue
            # All redirects, 4xx other than 429, and remaining 5xx are terminal.
            # Do not echo server body: it may contain private information.
            raise UploadError(f"Upload not accepted (HTTP {result.status_code}); local JSON retained")
    raise UploadError("Upload failed; local JSON retained")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verified HTTPS upload of a collected JSON envelope")
    parser.add_argument("--base-url", required=True, help="HTTPS origin, e.g. https://host:8443")
    parser.add_argument("--profile", required=True, help="destination profile ID")
    parser.add_argument("--input", type=Path, required=True, help="previously collected local JSON")
    parser.add_argument("--token-file", type=Path, required=True, help="mode-0600 bearer secret file")
    parser.add_argument("--ca-file", type=Path, help="additional certificate authority for test/private PKI")
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()
    try:
        data = envelope_bytes(args.input, args.profile)
        token = read_token(args.token_file)
        result = send(args.base_url, args.profile, data, token,
                      ca_file=args.ca_file, attempts=args.attempts)
    except (UploadError, CredentialsError, OSError) as exc:
        parser.error(str(exc))
    print("Imported batch " + str(result["import_id"]) +
          " (duplicate=" + str(bool(result.get("duplicate", False))).lower() +
          ", assets=" + str(result.get("assets_seen", "?")) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
