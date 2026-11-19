"""Scoped bearer credentials for the HTTPS inventory ingestion PoC.

Only random high-entropy tokens are supported. The server stores SHA-256
digests, not bearer secrets. Treat token files as sensitive; 0600 is enforced
on POSIX. The scope is explicitly ONE existing profile, write imports only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
from uuid import uuid4

SCHEMA_VERSION = 1
MAX_STORE_BYTES = 128 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID32 = re.compile(r"^[0-9a-f]{32}$")


class CredentialsError(ValueError):
    pass


def _secure_file(path: Path) -> None:
    if path.is_symlink():
        raise CredentialsError("Credential path must not be a symbolic link")
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise CredentialsError("Credential file cannot be read") from exc
    if not stat.S_ISREG(mode):
        raise CredentialsError("Credential path must be a regular file")
    if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
        raise CredentialsError("Credential file permissions must be 0600 or stricter")


def load_store(path: Path) -> dict:
    """Validate the whole file; refuse malformed configuration (fail closed)."""
    _secure_file(path)
    if path.stat().st_size > MAX_STORE_BYTES:
        raise CredentialsError("Credential store exceeds size limit")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CredentialsError("Invalid credential store") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
        raise CredentialsError("Unsupported credential store format")
    entries = doc.get("tokens")
    if not isinstance(entries, list) or len(entries) > 1000:
        raise CredentialsError("Malformed token entries")
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"id", "profile_id", "sha256"}:
            raise CredentialsError("Malformed token entry")
        if not (isinstance(item["id"], str) and ID32.fullmatch(item["id"])
                and isinstance(item["profile_id"], str) and ID32.fullmatch(item["profile_id"])
                and isinstance(item["sha256"], str) and HEX64.fullmatch(item["sha256"])):
            raise CredentialsError("Invalid token entry")
        if item["id"] in seen:
            raise CredentialsError("Duplicate token ID")
        seen.add(item["id"])
    return doc


def _write_store(path: Path, store: dict) -> None:
    """Write atomically, and avoid ever writing a world-readable token digest."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(store, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_STORE_BYTES:
        raise CredentialsError("Credential store exceeds size limit")
    if path.exists() or path.is_symlink():
        _secure_file(path)
    fd, tmp = tempfile.mkstemp(prefix=".vulnfolio-cred-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600) if hasattr(os, "fchmod") else None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def issue_token(store_path: Path, profile_id: str, token_output: Path) -> str:
    """Issue a new token, writing the only plaintext copy to a 0600 file."""
    if not isinstance(profile_id, str) or not ID32.fullmatch(profile_id):
        raise CredentialsError("profile_id must be a 32-character lowercase hex ID")
    if token_output.exists() or token_output.is_symlink():
        raise CredentialsError("Token output exists; never overwrite an existing secret")
    if store_path.resolve() == token_output.resolve():
        raise CredentialsError("Credential store and token output must differ")
    store = load_store(store_path) if store_path.exists() else {
        "schema_version": SCHEMA_VERSION, "tokens": []
    }
    raw = "vf_" + secrets.token_urlsafe(32)
    record_id = uuid4().hex
    store["tokens"].append({
        "id": record_id, "profile_id": profile_id,
        "sha256": hashlib.sha256(raw.encode("ascii")).hexdigest()
    })
    token_output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(token_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise CredentialsError("Cannot create secure token output") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(raw + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        _write_store(store_path, store)
    except Exception:
        token_output.unlink(missing_ok=True)
        raise
    return record_id


def revoke_token(store_path: Path, token_id: str) -> bool:
    if not ID32.fullmatch(token_id):
        raise CredentialsError("Invalid token ID")
    store = load_store(store_path)
    old_count = len(store["tokens"])
    store["tokens"] = [entry for entry in store["tokens"] if entry["id"] != token_id]
    if len(store["tokens"]) == old_count:
        return False
    _write_store(store_path, store)
    return True


def authorized(store_path: Path, bearer: str, profile_id: str) -> bool:
    if not (isinstance(bearer, str) and bearer.startswith("vf_")
            and 30 <= len(bearer) <= 120 and bearer.isascii()):
        return False
    digest = hashlib.sha256(bearer.encode("ascii")).hexdigest()
    store = load_store(store_path)
    match = False
    for entry in store["tokens"]:
        equal_digest = secrets.compare_digest(entry["sha256"], digest)
        if equal_digest and entry["profile_id"] == profile_id:
            match = True
    return match


def read_token(path: Path) -> str:
    _secure_file(path)
    if path.stat().st_size > 256:
        raise CredentialsError("Bearer token file is unexpectedly large")
    try:
        token = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise CredentialsError("Cannot read bearer token file") from exc
    if not token.startswith("vf_") or not 30 <= len(token) <= 120:
        raise CredentialsError("Invalid bearer token file")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage scoped inventory upload tokens (secrets never printed)")
    actions = parser.add_subparsers(dest="action", required=True)
    issue = actions.add_parser("issue", help="write token to a NEW mode-0600 file")
    issue.add_argument("--store", type=Path, required=True)
    issue.add_argument("--profile", required=True)
    issue.add_argument("--token-output", type=Path, required=True)
    revoke = actions.add_parser("revoke", help="remove token ID (not the secret)")
    revoke.add_argument("--store", type=Path, required=True)
    revoke.add_argument("--id", required=True)
    listing = actions.add_parser("list", help="list IDs and scopes (no bearer values)")
    listing.add_argument("--store", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "issue":
            ident = issue_token(args.store, args.profile, args.token_output)
            print(f"Created scoped token ID {ident}; bearer written to {args.token_output}")
        elif args.action == "revoke":
            if not revoke_token(args.store, args.id):
                raise CredentialsError("No matching token ID")
            print("Revoked token ID " + args.id)
        else:
            store = load_store(args.store)
            for entry in store["tokens"]:
                print(entry["id"] + "  profile=" + entry["profile_id"])
    except CredentialsError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
