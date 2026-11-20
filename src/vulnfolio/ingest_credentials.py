"""Profile-scoped, expiring, randomly generated inventory upload tokens.

Token Store v2 records only a SHA-256 digest, scope, issuance and expiration.
Legacy v1 files MUST be explicitly migrated to finite-lifetime v2 before use.
On POSIX we require mode 0600; Windows ACL validation remains future work.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
from uuid import uuid4

SCHEMA_VERSION = 2
MAX_STORE_BYTES = 128 * 1024
DEFAULT_TTL_HOURS = 168  # 7 days
MAX_TTL_HOURS = 720  # 30 days
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID32 = re.compile(r"^[0-9a-f]{32}$")
TOKEN_FIELDS = frozenset({"id", "profile_id", "sha256", "issued_at", "expires_at"})
LEGACY_FIELDS = frozenset({"id", "profile_id", "sha256"})


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


def _valid_identity(item: dict) -> bool:
    return (
        isinstance(item.get("id"), str) and ID32.fullmatch(item["id"]) is not None
        and isinstance(item.get("profile_id"), str)
        and ID32.fullmatch(item["profile_id"]) is not None
        and isinstance(item.get("sha256"), str)
        and HEX64.fullmatch(item["sha256"]) is not None
    )


def _read_file(path: Path) -> dict:
    _secure_file(path)
    if path.stat().st_size > MAX_STORE_BYTES:
        raise CredentialsError("Credential store exceeds size limit")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CredentialsError("Invalid credential store") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "tokens"}:
        raise CredentialsError("Unsupported credential store format")
    return doc


def _validate_store(doc: dict, version: int) -> dict:
    if doc["schema_version"] != version:
        raise CredentialsError("Token Store version mismatch; explicitly migrate legacy v1 with 'migrate'")
    entries = doc["tokens"]
    if not isinstance(entries, list) or len(entries) > 1000:
        raise CredentialsError("Malformed token entries")
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    for item in entries:
        expected = TOKEN_FIELDS if version == SCHEMA_VERSION else LEGACY_FIELDS
        if not isinstance(item, dict) or set(item) != expected or not _valid_identity(item):
            raise CredentialsError("Malformed token entry")
        if item["id"] in seen_ids or item["sha256"] in seen_digests:
            raise CredentialsError("Duplicate token ID or digest")
        seen_ids.add(item["id"])
        seen_digests.add(item["sha256"])
        if version == SCHEMA_VERSION:
            issued = item["issued_at"]
            expires = item["expires_at"]
            # bool is a subclass of int: explicitly forbid it.
            if not (type(issued) is int and type(expires) is int
                    and 0 < issued < expires <= issued + MAX_TTL_HOURS * 3600):
                raise CredentialsError("Invalid token validity window")
    return doc


def load_store(path: Path) -> dict:
    """Load only v2; legacy tokens cannot silently retain unlimited lifetime."""
    return _validate_store(_read_file(path), SCHEMA_VERSION)


def _write_store(path: Path, store: dict) -> None:
    _validate_store(store, SCHEMA_VERSION)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(store, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_STORE_BYTES:
        raise CredentialsError("Credential store exceeds size limit")
    if path.exists() or path.is_symlink():
        _secure_file(path)
    fd, tmp = tempfile.mkstemp(prefix=".vulnfolio-cred-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _expiry_hours(hours: int) -> int:
    if type(hours) is not int or not 1 <= hours <= MAX_TTL_HOURS:
        raise CredentialsError(f"ttl-hours must be 1..{MAX_TTL_HOURS}")
    return hours * 3600


def issue_token(store_path: Path, profile_id: str, token_output: Path,
                ttl_hours: int = DEFAULT_TTL_HOURS) -> str:
    """Issue a finite-lifetime token, writing one plaintext copy to a 0600 file."""
    seconds = _expiry_hours(ttl_hours)
    if not isinstance(profile_id, str) or not ID32.fullmatch(profile_id):
        raise CredentialsError("profile_id must be a 32-character lowercase hex ID")
    if token_output.exists() or token_output.is_symlink():
        raise CredentialsError("Token output exists; never overwrite an existing secret")
    if store_path.resolve() == token_output.resolve():
        raise CredentialsError("Credential store and token output must differ")
    store = load_store(store_path) if store_path.exists() else {
        "schema_version": SCHEMA_VERSION, "tokens": []
    }
    if len(store["tokens"]) >= 1000:
        raise CredentialsError("Maximum token entries reached")
    issued_at = int(time.time())
    raw = "vf_" + secrets.token_urlsafe(32)
    record_id = uuid4().hex
    store["tokens"].append({
        "id": record_id, "profile_id": profile_id,
        "sha256": hashlib.sha256(raw.encode("ascii")).hexdigest(),
        "issued_at": issued_at, "expires_at": issued_at + seconds,
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


def migrate_store(store_path: Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> int:
    """Convert v1 digests in place. Existing plaintext tokens remain unchanged."""
    seconds = _expiry_hours(ttl_hours)
    old = _validate_store(_read_file(store_path), 1)
    now = int(time.time())
    migrated = {
        "schema_version": SCHEMA_VERSION,
        "tokens": [
            {**item, "issued_at": now, "expires_at": now + seconds}
            for item in old["tokens"]
        ],
    }
    _write_store(store_path, migrated)
    return len(migrated["tokens"])


def revoke_token(store_path: Path, token_id: str) -> bool:
    if not isinstance(token_id, str) or not ID32.fullmatch(token_id):
        raise CredentialsError("Invalid token ID")
    store = load_store(store_path)
    before = len(store["tokens"])
    store["tokens"] = [entry for entry in store["tokens"] if entry["id"] != token_id]
    if len(store["tokens"]) == before:
        return False
    _write_store(store_path, store)
    return True


def authenticate_token(store_path: Path, bearer: str, profile_id: str) -> str | None:
    """Return only a matched valid token ID; never the digest or original bearer."""
    # Validate the credential store even if the supplied token is malformed.
    store = load_store(store_path)
    if not (isinstance(bearer, str) and bearer.startswith("vf_")
            and 30 <= len(bearer) <= 120 and bearer.isascii()):
        return None
    digest = hashlib.sha256(bearer.encode("ascii")).hexdigest()
    now = int(time.time())
    result = None
    for entry in store["tokens"]:
        equal_digest = secrets.compare_digest(entry["sha256"], digest)
        if equal_digest and entry["profile_id"] == profile_id and entry["issued_at"] <= now < entry["expires_at"]:
            result = entry["id"]
    return result


def authorized(store_path: Path, bearer: str, profile_id: str) -> bool:
    return authenticate_token(store_path, bearer, profile_id) is not None


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


def _timestamp(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage expiring scoped upload tokens (bearers never printed)")
    actions = parser.add_subparsers(dest="action", required=True)
    issue = actions.add_parser("issue", help="write an expiring token to a NEW 0600 file")
    issue.add_argument("--store", type=Path, required=True)
    issue.add_argument("--profile", required=True)
    issue.add_argument("--token-output", type=Path, required=True)
    issue.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    migrate = actions.add_parser("migrate", help="explicitly convert v1 tokens into expiring v2 tokens")
    migrate.add_argument("--store", type=Path, required=True)
    migrate.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    revoke = actions.add_parser("revoke", help="remove token ID (not the secret)")
    revoke.add_argument("--store", type=Path, required=True)
    revoke.add_argument("--id", required=True)
    listing = actions.add_parser("list", help="list token IDs, scopes and expiry (never bearer)")
    listing.add_argument("--store", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "issue":
            ident = issue_token(args.store, args.profile, args.token_output, args.ttl_hours)
            record = next(x for x in load_store(args.store)["tokens"] if x["id"] == ident)
            print(f"Created scoped token ID {ident}; expires {_timestamp(record['expires_at'])}; "
                  f"bearer written to {args.token_output}")
        elif args.action == "migrate":
            count = migrate_store(args.store, args.ttl_hours)
            print(f"Migrated {count} legacy token records to expiring v2")
        elif args.action == "revoke":
            if not revoke_token(args.store, args.id):
                raise CredentialsError("No matching token ID")
            print("Revoked token ID " + args.id)
        else:
            for entry in load_store(args.store)["tokens"]:
                print(entry["id"] + "  profile=" + entry["profile_id"] +
                      "  expires=" + _timestamp(entry["expires_at"]))
    except CredentialsError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
