"""Local structured audit journal for the upload-only service.

No HTTP body, bearer, digest, source IP, headers or remote hostnames are saved.
The journal is not served through an HTTP endpoint: inspect with local CLI.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
from uuid import uuid4

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.vulnerability_storage import utcnow

ALLOWED_EVENTS = frozenset({
    "imported", "duplicate", "auth_denied", "transport_denied",
    "rate_limited", "invalid_payload", "credentials_unavailable",
    "import_failed", "server_error",
})


def init_audit(repo: AssetRepository) -> None:
    with repo._db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ingest_audit (
                id TEXT PRIMARY KEY,
                recorded_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                profile_id TEXT,
                token_id TEXT,
                assets_seen INTEGER
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ingest_audit_at ON ingest_audit(recorded_at DESC)"
        )


def event_for_status(status: int, duplicate: bool = False) -> str:
    if status in (200, 201):
        return "duplicate" if duplicate else "imported"
    if status == 401:
        return "auth_denied"
    if status == 403:
        return "transport_denied"
    if status == 429:
        return "rate_limited"
    if status == 503:
        return "credentials_unavailable"
    if status in (400, 404, 405, 413, 415, 422):
        return "invalid_payload"
    if status >= 500:
        return "server_error"
    return "import_failed"


def record_audit(repo: AssetRepository, *, status: int, profile_id: str | None,
                 token_id: str | None, duplicate: bool = False,
                 assets_seen: int | None = None) -> None:
    outcome = event_for_status(status, duplicate)
    assert outcome in ALLOWED_EVENTS
    with repo._db() as conn:
        conn.execute("""
            INSERT INTO ingest_audit(id,recorded_at,outcome,http_status,profile_id,token_id,assets_seen)
            VALUES(?,?,?,?,?,?,?)
        """, (uuid4().hex, utcnow(), outcome, status,
              profile_id, token_id, assets_seen if status in (200, 201) else None))


def recent_audit(repo: AssetRepository, limit: int = 50) -> list[dict]:
    if not 1 <= limit <= 500:
        raise ValueError("Audit limit must be 1..500")
    with repo._db() as conn:
        return [dict(row) for row in conn.execute("""
            SELECT id,recorded_at,outcome,http_status,profile_id,token_id,assets_seen
            FROM ingest_audit ORDER BY recorded_at DESC, rowid DESC LIMIT ?
        """, (limit,)).fetchall()]


def prune_audit(repo: AssetRepository, days: int) -> int:
    """Explicit maintenance, not silent automatic event deletion."""
    if type(days) is not int or days < 1:
        raise ValueError("Retention days must be a positive integer")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with repo._db() as conn:
        result = conn.execute("DELETE FROM ingest_audit WHERE recorded_at < ?", (cutoff,))
        return result.rowcount


def main() -> int:
    parser = argparse.ArgumentParser(description="Read local ingest audit events (no API exposed)")
    parser.add_argument("--db", type=Path, required=True, help="existing vulnfolio SQLite file")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--prune-older-than-days", type=int)
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error("Audit database does not exist")
    repo = AssetRepository(args.db)
    init_audit(repo)
    try:
        if args.prune_older_than_days is not None:
            count = prune_audit(repo, args.prune_older_than_days)
            print(f"Pruned {count} audit events")
        else:
            for row in recent_audit(repo, args.limit):
                print(json.dumps(row, ensure_ascii=False))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
