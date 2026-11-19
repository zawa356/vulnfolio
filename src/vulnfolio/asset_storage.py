"""M1 private asset inventory and assessment persistence.

All operations are local-only PoC operations, NOT production authorization.
The inventory database is separated logically from public vulnerability APIs.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any
from uuid import uuid4

from vulnfolio.vulnerability_storage import VulnerabilityRepository, utcnow
from vulnfolio.vulnerabilities import validate_cve_id

CLOSED_STATUSES = frozenset({"mitigated", "not_affected", "accepted_risk"})
ALLOWED_STATUSES = frozenset({
    "new", "investigating", "affected", "in_progress", "mitigated", "not_affected", "accepted_risk"
})


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def _required(value: str, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} must not be empty")
    return cleaned


class AssetRepository(VulnerabilityRepository):
    """Extends the same local SQLite file; global CVE tables stay independent."""

    def _connect(self) -> sqlite3.Connection:
        conn = super()._connect()
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _initialize(self) -> None:
        super()._initialize()
        with self._db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                    name TEXT NOT NULL COLLATE NOCASE,
                    os_family TEXT NOT NULL DEFAULT '',
                    os_version TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    UNIQUE(profile_id, name)
                );
                CREATE TABLE IF NOT EXISTS asset_products (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    vendor TEXT NOT NULL COLLATE NOCASE DEFAULT '',
                    name TEXT NOT NULL COLLATE NOCASE,
                    version TEXT NOT NULL COLLATE NOCASE DEFAULT '',
                    created_at TEXT NOT NULL,
                    UNIQUE(asset_id, vendor, name, version)
                );
                CREATE TABLE IF NOT EXISTS assessments (
                    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    cve_id TEXT NOT NULL REFERENCES vulnerabilities(id),
                    status TEXT NOT NULL CHECK(status IN (
                      'new','investigating','affected','in_progress','mitigated','not_affected','accepted_risk'
                    )),
                    note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(asset_id, cve_id)
                );
                CREATE TABLE IF NOT EXISTS assessment_history (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    cve_id TEXT NOT NULL REFERENCES vulnerabilities(id),
                    status TEXT NOT NULL,
                    note TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assets_profile ON assets(profile_id);
                CREATE INDEX IF NOT EXISTS idx_products_asset ON asset_products(asset_id);
                CREATE INDEX IF NOT EXISTS idx_assessment_history_asset ON assessment_history(asset_id,cve_id);
                CREATE TABLE IF NOT EXISTS inventory_imports (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                    content_sha256 TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    observed_at TEXT,
                    imported_at TEXT NOT NULL,
                    asset_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    UNIQUE(profile_id, content_sha256)
                );
                CREATE TABLE IF NOT EXISTS asset_inventory_snapshots (
                    asset_id TEXT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
                    import_id TEXT NOT NULL REFERENCES inventory_imports(id),
                    collector TEXT NOT NULL,
                    observed_at TEXT,
                    patches_json TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS imported_products (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                    import_id TEXT NOT NULL REFERENCES inventory_imports(id),
                    vendor TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL,
                    version TEXT NOT NULL DEFAULT '',
                    epoch TEXT NOT NULL DEFAULT '',
                    release TEXT NOT NULL DEFAULT '',
                    arch TEXT NOT NULL DEFAULT '',
                    manager TEXT NOT NULL DEFAULT '',
                    UNIQUE(asset_id,name,version,epoch,release,arch,manager)
                );
                CREATE INDEX IF NOT EXISTS idx_import_products_asset ON imported_products(asset_id);
            """)

    def _profile_exists(self, conn: sqlite3.Connection, profile_id: str) -> None:
        if conn.execute("SELECT 1 FROM profiles WHERE id=?", (profile_id,)).fetchone() is None:
            raise NotFound("Profile not found")

    def _asset_profile(self, conn: sqlite3.Connection, asset_id: str) -> str:
        row = conn.execute("SELECT profile_id FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            raise NotFound("Asset not found")
        return row["profile_id"]

    def create_profile(self, name: str, description: str = "") -> dict[str, Any]:
        profile_id = uuid4().hex
        name = _required(name, "name")
        with self._db() as conn:
            try:
                conn.execute(
                    "INSERT INTO profiles(id,name,description,created_at) VALUES(?,?,?,?)",
                    (profile_id, name, description.strip(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("Profile name already exists") from exc
        return self.get_profile(profile_id)

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        if row is None:
            raise NotFound("Profile not found")
        return dict(row)

    def list_profiles(self) -> list[dict[str, Any]]:
        with self._db() as conn:
            return [dict(row) for row in conn.execute(
                """SELECT p.*,
                          (SELECT COUNT(*) FROM assets a WHERE a.profile_id=p.id) AS asset_count
                   FROM profiles p ORDER BY p.name COLLATE NOCASE"""
            ).fetchall()]

    def add_asset(self, profile_id: str, name: str, os_family: str = "", os_version: str = "") -> dict[str, Any]:
        asset_id = uuid4().hex
        name = _required(name, "name")
        with self._db() as conn:
            self._profile_exists(conn, profile_id)
            try:
                conn.execute("""
                    INSERT INTO assets(id,profile_id,name,os_family,os_version,created_at)
                    VALUES(?,?,?,?,?,?)
                """, (asset_id, profile_id, name, os_family.strip(), os_version.strip(), utcnow()))
            except sqlite3.IntegrityError as exc:
                raise Conflict("Asset name already exists in this profile") from exc
        return self.get_asset(asset_id)

    def get_asset(self, asset_id: str) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            raise NotFound("Asset not found")
        return dict(row)

    def list_assets(self, profile_id: str) -> list[dict[str, Any]]:
        with self._db() as conn:
            self._profile_exists(conn, profile_id)
            rows = conn.execute(
                "SELECT * FROM assets WHERE profile_id=? ORDER BY name COLLATE NOCASE", (profile_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def add_product(self, asset_id: str, name: str, vendor: str = "", version: str = "") -> dict[str, Any]:
        product_id = uuid4().hex
        name = _required(name, "product name")
        with self._db() as conn:
            self._asset_profile(conn, asset_id)
            try:
                conn.execute("""
                    INSERT INTO asset_products(id,asset_id,vendor,name,version,created_at)
                    VALUES(?,?,?,?,?,?)
                """, (product_id, asset_id, vendor.strip(), name, version.strip(), utcnow()))
            except sqlite3.IntegrityError as exc:
                raise Conflict("Software entry already exists on this asset") from exc
        return self.get_product(product_id)

    def get_product(self, product_id: str) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM asset_products WHERE id=?", (product_id,)).fetchone()
        if row is None:
            raise NotFound("Software entry not found")
        return dict(row)

    def list_products(self, asset_id: str) -> list[dict[str, Any]]:
        with self._db() as conn:
            self._asset_profile(conn, asset_id)
            return [dict(row) for row in conn.execute("""
                SELECT * FROM (
                SELECT id,asset_id,vendor,name,version,created_at,'manual' AS origin,
                       '' AS epoch,'' AS release,'' AS arch,'' AS manager
                FROM asset_products WHERE asset_id=?
                UNION ALL
                SELECT id,asset_id,vendor,name,version,'' AS created_at,'imported' AS origin,
                       epoch,release,arch,manager
                FROM imported_products WHERE asset_id=?
                ) ORDER BY name COLLATE NOCASE,version
            """, (asset_id, asset_id)).fetchall()]

    def delete_product(self, product_id: str) -> None:
        with self._db() as conn:
            if conn.execute("DELETE FROM asset_products WHERE id=?", (product_id,)).rowcount == 0:
                raise NotFound("Software entry not found")

    def record_assessment(self, asset_id: str, cve_id: str, status: str, note: str = "") -> dict[str, Any]:
        cve_id = validate_cve_id(cve_id)
        if status not in ALLOWED_STATUSES:
            raise ValueError("Unsupported assessment status")
        with self._db() as conn:
            self._asset_profile(conn, asset_id)
            if not conn.execute("SELECT 1 FROM vulnerabilities WHERE id=?", (cve_id,)).fetchone():
                raise NotFound("CVE not present in local database")
            now = utcnow()
            current = conn.execute(
                "SELECT status,note,updated_at FROM assessments WHERE asset_id=? AND cve_id=?",
                (asset_id, cve_id),
            ).fetchone()
            if current and current["status"] == status and current["note"] == note:
                return dict(current) | {"asset_id": asset_id, "cve_id": cve_id}
            conn.execute("""
                INSERT INTO assessments(asset_id,cve_id,status,note,updated_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(asset_id,cve_id) DO UPDATE SET
                  status=excluded.status,note=excluded.note,updated_at=excluded.updated_at
            """, (asset_id, cve_id, status, note, now))
            conn.execute("""
                INSERT INTO assessment_history(id,asset_id,cve_id,status,note,recorded_at)
                VALUES(?,?,?,?,?,?)
            """, (uuid4().hex, asset_id, cve_id, status, note, now))
            return {"asset_id": asset_id, "cve_id": cve_id, "status": status, "note": note, "updated_at": now}

    def list_assessment_history(self, asset_id: str, cve_id: str) -> list[dict[str, Any]]:
        cve_id = validate_cve_id(cve_id)
        with self._db() as conn:
            self._asset_profile(conn, asset_id)
            return [dict(row) for row in conn.execute("""
                SELECT id,asset_id,cve_id,status,note,recorded_at FROM assessment_history
                WHERE asset_id=? AND cve_id=? ORDER BY rowid DESC
            """, (asset_id, cve_id)).fetchall()]

    def candidates(self, profile_id: str, include_closed: bool = False) -> dict[str, Any]:
        # Product-only, low-confidence matches; bounded to prevent a misleading
        # heavy query as the public CVE collection eventually grows.
        from vulnfolio.asset_matching import candidates_for_inventory

        max_cves = 2000
        with self._db() as conn:
            self._profile_exists(conn, profile_id)
            products = [dict(row) for row in conn.execute("""
                SELECT * FROM (
                SELECT s.id,s.asset_id,s.vendor,s.name,s.version,
                       a.name AS asset_name,a.profile_id
                FROM asset_products s JOIN assets a ON s.asset_id=a.id
                WHERE a.profile_id=?
                UNION ALL
                SELECT s.id,s.asset_id,s.vendor,s.name,s.version,
                       a.name AS asset_name,a.profile_id
                FROM imported_products s JOIN assets a ON s.asset_id=a.id
                WHERE a.profile_id=?
                ) ORDER BY asset_name,name
            """, (profile_id, profile_id)).fetchall()]
            cvss = conn.execute(
                "SELECT id,title,raw_json FROM vulnerabilities ORDER BY id LIMIT ?", (max_cves + 1,)
            ).fetchall()
            assessments = {
                (row["asset_id"], row["cve_id"]): dict(row)
                for row in conn.execute("""
                    SELECT s.* FROM assessments s JOIN assets a ON a.id=s.asset_id
                    WHERE a.profile_id=?
                """, (profile_id,)).fetchall()
            }
        complete = len(cvss) <= max_cves
        results = candidates_for_inventory(products, cvss[:max_cves])
        for item in results:
            assessment = assessments.get((item["asset_id"], item["cve_id"]))
            item["assessment"] = assessment or {
                "status": "new", "note": "", "updated_at": None
            }
        if not include_closed:
            results = [r for r in results if r["assessment"]["status"] not in CLOSED_STATUSES]
        results.sort(key=lambda x: (x["asset_name"].casefold(), x["cve_id"]))
        return {
            "metadata": {
                "count": len(results), "checked_local_cves": min(len(cvss), max_cves),
                "complete": complete, "scope": "local_cve_records_only",
            },
            "data": results,
        }
