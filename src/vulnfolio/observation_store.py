"""M1d observation schema and one-time legacy M1b migration.

Keep the old imported_products/asset_inventory_snapshots tables intact as
read-only upgrade evidence; current write paths use source-specific tables.
Migration is idempotent and runs transactionally inside AssetRepository init.
"""
from __future__ import annotations

import sqlite3


def initialize_observations(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS source_observations (
            asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            collector TEXT NOT NULL,
            import_id TEXT NOT NULL REFERENCES inventory_imports(id),
            observed_at TEXT,
            imported_at TEXT NOT NULL,
            os_family TEXT NOT NULL DEFAULT '',
            os_version TEXT NOT NULL DEFAULT '',
            os_build TEXT NOT NULL DEFAULT '',
            packages_state TEXT NOT NULL DEFAULT 'unknown',
            patches_state TEXT NOT NULL DEFAULT 'unknown',
            packages_observed_at TEXT,
            patches_observed_at TEXT,
            patches_json TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY (asset_id, collector)
        );
        CREATE TABLE IF NOT EXISTS source_products (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            collector TEXT NOT NULL,
            import_id TEXT NOT NULL REFERENCES inventory_imports(id),
            vendor TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            epoch TEXT NOT NULL DEFAULT '',
            release TEXT NOT NULL DEFAULT '',
            arch TEXT NOT NULL DEFAULT '',
            manager TEXT NOT NULL DEFAULT '',
            UNIQUE(asset_id,collector,name,version,epoch,release,arch,manager)
        );
        CREATE INDEX IF NOT EXISTS idx_source_products_asset ON source_products(asset_id,collector);
        CREATE TABLE IF NOT EXISTS asset_stable_keys (
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            stable_key TEXT NOT NULL,
            asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            PRIMARY KEY (profile_id,stable_key)
        );
        CREATE INDEX IF NOT EXISTS idx_asset_stable_asset ON asset_stable_keys(asset_id);
        CREATE TABLE IF NOT EXISTS inventory_schema_migrations (
            migration TEXT PRIMARY KEY
        );
    """)
    already = conn.execute(
        "SELECT 1 FROM inventory_schema_migrations WHERE migration='m1d_source_observations'"
    ).fetchone()
    if already:
        return
    # v0.1 had one snapshot per host. Its reported collector may have
    # overwritten a previous source, so original provenance cannot be
    # reconstructed. Explicitly label migrated records as legacy-unverified.
    conn.execute("""
        INSERT OR IGNORE INTO source_observations
          (asset_id,collector,import_id,observed_at,imported_at,
           packages_state,patches_state,packages_observed_at,patches_observed_at,
           patches_json)
        SELECT asset_id,'legacy-unverified',import_id,observed_at,imported_at,
               'legacy_reported',
               CASE WHEN patches_json <> '[]' THEN 'legacy_reported' ELSE 'unknown' END,
               observed_at,observed_at,patches_json
        FROM asset_inventory_snapshots
    """)
    # At import-time the v0.1 products table could contain mixed-source
    # observations. Preserve them with an honest 'legacy-unverified' label.
    conn.execute("""
        INSERT OR IGNORE INTO source_products
          (id,asset_id,collector,import_id,vendor,name,version,epoch,release,arch,manager)
        SELECT id,asset_id,'legacy-unverified',import_id,vendor,name,version,
               epoch,release,arch,manager
        FROM imported_products
    """)
    conn.execute(
        "INSERT INTO inventory_schema_migrations(migration) VALUES('m1d_source_observations')"
    )
