"""Canonical inventory import with source isolation and explicit evidence quality.

v0.1.0 remains compatible: its nonempty 'reported' observations replace only
that collector's previous records; empty means 'unknown' and NEVER deletes.
v0.2.0 supplies coverage for explicit complete/partial/unknown semantics.
This module never claims a vulnerability is patched or unaffected.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

from vulnfolio.asset_storage import AssetRepository, Conflict
from vulnfolio.vulnerability_storage import utcnow


class ImportValidationError(ValueError):
    pass


def _obj(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ImportValidationError(f"{label} must be an object")
    return value


def _text(value: Any, label: str, maximum: int = 180, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ImportValidationError(f"{label} must be a string (max {maximum} characters)")
    return value.strip()


def _items(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ImportValidationError(f"{label} must be an array (max {maximum} entries)")
    return value


def _parse_utc(value: str) -> datetime | None:
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if when.utcoffset() is None:
            return None
        return when.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def _scope(value: Any, field: str, present: bool) -> str:
    if not isinstance(value, str) or value not in {"complete", "partial", "unknown"}:
        raise ImportValidationError(f"coverage.{field} must be complete, partial or unknown")
    if value == "unknown" and present:
        raise ImportValidationError(f"coverage.{field}=unknown cannot report entries")
    return value


def validate_envelope(payload: Any, profile_id: str) -> dict[str, Any]:
    root = _obj(payload, "envelope")
    version = root.get("schema_version")
    if version not in {"0.1.0", "0.2.0"}:
        raise ImportValidationError("Only CollectionEnvelope 0.1.0 / 0.2.0 are supported")
    if root.get("profile_id") != profile_id:
        raise ImportValidationError("Envelope profile_id must match URL profile_id")
    if root.get("status") not in {"success", "partial_success", "failed", "empty"}:
        raise ImportValidationError("Invalid envelope status")
    collector = _obj(root.get("collector"), "collector")
    driver = _text(collector.get("driver"), "collector.driver", 80, True)
    if driver == "legacy-unverified":
        raise ImportValidationError("Reserved collector name")
    observations = _items(root.get("observations"), "observations", 200)
    errors = _items(root.get("errors"), "errors", 200)
    findings = _items(root.get("findings"), "findings", 200)
    if findings:
        raise ImportValidationError("VulnerabilityFinding import not implemented; nothing imported")
    observed_at = _text(root.get("observed_at"), "observed_at", 64)
    if version == "0.2.0" and (not observed_at or _parse_utc(observed_at) is None):
        raise ImportValidationError("0.2.0 observed_at must be an ISO8601 timezone-aware date")
    parsed_observations = []
    seen_assets: set[str] = set()
    seen_keys: set[str] = set()
    total_packages = 0
    for index, raw in enumerate(observations):
        item = _obj(raw, f"observations[{index}]")
        name = _text(item.get("asset_id"), f"observations[{index}].asset_id", 180, True)
        if name.casefold() in seen_assets:
            raise ImportValidationError("Duplicate asset_id in one envelope")
        seen_assets.add(name.casefold())
        stable_key = ""
        if version == "0.2.0":
            stable_key = _text(item.get("asset_key"), "asset_key", 180)
            if stable_key and stable_key in seen_keys:
                raise ImportValidationError("Duplicate asset_key in one envelope")
            if stable_key:
                seen_keys.add(stable_key)
        os = _obj(item.get("os"), f"observations[{index}].os")
        family = _text(os.get("family"), "os.family", 80)
        distribution = _text(os.get("distribution"), "os.distribution", 120)
        os_version = _text(os.get("version"), "os.version", 120)
        build = _text(os.get("build"), "os.build", 120)
        raw_packages = _items(item.get("packages"), f"observations[{index}].packages", 2000)
        total_packages += len(raw_packages)
        if total_packages > 5000:
            raise ImportValidationError("Maximum 5,000 packages per envelope")
        packages = []
        for package in raw_packages:
            pkg = _obj(package, "package")
            packages.append({
                "name": _text(pkg.get("name"), "package.name", 180, True),
                "version": _text(pkg.get("version"), "package.version", 120),
                "epoch": _text(pkg.get("epoch"), "package.epoch", 60),
                "release": _text(pkg.get("release"), "package.release", 120),
                "arch": _text(pkg.get("arch"), "package.arch", 80),
                "manager": _text(pkg.get("manager"), "package.manager", 80),
            })
        raw_patches = _items(item.get("patches"), "patches", 2000)
        patches = [_text(x, "patch ID", 80, True) for x in raw_patches]
        if version == "0.2.0":
            coverage = _obj(item.get("coverage"), "coverage")
            ps = _scope(coverage.get("packages"), "packages", bool(packages))
            ks = _scope(coverage.get("patches"), "patches", bool(patches))
        else:
            # v0.1 'reported' provides no *proof* of exhaustive inventory.
            ps = "reported" if packages else "unknown"
            ks = "reported" if patches else "unknown"
        parsed_observations.append({
            "name": name, "asset_key": stable_key,
            "os_family": family,
            "os_version": " ".join(x for x in (distribution, os_version) if x).strip()[:120],
            "os_build": build, "packages": packages, "patches": patches,
            "packages_state": ps, "patches_state": ks,
        })
    return {
        "profile_id": profile_id, "schema_version": version,
        "collector": driver, "observed_at": observed_at or None,
        "observations": parsed_observations, "error_count": len(errors),
    }


def _match_asset(conn: sqlite3.Connection, profile_id: str, item: dict, timestamp: str) -> str:
    """Resolve an explicitly supplied stable key; never fuzzy-merge hostnames."""
    key = item["asset_key"]
    existing_key = None
    if key:
        existing_key = conn.execute("""
            SELECT asset_id FROM asset_stable_keys WHERE profile_id=? AND stable_key=?
        """, (profile_id, key)).fetchone()
    named = conn.execute(
        "SELECT id FROM assets WHERE profile_id=? AND name=? COLLATE NOCASE",
        (profile_id, item["name"]),
    ).fetchone()
    if existing_key:
        asset_id = existing_key["asset_id"]
        if named is not None and named["id"] != asset_id:
            raise ImportValidationError("asset_key rename collides with another asset name")
        conn.execute("""
            UPDATE assets SET name=?,os_family=CASE WHEN ?<>'' THEN ? ELSE os_family END,
                os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END WHERE id=?
        """, (item["name"], item["os_family"], item["os_family"],
              item["os_version"], item["os_version"], asset_id))
        return asset_id
    if named:
        asset_id = named["id"]
        # Distinct explicit stable keys must never silently merge solely
        # because DNS/NetBIOS/inventory names happen to be the same.
        if key and conn.execute("""
            SELECT 1 FROM asset_stable_keys
            WHERE asset_id=? AND stable_key<>? LIMIT 1
        """, (asset_id, key)).fetchone():
            raise ImportValidationError(
                "asset name is already bound to a different stable key; explicit reconciliation required"
            )
        conn.execute("""
            UPDATE assets SET os_family=CASE WHEN ?<>'' THEN ? ELSE os_family END,
                os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END WHERE id=?
        """, (item["os_family"], item["os_family"],
              item["os_version"], item["os_version"], asset_id))
    else:
        asset_id = uuid4().hex
        conn.execute("""
            INSERT INTO assets(id,profile_id,name,os_family,os_version,created_at)
            VALUES(?,?,?,?,?,?)
        """, (asset_id, profile_id, item["name"], item["os_family"],
              item["os_version"], timestamp))
    if key:
        conn.execute("""
            INSERT INTO asset_stable_keys(profile_id,stable_key,asset_id) VALUES(?,?,?)
        """, (profile_id, key, asset_id))
    return asset_id


def _replace_products(conn: sqlite3.Connection, asset_id: str, driver: str,
                      packages: list[dict], import_id: str, state: str) -> None:
    if state in {"complete", "reported"}:
        conn.execute("DELETE FROM source_products WHERE asset_id=? AND collector=?",
                     (asset_id, driver))
    if state == "unknown":
        return
    for pkg in packages:
        conn.execute("""
            INSERT OR IGNORE INTO source_products
              (id,asset_id,collector,import_id,vendor,name,version,epoch,release,arch,manager)
            VALUES(?,?,?,?,'',?,?,?,?,?,?)
        """, (uuid4().hex, asset_id, driver, import_id,
              pkg["name"], pkg["version"], pkg["epoch"], pkg["release"],
              pkg["arch"], pkg["manager"]))


class InventoryImporter:
    def __init__(self, repo: AssetRepository):
        self.repo = repo

    def import_envelope(self, profile_id: str, payload: Any) -> dict[str, Any]:
        parsed = validate_envelope(payload, profile_id)
        digest = sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")).hexdigest()
        imported_at = utcnow()
        with self.repo._db() as conn:
            self.repo._profile_exists(conn, profile_id)
            prior = conn.execute("""
                SELECT id,asset_count,error_count FROM inventory_imports
                WHERE profile_id=? AND content_sha256=?
            """, (profile_id, digest)).fetchone()
            if prior:
                return {
                    "import_id": prior["id"], "duplicate": True,
                    "assets_seen": prior["asset_count"], "error_count": prior["error_count"],
                    "collector": parsed["collector"], "stale_skipped": 0,
                }
            batch_id = uuid4().hex
            conn.execute("""
                INSERT INTO inventory_imports
                    (id,profile_id,content_sha256,collector,observed_at,imported_at,asset_count,error_count)
                VALUES(?,?,?,?,?,?,?,?)
            """, (batch_id, profile_id, digest, parsed["collector"], parsed["observed_at"],
                  imported_at, len(parsed["observations"]), parsed["error_count"]))
            skipped = 0
            for item in parsed["observations"]:
                # Evaluate staleness before mutating asset metadata or stable alias.
                stable = None
                if item["asset_key"]:
                    stable = conn.execute("""
                        SELECT asset_id FROM asset_stable_keys WHERE profile_id=? AND stable_key=?
                    """, (profile_id, item["asset_key"])).fetchone()
                named = conn.execute("""
                    SELECT id FROM assets WHERE profile_id=? AND name=? COLLATE NOCASE
                """, (profile_id, item["name"])).fetchone()
                current_id = stable["asset_id"] if stable else (named["id"] if named else None)
                old = conn.execute("""
                    SELECT * FROM source_observations WHERE asset_id=? AND collector=?
                """, (current_id, parsed["collector"])).fetchone() if current_id else None
                new_time = _parse_utc(parsed["observed_at"]) if parsed["observed_at"] else None
                old_time = _parse_utc(old["observed_at"]) if old and old["observed_at"] else None
                if old_time is not None and new_time is not None and new_time < old_time:
                    skipped += 1
                    continue
                asset_id = _match_asset(conn, profile_id, item, imported_at)
                # 'unknown' does not mean confirmed absence. Keep previous
                # products/patches and per-field last-success timestamps.
                prior_patches = json.loads(old["patches_json"]) if old else []
                package_state = item["packages_state"]
                patch_state = item["patches_state"]
                _replace_products(conn, asset_id, parsed["collector"],
                                  item["packages"], batch_id, package_state)
                if patch_state == "complete":
                    patches = item["patches"]
                elif patch_state == "reported":
                    patches = item["patches"]
                elif patch_state == "partial":
                    patches = sorted(set(prior_patches) | set(item["patches"]))
                else:
                    patches = prior_patches
                package_time = (
                    parsed["observed_at"] or imported_at
                    if package_state != "unknown"
                    else (old["packages_observed_at"] if old else None)
                )
                patch_time = (
                    parsed["observed_at"] or imported_at
                    if patch_state != "unknown"
                    else (old["patches_observed_at"] if old else None)
                )
                conn.execute("""
                    INSERT INTO source_observations
                      (asset_id,collector,import_id,observed_at,imported_at,os_family,os_version,
                       os_build,packages_state,patches_state,packages_observed_at,
                       patches_observed_at,patches_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(asset_id,collector) DO UPDATE SET
                      import_id=excluded.import_id,observed_at=excluded.observed_at,
                      imported_at=excluded.imported_at,os_family=excluded.os_family,
                      os_version=excluded.os_version,os_build=excluded.os_build,
                      packages_state=excluded.packages_state,
                      patches_state=excluded.patches_state,
                      packages_observed_at=excluded.packages_observed_at,
                      patches_observed_at=excluded.patches_observed_at,
                      patches_json=excluded.patches_json
                """, (asset_id, parsed["collector"], batch_id, parsed["observed_at"],
                      imported_at, item["os_family"], item["os_version"], item["os_build"],
                      package_state, patch_state, package_time, patch_time,
                      json.dumps(patches)))
            return {
                "import_id": batch_id, "duplicate": False,
                "assets_seen": len(parsed["observations"]),
                "error_count": parsed["error_count"], "collector": parsed["collector"],
                "stale_skipped": skipped,
            }

    def list_imports(self, profile_id: str) -> list[dict[str, Any]]:
        with self.repo._db() as conn:
            self.repo._profile_exists(conn, profile_id)
            return [dict(r) for r in conn.execute("""
                SELECT id,profile_id,collector,observed_at,imported_at,asset_count,error_count
                FROM inventory_imports WHERE profile_id=? ORDER BY imported_at DESC,id DESC LIMIT 100
            """, (profile_id,)).fetchall()]

    def source_snapshots(self, asset_id: str) -> list[dict[str, Any]]:
        with self.repo._db() as conn:
            self.repo._asset_profile(conn, asset_id)
            rows = conn.execute("""
                SELECT collector,observed_at,imported_at,os_family,os_version,os_build,
                       packages_state,patches_state,packages_observed_at,patches_observed_at,
                       patches_json
                FROM source_observations WHERE asset_id=?
                ORDER BY COALESCE(observed_at,imported_at) DESC,collector
            """, (asset_id,)).fetchall()
        result = []
        for row in rows:
            data = dict(row)
            data["patches"] = json.loads(data.pop("patches_json"))
            result.append(data)
        return result

    def asset_snapshot(self, asset_id: str) -> dict[str, Any] | None:
        snapshots = self.source_snapshots(asset_id)
        return snapshots[0] if snapshots else None
