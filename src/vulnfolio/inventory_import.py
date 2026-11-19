"""Import v0.1 CollectionEnvelope observations into the private inventory.

The adapter/normalizer is intentionally outside this module. This only consumes
its canonical output, keeping Ansible/Vuls/OpenVAS source formats out of Core.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any, Mapping
from uuid import uuid4

from vulnfolio.asset_storage import AssetRepository
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


def validate_envelope(payload: Any, profile_id: str) -> dict[str, Any]:
    root = _obj(payload, "envelope")
    if root.get("schema_version") != "0.1.0":
        raise ImportValidationError("Only CollectionEnvelope schema_version 0.1.0 is supported")
    if root.get("profile_id") != profile_id:
        raise ImportValidationError("Envelope profile_id must match URL profile_id")
    if root.get("status") not in {"success", "partial_success", "failed", "empty"}:
        raise ImportValidationError("Invalid envelope status")
    collector = _obj(root.get("collector"), "collector")
    driver = _text(collector.get("driver"), "collector.driver", 80, True)
    observations = _items(root.get("observations"), "observations", 200)
    errors = _items(root.get("errors"), "errors", 200)
    findings = _items(root.get("findings"), "findings", 200)
    if findings:
        raise ImportValidationError("VulnerabilityFinding import is not implemented; nothing was imported")
    observed_at = _text(root.get("observed_at"), "observed_at", 64)
    parsed_observations = []
    seen_assets: set[str] = set()
    total_packages = 0
    for index, raw in enumerate(observations):
        item = _obj(raw, f"observations[{index}]")
        name = _text(item.get("asset_id"), f"observations[{index}].asset_id", 180, True)
        if name.casefold() in seen_assets:
            raise ImportValidationError("Duplicate asset_id in one envelope")
        seen_assets.add(name.casefold())
        os = _obj(item.get("os"), f"observations[{index}].os")
        family = _text(os.get("family"), "os.family", 80)
        distribution = _text(os.get("distribution"), "os.distribution", 120)
        version = _text(os.get("version"), "os.version", 120)
        _text(os.get("build"), "os.build", 120)
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
        parsed_observations.append({
            "name": name, "os_family": family,
            "os_version": " ".join(x for x in (distribution, version) if x).strip()[:120],
            "packages": packages, "patches": patches,
        })
    return {
        "profile_id": profile_id,
        "collector": driver,
        "observed_at": observed_at or None,
        "observations": parsed_observations,
        "error_count": len(errors),
    }


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
            prior = conn.execute(
                "SELECT id,asset_count,error_count FROM inventory_imports WHERE profile_id=? AND content_sha256=?",
                (profile_id, digest),
            ).fetchone()
            if prior:
                return {
                    "import_id": prior["id"], "duplicate": True,
                    "assets_seen": prior["asset_count"], "error_count": prior["error_count"],
                    "collector": parsed["collector"],
                }
            batch_id = uuid4().hex
            conn.execute("""
                INSERT INTO inventory_imports
                    (id,profile_id,content_sha256,collector,observed_at,imported_at,asset_count,error_count)
                VALUES(?,?,?,?,?,?,?,?)
            """, (batch_id, profile_id, digest, parsed["collector"], parsed["observed_at"],
                  imported_at, len(parsed["observations"]), parsed["error_count"]))
            for item in parsed["observations"]:
                current = conn.execute(
                    "SELECT id FROM assets WHERE profile_id=? AND name=? COLLATE NOCASE",
                    (profile_id, item["name"]),
                ).fetchone()
                if current:
                    asset_id = current["id"]
                    conn.execute("""
                        UPDATE assets SET
                          os_family=CASE WHEN ?<>'' THEN ? ELSE os_family END,
                          os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END
                        WHERE id=?
                    """, (item["os_family"], item["os_family"],
                          item["os_version"], item["os_version"], asset_id))
                else:
                    asset_id = uuid4().hex
                    conn.execute("""
                        INSERT INTO assets(id,profile_id,name,os_family,os_version,created_at)
                        VALUES(?,?,?,?,?,?)
                    """, (asset_id, profile_id, item["name"], item["os_family"],
                          item["os_version"], imported_at))
                conn.execute("""
                    INSERT INTO asset_inventory_snapshots
                      (asset_id,import_id,collector,observed_at,patches_json,imported_at)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                      import_id=excluded.import_id,collector=excluded.collector,
                      observed_at=excluded.observed_at,
                      patches_json=CASE WHEN excluded.patches_json<>'[]'
                                        THEN excluded.patches_json
                                        ELSE asset_inventory_snapshots.patches_json END,
                      imported_at=excluded.imported_at
                """, (asset_id, batch_id, parsed["collector"], parsed["observed_at"],
                      json.dumps(item["patches"]), imported_at))
                # Empty/missing package inventories do NOT mean the previous
                # software was uninstalled. Keep the last nonempty snapshot.
                if item["packages"]:
                    conn.execute("DELETE FROM imported_products WHERE asset_id=?", (asset_id,))
                    for pkg in item["packages"]:
                        conn.execute("""
                            INSERT OR IGNORE INTO imported_products
                              (id,asset_id,import_id,vendor,name,version,epoch,release,arch,manager)
                            VALUES(?,?,?,'',?,?,?,?,?,?)
                        """, (uuid4().hex, asset_id, batch_id, pkg["name"], pkg["version"],
                              pkg["epoch"], pkg["release"], pkg["arch"], pkg["manager"]))
            return {
                "import_id": batch_id, "duplicate": False,
                "assets_seen": len(parsed["observations"]),
                "error_count": parsed["error_count"], "collector": parsed["collector"],
            }

    def list_imports(self, profile_id: str) -> list[dict[str, Any]]:
        with self.repo._db() as conn:
            self.repo._profile_exists(conn, profile_id)
            return [dict(r) for r in conn.execute("""
                SELECT id,profile_id,collector,observed_at,imported_at,asset_count,error_count
                FROM inventory_imports WHERE profile_id=? ORDER BY imported_at DESC,id DESC LIMIT 100
            """, (profile_id,)).fetchall()]

    def asset_snapshot(self, asset_id: str) -> dict[str, Any] | None:
        with self.repo._db() as conn:
            self.repo._asset_profile(conn, asset_id)
            row = conn.execute("""
                SELECT collector,observed_at,patches_json,imported_at
                FROM asset_inventory_snapshots WHERE asset_id=?
            """, (asset_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["patches"] = json.loads(result.pop("patches_json"))
        return result
