"""Create a completely synthetic M1d sandbox database for user acceptance.

This script never connects to remote hosts, upstream CVE APIs or the network.
It refuses to overwrite an existing database and uses only bundled fixtures.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.inventory_import import InventoryImporter
from vulnfolio.vulnerability_storage import utcnow
from vulnfolio.vulnerabilities import from_cve_record

ROOT = Path(__file__).resolve().parent.parent
FAKE_CVE = "CVE-2099-23456"


def envelope(profile_id, driver, rows, when):
    return {
        "schema_version": "0.2.0",
        "profile_id": profile_id,
        "collector": {"driver": driver, "capabilities": ["asset_inventory", "installed_packages"]},
        "observed_at": when,
        "status": "success",
        "observations": rows,
        "findings": [],
        "errors": [],
    }


def observation(name, key, family, distribution, version, build,
                packages, patches, coverage):
    return {
        "asset_id": name, "asset_key": key,
        "os": {"family": family, "distribution": distribution,
               "version": version, "build": build},
        "packages": packages, "patches": patches, "coverage": coverage,
        "inventory_scope": "reported", "source": "synthetic",
    }


def create_demo(db_path: Path) -> dict:
    if db_path.exists():
        raise FileExistsError("Demo DB already exists; choose a fresh path (no overwrite)")
    raw = json.loads((ROOT / "tests" / "fixtures" / "cve_affected.json").read_text())
    repo = AssetRepository(db_path)
    repo.upsert(from_cve_record(raw, FAKE_CVE, "https://example.invalid/" + FAKE_CVE), raw)
    profile_id = repo.create_profile("M1d Synthetic Lab", "No real hosts or customer data")["id"]
    importer = InventoryImporter(repo)
    when = utcnow()
    linux = observation(
        "lab-linux", "machine:synthetic-linux-001",
        "RedHat", "Synthetic Enterprise Linux", "9.5", "",
        [
            {"name": "fluxctl", "version": "1.2.0", "release": "1.el9",
             "epoch": "0", "arch": "x86_64", "manager": "rpm"},
            {"name": "openssl", "version": "3.0.7", "release": "27.el9",
             "epoch": "1", "arch": "x86_64", "manager": "rpm"},
        ],
        [],
        {"packages": "partial", "patches": "unknown"},
    )
    windows = observation(
        "lab-windows", "machine:synthetic-windows-001",
        "Windows", "Synthetic Windows Server", "2022", "20348",
        [{"name": "Synthetic Console", "version": "2.0", "manager": "windows_registry"}],
        ["KB5000000"],
        {"packages": "partial", "patches": "partial"},
    )
    other_collector = observation(
        "lab-linux", "machine:synthetic-linux-001",
        "RedHat", "Synthetic Enterprise Linux", "9.5", "",
        [{"name": "helper", "version": "2.0.0", "manager": "rpm"}],
        [],
        {"packages": "partial", "patches": "unknown"},
    )
    importer.import_envelope(profile_id, envelope(profile_id, "ansible",
                                                 [linux, windows], when))
    importer.import_envelope(profile_id, envelope(profile_id, "vuls",
                                                 [other_collector], when))
    linux_asset = next(a for a in repo.list_assets(profile_id) if a["name"] == "lab-linux")
    repo.record_assessment(linux_asset["id"], FAKE_CVE, "investigating",
                           "Synthetic candidate; no confirmed vulnerability")
    return {"profile_id": profile_id, "assets": 2, "cve": FAKE_CVE,
            "candidates": len(repo.candidates(profile_id)["data"])}


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare offline synthetic vulnfolio M1d demo DB")
    parser.add_argument("--db", type=Path, default=Path("private-data/m1d-demo.sqlite"))
    args = parser.parse_args()
    try:
        summary = create_demo(args.db)
    except (FileExistsError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print("SYNTHETIC DATA ONLY — never use this database for real assessments")
    print("SQLite:", args.db.resolve())
    print("Profile:", summary["profile_id"])
    print("Assets:", summary["assets"], "CVE candidates:", summary["candidates"])
    print("Start locally (Bash):")
    print(f"  VULNFOLIO_DB='{args.db.resolve()}' uvicorn "
          "vulnfolio.vulnerability_api:app --host 127.0.0.1 --port 8000")
    print("Then open http://127.0.0.1:8000/environment")
    return 0


if __name__ == "__main__":
    sys.exit(main())
