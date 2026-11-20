"""M1d: trust boundaries and multi-collector source isolation (offline only)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.asset_storage import AssetRepository
from vulnfolio.inventory_import import InventoryImporter, ImportValidationError
from vulnfolio.vulnerability_api import create_app
from vulnfolio.vulnerabilities import from_cve_record

FIXTURE = Path(__file__).parent / "fixtures"
CVE = "CVE-2099-23456"


def report(profile: str, *, collector: str = "ansible", name: str = "node-1",
           products: list | None = None, patches: list | None = None,
           stamp: str = "2026-11-20T10:00:00Z", asset_key: str = "",
           coverage: tuple[str, str] = ("partial", "partial")) -> dict:
    obs = {
        "asset_id": name, "os": {
            "family": "Windows", "distribution": "Windows Server",
            "version": "2022", "build": "20348",
        },
        "packages": products if products is not None else [],
        "patches": patches if patches is not None else [],
        "coverage": {"packages": coverage[0], "patches": coverage[1]},
        "inventory_scope": "reported", "source": collector,
    }
    if asset_key:
        obs["asset_key"] = asset_key
    return {
        "schema_version": "0.2.0", "profile_id": profile,
        "collector": {"driver": collector, "capabilities": ["asset_inventory"]},
        "observed_at": stamp, "status": "success", "observations": [obs],
        "findings": [], "errors": [],
    }


def pkg(name: str, version: str = "1.0") -> dict:
    return {"name": name, "version": version, "manager": "rpm"}


class ObservationQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "quality.sqlite"
        self.repo = AssetRepository(self.path)
        self.profile = self.repo.create_profile("M1d synthetic")["id"]
        self.other = self.repo.create_profile("Other synthetic")["id"]
        raw = json.loads((FIXTURE / "cve_affected.json").read_text())
        self.repo.upsert(from_cve_record(raw, CVE, f"https://example.invalid/{CVE}"), raw)
        self.imp = InventoryImporter(self.repo)

    def assets(self):
        return self.repo.list_assets(self.profile)

    def asset(self):
        return self.assets()[0]

    def products(self):
        return self.repo.list_products(self.asset()["id"])

    def snapshots(self):
        return self.imp.source_snapshots(self.asset()["id"])

    def test_two_collectors_are_non_destructive_and_candidate_matching_remains(self):
        first = report(self.profile, products=[pkg("fluxctl", "1.2.0")],
                       patches=["KB5000000"], coverage=("complete", "complete"))
        second = report(self.profile, collector="vuls",
                        products=[pkg("helper", "2.0.0")], patches=[],
                        coverage=("complete", "unknown"),
                        stamp="2026-11-20T11:00:00Z")
        self.imp.import_envelope(self.profile, first)
        self.imp.import_envelope(self.profile, second)
        products = self.products()
        self.assertEqual({(p["source_collector"], p["name"]) for p in products},
                         {("ansible", "fluxctl"), ("vuls", "helper")})
        self.assertEqual(len(self.snapshots()), 2)
        a = next(s for s in self.snapshots() if s["collector"] == "ansible")
        self.assertEqual(a["patches"], ["KB5000000"])
        self.assertEqual(a["os_build"], "20348")
        self.assertEqual(a["packages_state"], "complete")
        self.assertEqual(len(self.repo.candidates(self.profile)["data"]), 1)
        self.assertEqual(self.repo.list_assets(self.other), [])

        # A complete empty snapshot from Vuls clears Vuls records only.
        cleared = report(self.profile, collector="vuls", products=[], patches=[],
                         coverage=("complete", "complete"),
                         stamp="2026-11-20T12:00:00Z")
        self.imp.import_envelope(self.profile, cleared)
        self.assertEqual([(p["source_collector"], p["name"]) for p in self.products()],
                         [("ansible", "fluxctl")])
        v = next(s for s in self.snapshots() if s["collector"] == "vuls")
        self.assertEqual(v["patches"], [])
        self.assertEqual(v["patches_state"], "complete")
        self.assertEqual(len(self.repo.candidates(self.profile)["data"]), 1)

    def test_legacy_v01_nonempty_replaces_own_source_empty_never_deletes(self):
        original = json.loads((FIXTURE / "ansible.json").read_text())
        first = AnsibleAdapter().normalize(original, self.profile)
        self.imp.import_envelope(self.profile, first)
        name = "rhel-demo"
        asset = next(a for a in self.assets() if a["name"] == name)
        before = {p["name"] for p in self.repo.list_products(asset["id"])}
        self.assertEqual(before, {"openssl"})
        updated = deepcopy(first)
        updated["observed_at"] = "2026-11-20T10:00:00Z"
        updated["observations"][0]["packages"] = [pkg("new-package")]
        self.imp.import_envelope(self.profile, updated)
        self.assertEqual({p["name"] for p in self.repo.list_products(asset["id"])},
                         {"new-package"})
        updated["observed_at"] = "2026-11-20T11:00:00Z"
        updated["observations"][0]["packages"] = []
        self.imp.import_envelope(self.profile, updated)
        self.assertEqual({p["name"] for p in self.repo.list_products(asset["id"])},
                         {"new-package"})
        source = self.imp.source_snapshots(asset["id"])[0]
        self.assertEqual(source["packages_state"], "unknown")
        self.assertEqual(source["packages_observed_at"], "2026-11-20T10:00:00Z")

    def test_partial_and_unknown_preserve_previous_successful_evidence(self):
        complete = report(self.profile, products=[pkg("first")],
                          patches=["KB0001"], coverage=("complete", "complete"))
        self.imp.import_envelope(self.profile, complete)
        partial = report(self.profile, products=[pkg("second")],
                         patches=["KB0002"], coverage=("partial", "partial"),
                         stamp="2026-11-20T11:00:00Z")
        self.imp.import_envelope(self.profile, partial)
        self.assertEqual({p["name"] for p in self.products()}, {"first", "second"})
        self.assertEqual(self.snapshots()[0]["patches"], ["KB0001", "KB0002"])
        unknown = report(self.profile, products=[], patches=[],
                         coverage=("unknown", "unknown"),
                         stamp="2026-11-20T12:00:00Z")
        self.imp.import_envelope(self.profile, unknown)
        self.assertEqual({p["name"] for p in self.products()}, {"first", "second"})
        current = self.snapshots()[0]
        self.assertEqual(current["packages_state"], "unknown")
        self.assertEqual(current["patches_state"], "unknown")
        self.assertEqual(current["patches"], ["KB0001", "KB0002"])
        self.assertEqual(current["packages_observed_at"], "2026-11-20T11:00:00Z")
        self.assertEqual(current["patches_observed_at"], "2026-11-20T11:00:00Z")

    def test_older_batch_is_ignored_without_renaming_asset(self):
        fresh = report(self.profile, name="old-host", asset_key="host:123",
                       products=[pkg("first")], coverage=("complete", "unknown"))
        self.imp.import_envelope(self.profile, fresh)
        asset_id = self.asset()["id"]
        stale = report(self.profile, name="wrong-new-name", asset_key="host:123",
                       products=[pkg("broken")], coverage=("complete", "unknown"),
                       stamp="2026-11-19T00:00:00Z")
        outcome = self.imp.import_envelope(self.profile, stale)
        self.assertEqual(outcome["stale_skipped"], 1)
        self.assertEqual(self.asset()["id"], asset_id)
        self.assertEqual(self.asset()["name"], "old-host")
        self.assertEqual({p["name"] for p in self.products()}, {"first"})

    def test_stable_identity_rename_keeps_asset_id_and_assessment(self):
        first = report(self.profile, name="old-host", asset_key="host:uuid-1",
                       products=[pkg("fluxctl", "1.2.0")],
                       coverage=("complete", "complete"))
        self.imp.import_envelope(self.profile, first)
        identifier = self.asset()["id"]
        self.repo.record_assessment(identifier, CVE, "investigating", "Needs verification")
        renamed = report(self.profile, name="new-host", asset_key="host:uuid-1",
                         products=[pkg("fluxctl", "1.2.0")],
                         stamp="2026-11-20T11:00:00Z",
                         coverage=("complete", "complete"))
        self.imp.import_envelope(self.profile, renamed)
        self.assertEqual(self.asset()["id"], identifier)
        self.assertEqual(self.asset()["name"], "new-host")
        self.assertEqual(self.repo.candidates(self.profile)["data"][0]["assessment"]["status"],
                         "investigating")
        self.assertEqual(len(self.repo.list_assessment_history(identifier, CVE)), 1)

    def test_identity_collision_rolls_back_entire_import(self):
        self.imp.import_envelope(self.profile, report(self.profile, name="a",
            asset_key="key-a", products=[pkg("first")], coverage=("complete", "unknown")))
        self.imp.import_envelope(self.profile, report(self.profile, name="b",
            asset_key="key-b", products=[pkg("second")], coverage=("complete", "unknown")))
        clash = report(self.profile, name="b", asset_key="key-a",
                       products=[pkg("unexpected")], stamp="2026-11-21T10:00:00Z",
                       coverage=("complete", "unknown"))
        with self.assertRaises(ImportValidationError):
            self.imp.import_envelope(self.profile, clash)
        self.assertEqual({a["name"] for a in self.assets()}, {"a", "b"})
        self.assertEqual(len(self.imp.list_imports(self.profile)), 2)
        self.assertNotIn("unexpected", {p["name"] for a in self.assets()
                          for p in self.repo.list_products(a["id"])})

    def test_invalid_v02_coverage_cannot_delete_or_mix_assets(self):
        valid = report(self.profile, products=[pkg("first")],
                       coverage=("complete", "unknown"))
        self.imp.import_envelope(self.profile, valid)
        for version, cov in [
            ("0.2.0", ("unknown", "unknown")),
            ("0.2.0", ("complete", "invalid")),
            ("0.2.0", ("partial", "unknown")),
        ]:
            bad = deepcopy(valid)
            bad["observed_at"] = "2026-11-20T11:00:00Z"
            bad["schema_version"] = version
            bad["observations"][0]["coverage"]["packages"] = cov[0]
            bad["observations"][0]["coverage"]["patches"] = cov[1]
            # First and third cases have a package despite unknown, except
            # for the third: explicitly force an invalid nonempty patch.
            if cov[0] != "unknown" and cov[1] == "unknown":
                bad["observations"][0]["patches"] = ["KB1"]
            with self.assertRaises(ImportValidationError):
                self.imp.import_envelope(self.profile, bad)
        self.assertEqual({p["name"] for p in self.products()}, {"first"})
        bad = deepcopy(valid)
        bad["observed_at"] = "naive-no-timezone"
        with self.assertRaises(ImportValidationError):
            self.imp.import_envelope(self.profile, bad)

    def test_old_db_tables_migrate_once_and_keep_assessments(self):
        # Construct pre-M1d storage contents without the migration marker,
        # then reopen. Keep same schema, no external network connection.
        asset = self.repo.add_asset(self.profile, "legacy-node")
        self.repo.add_product(asset["id"], "manual", "Lab", "1.0")
        self.repo.record_assessment(asset["id"], CVE, "mitigated", "Legacy preserved")
        batch = uuid4().hex
        with self.repo._db() as conn:
            conn.execute("""
                INSERT INTO inventory_imports
                    (id,profile_id,content_sha256,collector,observed_at,imported_at,
                     asset_count,error_count)
                VALUES(?,?,?,?,?,?,?,?)
            """, (batch, self.profile, "fake-old-hash", "ansible",
                  "2026-11-19T00:00:00Z", "2026-11-19T00:00:00Z", 1, 0))
            conn.execute("""
                INSERT INTO asset_inventory_snapshots
                    (asset_id,import_id,collector,observed_at,patches_json,imported_at)
                VALUES(?,?,?,?,?,?)
            """, (asset["id"], batch, "ansible", "2026-11-19T00:00:00Z",
                  '["KB12345"]', "2026-11-19T00:00:00Z"))
            conn.execute("""
                INSERT INTO imported_products
                    (id,asset_id,import_id,vendor,name,version,epoch,release,arch,manager)
                VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (uuid4().hex, asset["id"], batch, "", "legacy-package",
                  "2.0", "", "", "", "rpm"))
            conn.execute("DELETE FROM inventory_schema_migrations")
        upgraded = AssetRepository(self.path)
        again = AssetRepository(self.path)
        rows = again.list_products(asset["id"])
        self.assertEqual({p["name"] for p in rows}, {"legacy-package", "manual"})
        migrated = next(p for p in rows if p["name"] == "legacy-package")
        self.assertEqual(migrated["source_collector"], "legacy-unverified")
        self.assertEqual(len(InventoryImporter(upgraded).source_snapshots(asset["id"])), 1)
        self.assertEqual(upgraded.list_assessment_history(asset["id"], CVE)[0]["note"],
                         "Legacy preserved")

    def test_http_json_api_sources_and_global_boundary(self):
        with TestClient(create_app(self.path), client=("127.0.0.1", 9000)) as client:
            payload = report(self.profile, products=[pkg("fluxctl", "1.2.0")],
                             patches=["KB5000000"], coverage=("complete", "complete"))
            response = client.post(f"/api/v1/profiles/{self.profile}/imports", json=payload)
            self.assertEqual(response.status_code, 201, response.text)
            asset_id = self.asset()["id"]
            observed = client.get(f"/api/v1/assets/{asset_id}/inventory")
            self.assertEqual(observed.status_code, 200)
            data = observed.json()
            self.assertEqual(data["snapshot"]["collector"], "ansible")
            self.assertEqual(data["sources"][0]["os_build"], "20348")
            self.assertEqual(data["sources"][0]["patches_state"], "complete")
            product = client.get(f"/api/v1/assets/{asset_id}/products").json()["data"][0]
            self.assertEqual(product["source_collector"], "ansible")
            self.assertEqual(product["coverage"], "complete")
            self.assertNotIn("node-1", client.get("/api/v1/vulnerabilities").text)
        with TestClient(create_app(self.path)) as outside:
            self.assertEqual(outside.get(f"/api/v1/assets/{self.asset()['id']}/inventory").status_code, 403)


if __name__ == "__main__":
    unittest.main()
