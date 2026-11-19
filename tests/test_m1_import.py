"""M1b: canonical collector envelope -> private profile inventory import."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.asset_storage import AssetRepository
from vulnfolio.vulnerability_api import create_app
from vulnfolio.vulnerabilities import from_cve_record

FIXTURES = Path(__file__).parent / "fixtures"
RAW = json.loads((FIXTURES / "cve_affected.json").read_text())
CVE = "CVE-2099-23456"


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.store = AssetRepository(Path(self.temp.name) / "inventory.db")
        self.store.upsert(from_cve_record(RAW, CVE, "https://example.invalid/" + CVE), RAW)
        self.profile = self.store.create_profile("Collection demo")
        self.other = self.store.create_profile("Other project")
        self.client = TestClient(create_app(self.store.path), client=("127.0.0.1", 5000))

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def envelope(self):
        payload = json.loads((FIXTURES / "ansible.json").read_text())
        payload["hosts"]["rhel-demo"]["ansible_facts"]["packages"]["fluxctl"] = [
            {"name": "fluxctl", "version": "1.2.0", "release": "1.el9", "epoch": "0", "arch": "x86_64", "source": "rpm"}
        ]
        return AnsibleAdapter().normalize(payload, self.profile["id"])

    def endpoint(self):
        return f"/api/v1/profiles/{self.profile['id']}/imports"

    def test_import_produces_assets_candidates_and_windows_patches(self):
        payload = self.envelope()
        response = self.client.post(self.endpoint(), json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        result = response.json()
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["assets_seen"], 2)
        self.assertEqual(result["error_count"], 1)  # unreachable host, not accidentally deleted
        self.assertEqual(result["collector"], "ansible")
        assets = self.store.list_assets(self.profile["id"])
        self.assertEqual({a["name"] for a in assets}, {"rhel-demo", "win-demo"})
        rhel = next(a for a in assets if a["name"] == "rhel-demo")
        win = next(a for a in assets if a["name"] == "win-demo")
        self.assertEqual(rhel["os_family"], "RedHat")
        products = self.store.list_products(rhel["id"])
        self.assertEqual({p["name"] for p in products}, {"openssl", "fluxctl"})
        fluxctl = next(p for p in products if p["name"] == "fluxctl")
        self.assertEqual(fluxctl["origin"], "imported")
        self.assertEqual(fluxctl["release"], "1.el9")
        self.assertEqual(fluxctl["epoch"], "0")
        self.assertEqual(fluxctl["arch"], "x86_64")
        self.assertEqual(fluxctl["manager"], "rpm")
        matched = self.store.candidates(self.profile["id"])["data"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["cve_id"], CVE)
        self.assertEqual(matched[0]["match_basis"], "exact_version_listed_affected")
        self.assertFalse(matched[0]["vendor_verified"])
        inventory = self.client.get(f"/api/v1/assets/{win['id']}/inventory")
        self.assertEqual(inventory.status_code, 200)
        self.assertEqual(inventory.json()["snapshot"]["patches"], ["KB5000000"])
        self.assertEqual(self.client.get(self.endpoint()).json()["data"][0]["asset_count"], 2)
        # Import must not contaminate other profiles or global REST.
        self.assertEqual(self.store.list_assets(self.other["id"]), [])
        self.assertNotIn("rhel-demo", self.client.get(f"/api/v1/vulnerabilities/{CVE}").text)

    def test_duplicate_import_is_idempotent_and_edited_manual_data_survives(self):
        payload = self.envelope()
        first = self.client.post(self.endpoint(), json=payload).json()
        second = self.client.post(self.endpoint(), json=payload).json()
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["import_id"], second["import_id"])
        rhel = next(a for a in self.store.list_assets(self.profile["id"]) if a["name"] == "rhel-demo")
        self.store.add_product(rhel["id"], "manual-only", "Acme", "0.0.1")
        self.assertEqual(len(self.client.get(self.endpoint()).json()["data"]), 1)
        self.assertEqual(len(self.store.list_assets(self.profile["id"])), 2)
        # Empty/missing packages from a later collection don't remove known installed software.
        newer = copy.deepcopy(payload)
        newer["observed_at"] = "2026-11-20T00:00:00Z"
        newer["observations"][0]["packages"] = []
        newer["observations"][1]["patches"] = []
        third = self.client.post(self.endpoint(), json=newer)
        self.assertEqual(third.status_code, 201, third.text)
        products = self.store.list_products(rhel["id"])
        self.assertEqual({p["name"] for p in products}, {"openssl", "fluxctl", "manual-only"})
        self.assertEqual(len(self.store.candidates(self.profile["id"])["data"]), 1)
        win = next(a for a in self.store.list_assets(self.profile["id"]) if a["name"] == "win-demo")
        self.assertEqual(self.client.get(f"/api/v1/assets/{win['id']}/inventory").json()["snapshot"]["patches"],
                         ["KB5000000"])
        # Observations list can omit failed hosts; never implicitly remove assets.
        fewer = copy.deepcopy(newer)
        fewer["observed_at"] = "2026-11-21T00:00:00Z"
        fewer["observations"] = fewer["observations"][1:]
        self.assertEqual(self.client.post(self.endpoint(), json=fewer).status_code, 201)
        self.assertEqual(len(self.store.list_assets(self.profile["id"])), 2)

    def test_nonempty_new_package_snapshot_replaces_only_imported_products(self):
        first = self.envelope()
        self.assertEqual(self.client.post(self.endpoint(), json=first).status_code, 201)
        rhel = next(a for a in self.store.list_assets(self.profile["id"]) if a["name"] == "rhel-demo")
        manual = self.store.add_product(rhel["id"], "manual", "Lab", "1")
        newer = copy.deepcopy(first)
        newer["observed_at"] = "2026-11-20T00:00:00Z"
        newer["observations"][0]["packages"] = [
            {"name": "unrelated", "version": "1.0", "manager": "rpm"}
        ]
        self.assertEqual(self.client.post(self.endpoint(), json=newer).status_code, 201)
        products = self.store.list_products(rhel["id"])
        self.assertEqual({p["name"] for p in products}, {"manual", "unrelated"})
        self.assertIn(manual["id"], [p["id"] for p in products])
        self.assertEqual(self.store.candidates(self.profile["id"])["data"], [])

    def test_rejects_wrong_profile_unsupported_findings_and_invalid_inputs(self):
        payload = self.envelope()
        bad = copy.deepcopy(payload)
        bad["profile_id"] = self.other["id"]
        self.assertEqual(self.client.post(self.endpoint(), json=bad).status_code, 422)
        bad = copy.deepcopy(payload)
        bad["findings"] = [{"vulnerability_id": CVE}]
        self.assertEqual(self.client.post(self.endpoint(), json=bad).status_code, 422)
        bad = copy.deepcopy(payload)
        bad["schema_version"] = "9.0"
        self.assertEqual(self.client.post(self.endpoint(), json=bad).status_code, 422)
        bad = copy.deepcopy(payload)
        bad["observations"].append(copy.deepcopy(bad["observations"][0]))
        self.assertEqual(self.client.post(self.endpoint(), json=bad).status_code, 422)
        bad = copy.deepcopy(payload)
        bad["observations"][0]["packages"][0]["version"] = {"malicious": "object"}
        self.assertEqual(self.client.post(self.endpoint(), json=bad).status_code, 422)
        self.assertEqual(self.client.post(self.endpoint(), data=b"not json",
                                          headers={"Content-Type": "application/json"}).status_code, 422)
        self.assertEqual(self.client.post(self.endpoint(), data=b"{}",
                                          headers={"Content-Type": "text/plain"}).status_code, 415)
        self.assertEqual(self.client.post(self.endpoint(), data=b"x" * (2 * 1024 * 1024 + 1),
                                          headers={"Content-Type": "application/json"}).status_code, 413)
        self.assertEqual(self.store.list_assets(self.profile["id"]), [])

    def test_existing_manual_asset_is_reused_and_manual_product_preserved(self):
        manual = self.store.add_asset(self.profile["id"], "rhel-demo", "Linux", "RHEL 9")
        product = self.store.add_product(manual["id"], "fluxctl", "Acme", "1.2.0")
        response = self.client.post(self.endpoint(), json=self.envelope())
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(next(a for a in self.store.list_assets(self.profile["id"])
                              if a["name"] == "rhel-demo")["id"], manual["id"])
        products = self.store.list_products(manual["id"])
        self.assertIn(product["id"], [p["id"] for p in products])
        self.assertEqual(len([p for p in products if p["origin"] == "imported"]), 2)
        self.assertEqual(len(self.store.candidates(self.profile["id"])["data"]), 1)

    def test_non_loopback_cannot_import_or_read_private_inventory(self):
        payload = self.envelope()
        with TestClient(create_app(self.store.path)) as outside:
            self.assertEqual(outside.post(self.endpoint(), json=payload).status_code, 403)
            self.assertEqual(outside.get(self.endpoint()).status_code, 403)
        self.assertEqual(self.client.post(self.endpoint(), json=payload,
                          headers={"Origin": "https://evil.example"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
