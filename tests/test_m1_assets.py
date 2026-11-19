"""M1: private profile, software, candidate and assessment contract tests."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient

from vulnfolio.asset_storage import AssetRepository, Conflict, NotFound
from vulnfolio.vulnerabilities import from_cve_record
from vulnfolio.vulnerability_api import create_app

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "cve_affected.json").read_text())
CVE = "CVE-2099-23456"


class AssetStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "assets.db")
        self.store = AssetRepository(self.path)
        self.store.upsert(from_cve_record(FIXTURE, CVE, "https://example.invalid/" + CVE), FIXTURE)

    def tearDown(self):
        self.temp.cleanup()

    def test_profile_asset_product_persist_and_duplicates(self):
        profile = self.store.create_profile("Project Alpha")
        other = self.store.create_profile("Project Beta")
        self.assertNotEqual(profile["id"], other["id"])
        with self.assertRaises(Conflict):
            self.store.create_profile("project alpha")
        asset = self.store.add_asset(profile["id"], "server01", "Linux", "RHEL 9")
        with self.assertRaises(Conflict):
            self.store.add_asset(profile["id"], "SERVER01")
        product = self.store.add_product(asset["id"], "fluxctl", "Acme", "1.2.0")
        with self.assertRaises(Conflict):
            self.store.add_product(asset["id"], "Fluxctl", "ACME", "1.2.0")
        self.assertEqual(self.store.list_profiles()[0]["asset_count"], 1)
        self.assertEqual(self.store.list_products(asset["id"])[0]["id"], product["id"])
        self.assertEqual(self.store.list_assets(other["id"]), [])
        self.assertEqual(self.store.get_profile(profile["id"])["name"], "Project Alpha")
        self.assertEqual(self.store.get_asset(asset["id"])["os_version"], "RHEL 9")

    def test_candidate_exact_version_and_status_isolated_by_asset(self):
        one = self.store.create_profile("One")
        two = self.store.create_profile("Two")
        a1 = self.store.add_asset(one["id"], "a1")
        a2 = self.store.add_asset(two["id"], "a2")
        self.store.add_product(a1["id"], "fluxctl", "Acme", "1.2.0")
        self.store.add_product(a2["id"], "fluxctl", "Acme", "1.2.0")
        first = self.store.candidates(one["id"])["data"]
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["match_basis"], "exact_version_listed_affected")
        self.assertTrue(first[0]["vendor_verified"])
        self.assertEqual(first[0]["assessment"]["status"], "new")
        result = self.store.record_assessment(a1["id"], CVE, "mitigated", "Patched on test node")
        self.assertEqual(result["status"], "mitigated")
        self.assertEqual(self.store.candidates(one["id"])["data"], [])
        self.assertEqual(len(self.store.candidates(one["id"], include_closed=True)["data"]), 1)
        self.assertEqual(self.store.candidates(two["id"])["data"][0]["assessment"]["status"], "new")
        self.assertEqual(len(self.store.list_assessment_history(a1["id"], CVE)), 1)
        # Idempotent assessment updates must not create duplicate history.
        self.store.record_assessment(a1["id"], CVE, "mitigated", "Patched on test node")
        self.assertEqual(len(self.store.list_assessment_history(a1["id"], CVE)), 1)
        self.store.record_assessment(a1["id"], CVE, "investigating", "Re-check")
        self.assertEqual(len(self.store.list_assessment_history(a1["id"], CVE)), 2)

    def test_product_only_candidate_does_not_claim_affected(self):
        profile = self.store.create_profile("Unsure")
        asset = self.store.add_asset(profile["id"], "server01")
        self.store.add_product(asset["id"], "fluxctl", "", "9.9.9")
        item = self.store.candidates(profile["id"])["data"][0]
        self.assertEqual(item["match_basis"], "product_only")
        self.assertFalse(item["vendor_verified"])
        self.assertIn("not a confirmed", item["evidence"])

    def test_explicit_unaffected_version_and_vendor_mismatch_not_flagged(self):
        profile = self.store.create_profile("Patched")
        a = self.store.add_asset(profile["id"], "a")
        self.store.add_product(a["id"], "fluxctl", "Acme", "1.2.1")
        self.store.add_product(a["id"], "helper", "OtherVendor", "2.0.0")
        self.assertEqual(self.store.candidates(profile["id"])["metadata"]["count"], 0)

    def test_absent_source_affected_and_description_text_not_matched(self):
        profile = self.store.create_profile("No fuzzy")
        a = self.store.add_asset(profile["id"], "asset")
        self.store.add_product(a["id"], "vulnerability", "", "1.0")
        self.assertEqual(self.store.candidates(profile["id"])["data"], [])

    def test_remove_product_removes_candidate(self):
        profile = self.store.create_profile("Remove")
        a = self.store.add_asset(profile["id"], "host")
        product = self.store.add_product(a["id"], "fluxctl", "Acme", "1.2.0")
        self.assertEqual(len(self.store.candidates(profile["id"])["data"]), 1)
        self.store.delete_product(product["id"])
        self.assertEqual(self.store.candidates(profile["id"])["data"], [])
        with self.assertRaises(NotFound):
            self.store.delete_product(product["id"])

    def test_invalid_profile_asset_and_status(self):
        with self.assertRaises(NotFound):
            self.store.list_assets("missing")
        with self.assertRaises(NotFound):
            self.store.add_product("missing", "openssl")
        profile = self.store.create_profile("Test")
        asset = self.store.add_asset(profile["id"], "node")
        with self.assertRaises(ValueError):
            self.store.record_assessment(asset["id"], CVE, "invalid")
        with self.assertRaises(NotFound):
            self.store.record_assessment(asset["id"], "CVE-2099-9999", "investigating")
        with self.assertRaises(ValueError):
            self.store.create_profile("   ")

    def test_private_api_local_only_and_global_access_still_separate(self):
        app = create_app(self.path)
        # TestClient defaults to a non-loopback peer. No private data must leak.
        with TestClient(app) as outside:
            self.assertEqual(outside.get("/api/v1/profiles").status_code, 403)
            self.assertEqual(outside.get("/environment").status_code, 403)
            self.assertEqual(outside.get("/api/v1/vulnerabilities").status_code, 200)
        with TestClient(app, client=("127.0.0.1", 54321)) as client:
            self.assertEqual(client.get("/environment").status_code, 200)
            self.assertIn("My Environment", client.get("/environment").text)
            blocked = client.post("/api/v1/profiles", json={"name": "CSRF"},
                                  headers={"Origin": "https://foreign.example"})
            self.assertEqual(blocked.status_code, 403)
            created = client.post("/api/v1/profiles", json={"name": "Internal project"})
            self.assertEqual(created.status_code, 201)
            pid = created.json()["id"]
            asset = client.post(f"/api/v1/profiles/{pid}/assets",
                                json={"name": "linux01", "os_family": "Linux"}).json()
            apath = f"/api/v1/assets/{asset['id']}/products"
            product = client.post(apath, json={"name": "fluxctl", "vendor": "Acme", "version": "1.2.0"})
            self.assertEqual(product.status_code, 201)
            self.assertEqual(client.get(apath).json()["data"][0]["name"], "fluxctl")
            candidates = client.get(f"/api/v1/profiles/{pid}/candidates").json()
            self.assertEqual(len(candidates["data"]), 1)
            self.assertTrue(candidates["metadata"]["complete"])
            url = f"/api/v1/assets/{asset['id']}/assessments/{CVE}"
            self.assertEqual(client.put(url, json={"status": "investigating", "note": "checking"}).status_code, 200)
            self.assertEqual(client.get(url + "/history").json()["data"][0]["note"], "checking")
            self.assertEqual(client.post(apath, json={"name": "fluxctl", "vendor": "Acme", "version": "1.2.0"}).status_code, 409)
            self.assertEqual(client.put(url, json={"status": "invalid"}).status_code, 422)
            self.assertEqual(client.post("/api/v1/profiles", json={"name": "x", "unknown": "y"}).status_code, 422)
            self.assertEqual(client.post(f"/api/v1/profiles/{pid}/assets", json={"name": "  "}).status_code, 422)
            self.assertEqual(client.get("/api/v1/profiles/missing/candidates").status_code, 404)
            # Public CVE detail never embeds profile / host / package inventory.
            global_detail = client.get("/api/v1/vulnerabilities/" + CVE).json()
            self.assertNotIn("Internal project", json.dumps(global_detail))
            self.assertNotIn("linux01", json.dumps(global_detail))
            self.assertEqual(client.delete(f"/api/v1/products/{product.json()['id']}").status_code, 204)
            self.assertEqual(client.get(f"/api/v1/profiles/{pid}/candidates").json()["data"], [])


if __name__ == "__main__":
    unittest.main()
