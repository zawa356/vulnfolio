"""M1c authenticated HTTPS import, scoped tokens, fail-closed behavior."""
from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.asset_storage import AssetRepository
from vulnfolio.ingest_credentials import (
    CredentialsError, authorized, issue_token, load_store, read_token, revoke_token,
)
from vulnfolio.ingest_upload import UploadError, endpoint_url, envelope_bytes, send
from vulnfolio.inventory_import import InventoryImporter
from vulnfolio.vulnerability_api import create_app


class ScopedIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "database.sqlite"
        repo = AssetRepository(self.db)
        self.profile = repo.create_profile("Company A")["id"]
        self.other = repo.create_profile("Company B")["id"]
        self.store = self.root / "private" / "tokens.json"
        self.token_file = self.root / "private" / "collector.token"
        self.token_id = issue_token(self.store, self.profile, self.token_file)
        self.token = read_token(self.token_file)
        self.env = patch.dict(os.environ, {"VULNFOLIO_INGEST_TOKENS_FILE": str(self.store)})
        self.env.start()
        self.app = create_app(self.db)
        self.client = TestClient(self.app, base_url="https://example.test",
                                 client=("203.0.113.17", 53121))
        self.path = f"/api/v1/ingest/profiles/{self.profile}/imports"
        self.headers = {"Authorization": "Bearer " + self.token}
        fixture = json.loads((Path(__file__).parent / "fixtures" / "ansible.json").read_text())
        self.payload = AnsibleAdapter().normalize(fixture, self.profile)

    def tearDown(self):
        self.client.close()
        self.env.stop()
        self.temp.cleanup()

    def test_scoped_upload_duplicate_and_cannot_read_inventory(self):
        first = self.client.post(self.path, json=self.payload, headers=self.headers)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertFalse(first.json()["duplicate"])
        self.assertEqual(first.headers.get("cache-control"), "no-store")
        second = self.client.post(self.path, json=self.payload, headers=self.headers)
        self.assertEqual(second.status_code, 201)
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(first.json()["import_id"], second.json()["import_id"])
        repo = AssetRepository(self.db)
        self.assertEqual(len(repo.list_assets(self.profile)), 2)
        self.assertEqual(len(InventoryImporter(repo).list_imports(self.profile)), 1)
        # Public asset endpoints are NOT opened by the upload token.
        self.assertEqual(self.client.get("/api/v1/profiles", headers=self.headers).status_code, 403)
        self.assertEqual(self.client.get("/environment", headers=self.headers).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/ingest/profiles/" + self.profile + "/imports",
                                         headers=self.headers).status_code, 405)
        self.assertNotIn("Company A", self.client.get("/api/v1/vulnerabilities").text)

    def test_profile_scope_isolated_and_mismatch_validation(self):
        wrong_url = f"/api/v1/ingest/profiles/{self.other}/imports"
        self.assertEqual(self.client.post(wrong_url, json=self.payload,
                                          headers=self.headers).status_code, 401)
        bad = dict(self.payload, profile_id=self.other)
        self.assertEqual(self.client.post(self.path, json=bad, headers=self.headers).status_code, 422)
        self.assertEqual(AssetRepository(self.db).list_assets(self.other), [])

    def test_no_token_wrong_token_plain_http_origin_and_disabled_config(self):
        self.assertEqual(self.client.post(self.path, json=self.payload).status_code, 401)
        self.assertEqual(self.client.post(self.path, json=self.payload,
                        headers={"Authorization": "Bearer vf_" + "x" * 43}).status_code, 401)
        self.assertEqual(self.client.post(self.path, json=self.payload,
                        headers=self.headers | {"Origin": "https://example.test"}).status_code, 403)
        with TestClient(self.app, base_url="http://example.test",
                        client=("203.0.113.17", 1234)) as plaintext:
            self.assertEqual(plaintext.post(self.path, json=self.payload,
                                            headers=self.headers).status_code, 403)
        with patch.dict(os.environ, {"VULNFOLIO_INGEST_TOKENS_FILE": ""}):
            self.assertEqual(self.client.post(self.path, json=self.payload,
                                              headers=self.headers).status_code, 503)

    def test_revoke_rotate_and_bad_store_fail_closed(self):
        token2file = self.root / "private" / "collector2.token"
        issued2 = issue_token(self.store, self.profile, token2file)
        token2 = read_token(token2file)
        self.assertEqual(len(load_store(self.store)["tokens"]), 2)
        self.assertNotIn(self.token, self.store.read_text())
        self.assertNotIn(token2, self.store.read_text())
        self.assertTrue(authorized(self.store, token2, self.profile))
        self.assertTrue(revoke_token(self.store, self.token_id))
        self.assertFalse(revoke_token(self.store, self.token_id))
        self.assertEqual(self.client.post(self.path, json=self.payload,
                                          headers=self.headers).status_code, 401)
        new_auth = {"Authorization": "Bearer " + token2}
        self.assertEqual(self.client.post(self.path, json=self.payload,
                                          headers=new_auth).status_code, 201)
        if os.name == "posix":
            os.chmod(self.store, 0o644)
            self.assertEqual(self.client.post(self.path, json=self.payload,
                                              headers=new_auth).status_code, 503)
            os.chmod(self.store, 0o600)
        self.assertTrue(revoke_token(self.store, issued2))

    def test_auth_before_json_and_shared_limits(self):
        too_large = b"x" * (2 * 1024 * 1024 + 1)
        self.assertEqual(self.client.post(self.path, content=too_large,
                        headers=self.headers | {"Content-Type": "application/json"}).status_code, 413)
        self.assertEqual(self.client.post(self.path, content=b"not-json",
                        headers=self.headers | {"Content-Type": "application/json"}).status_code, 422)
        self.assertEqual(self.client.post(self.path, content=b"{}",
                        headers=self.headers | {"Content-Type": "text/plain"}).status_code, 415)
        bad = dict(self.payload, schema_version="0.0.0")
        self.assertEqual(self.client.post(self.path, json=bad, headers=self.headers).status_code, 422)
        # Unauthorized callers should never process a large body.
        self.assertEqual(self.client.post(self.path, content=too_large,
                        headers={"Content-Type": "application/json"}).status_code, 401)

    def test_token_and_inventory_file_input_guards(self):
        self.assertEqual(len(self.token), 46)
        if os.name == "posix":
            self.assertEqual(self.token_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.store.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(CredentialsError):
            issue_token(self.store, self.profile, self.token_file)
        with self.assertRaises(UploadError):
            endpoint_url("http://127.0.0.1:8000", self.profile)
        with self.assertRaises(UploadError):
            endpoint_url("https://user:pass@example.test", self.profile)
        with self.assertRaises(UploadError):
            endpoint_url("https://example.test/redirect", self.profile)
        envelope_path = self.root / "inventory.json"
        envelope_path.write_text(json.dumps(self.payload))
        self.assertEqual(json.loads(envelope_bytes(envelope_path, self.profile))["profile_id"],
                         self.profile)
        with self.assertRaises(UploadError):
            envelope_bytes(envelope_path, self.other)
        if os.name == "posix":
            os.chmod(self.token_file, 0o644)
            with self.assertRaises(CredentialsError):
                read_token(self.token_file)
            os.chmod(self.token_file, 0o600)

    def test_uploader_retries_only_transient_and_does_not_follow_redirects(self):
        document = json.dumps(self.payload).encode()
        sequence = [503, 429, 201]
        calls = []
        def response(request):
            calls.append(request)
            code = sequence.pop(0)
            return httpx.Response(code, json={"import_id": "test-batch", "duplicate": False})
        with patch("vulnfolio.ingest_upload.time.sleep") as sleep:
            result = send("https://example.test", self.profile, document, self.token,
                          attempts=3, _transport=httpx.MockTransport(response))
        self.assertEqual(result["import_id"], "test-batch")
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(calls[0].headers["Authorization"], "Bearer " + self.token)

        statuses = [422, 302]
        for status in statuses:
            calls.clear()
            def reject(request):
                calls.append(request)
                return httpx.Response(status, headers={"location": "https://another.example/"})
            with self.assertRaises(UploadError):
                send("https://example.test", self.profile, document, self.token,
                     attempts=3, _transport=httpx.MockTransport(reject))
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
