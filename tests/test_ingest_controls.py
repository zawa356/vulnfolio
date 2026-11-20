"""Security contracts: expiry, migration, local audit and bounded rate limits."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.asset_storage import AssetRepository
from vulnfolio.ingest_audit import recent_audit, prune_audit
from vulnfolio.ingest_credentials import (
    CredentialsError, authenticate_token, authorized, issue_token, load_store,
    migrate_store, read_token,
)
from vulnfolio.ingest_security import IngestRateLimiter
from vulnfolio.ingest_server import create_ingest_app
from vulnfolio.inventory_import import InventoryImporter


class SecurityControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "vulnfolio.sqlite"
        self.repo = AssetRepository(self.db)
        self.profile = self.repo.create_profile("Synthetic test")["id"]
        self.other = self.repo.create_profile("Other")["id"]
        self.store = self.root / "private" / "tokens.json"
        self.token_file = self.root / "private" / "client.token"
        self.token_id = issue_token(self.store, self.profile, self.token_file)
        self.token = read_token(self.token_file)
        self.env = patch.dict(os.environ, {"VULNFOLIO_INGEST_TOKENS_FILE": str(self.store)})
        self.env.start()
        self.addCleanup(self.env.stop)
        fixture = json.loads((Path(__file__).parent / "fixtures" / "ansible.json").read_text())
        self.envelope = AnsibleAdapter().normalize(fixture, self.profile)
        self.url = f"/api/v1/ingest/profiles/{self.profile}/imports"
        self.headers = {"Authorization": "Bearer " + self.token}

    def client(self, limiter=None):
        return TestClient(
            create_ingest_app(self.db, limiter=limiter),
            base_url="https://collector.example", client=("203.0.113.77", 49100),
        )

    def test_token_expiry_and_legacy_migration_preserve_bearer(self):
        store = load_store(self.store)
        self.assertEqual(store["schema_version"], 2)
        original = store["tokens"][0]
        self.assertEqual(original["expires_at"] - original["issued_at"], 7 * 86400)
        self.assertTrue(authorized(self.store, self.token, self.profile))
        self.assertFalse(authorized(self.store, self.token, self.other))
        with patch("vulnfolio.ingest_credentials.time.time",
                   return_value=original["expires_at"]):
            self.assertFalse(authorized(self.store, self.token, self.profile))
            with self.client() as client:
                self.assertEqual(client.post(self.url, json=self.envelope,
                                             headers=self.headers).status_code, 401)
        # v1 must fail closed until explicit bounded migration.
        old = {"schema_version": 1, "tokens": [
            {field: original[field] for field in ("id", "profile_id", "sha256")}
        ]}
        self.store.write_text(json.dumps(old))
        with self.assertRaises(CredentialsError):
            load_store(self.store)
        with self.client() as client:
            self.assertEqual(client.post(self.url, json=self.envelope,
                                         headers=self.headers).status_code, 503)
        self.assertEqual(migrate_store(self.store, ttl_hours=1), 1)
        migrated = load_store(self.store)["tokens"][0]
        self.assertEqual(migrated["expires_at"] - migrated["issued_at"], 3600)
        self.assertEqual(migrated["sha256"], sha256(self.token.encode()).hexdigest())
        self.assertEqual(authenticate_token(self.store, self.token, self.profile), self.token_id)
        with self.assertRaises(CredentialsError):
            migrate_store(self.store)
        with patch("vulnfolio.ingest_credentials.time.time",
                   return_value=migrated["expires_at"]):
            self.assertIsNone(authenticate_token(self.store, self.token, self.profile))

    def test_ttl_limits_and_invalid_store_fail_closed(self):
        for ttl in (0, 721, -1, True):
            with self.subTest(ttl=ttl):
                with self.assertRaises(CredentialsError):
                    issue_token(self.store, self.profile, self.root / "next.token", ttl_hours=ttl)
        self.assertFalse((self.root / "next.token").exists())
        variants = [
            {"expires_at": 0},
            {"issued_at": True},
            {"expires_at": "never"},
            {"expires_at": 99999999999999},
            {"profile_id": "another-profile"},
        ]
        for mutation in variants:
            with self.subTest(mutation=mutation):
                doc = load_store(self.store)
                doc["tokens"][0].update(mutation)
                self.store.write_text(json.dumps(doc))
                with self.assertRaises(CredentialsError):
                    load_store(self.store)
                with self.client() as client:
                    response = client.post(self.url, json=self.envelope, headers=self.headers)
                    self.assertEqual(response.status_code, 503)
                # Restore the valid original for the next case.
                original = issue = {
                    "schema_version": 2,
                    "tokens": [{
                        "id": self.token_id,
                        "profile_id": self.profile,
                        "sha256": sha256(self.token.encode()).hexdigest(),
                        "issued_at": 1_750_000_000,
                        "expires_at": 1_750_000_000 + 3600,
                    }],
                }
                self.store.write_text(json.dumps(original))
        # The restored token is intentionally historical and should no longer authorize.
        self.assertFalse(authorized(self.store, self.token, self.profile))

    def test_bounded_peer_and_per_token_limits(self):
        now = [100.0]
        limiter = IngestRateLimiter(
            peer_limit=3, token_limit=1, window_seconds=60,
            clock=lambda: now[0], max_keys=10,
        )
        with self.client(limiter) as client:
            first = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(first.status_code, 201)
            second = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(second.status_code, 429)  # token limit
            self.assertEqual(second.headers.get("retry-after"), "60")
            third = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(third.status_code, 429)
            fourth = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(fourth.status_code, 429)  # peer limit
            fifth = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(fifth.status_code, 429)
            self.assertEqual(fifth.headers.get("cache-control"), "no-store")
            # Only first rejection for each bucket is journaled.
            events = recent_audit(AssetRepository(self.db))
            self.assertEqual([e["outcome"] for e in events].count("rate_limited"), 2)
            now[0] = 161.0
            result = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(result.status_code, 201)
            self.assertTrue(result.json()["duplicate"])

    def test_denied_attempts_and_audit_journal_contain_no_secrets(self):
        with self.client() as client:
            self.assertEqual(client.post(self.url, json=self.envelope).status_code, 401)
            self.assertEqual(client.post(self.url, json=self.envelope,
                             headers=self.headers).status_code, 201)
            self.assertEqual(client.post(self.url, json=self.envelope,
                             headers=self.headers).status_code, 201)
            self.assertEqual(client.post(self.url, json=dict(self.envelope, schema_version="wrong"),
                             headers=self.headers).status_code, 422)
            self.assertEqual(client.get("/api/v1/ingest/audit").status_code, 404)
            self.assertEqual(client.get("/docs").status_code, 404)
        events = recent_audit(self.repo, 20)
        self.assertEqual([event["outcome"] for event in events],
                         ["invalid_payload", "duplicate", "imported", "auth_denied"])
        self.assertEqual(sum(e["assets_seen"] is not None for e in events), 2)
        for entry in events:
            self.assertEqual(set(entry), {
                "id", "recorded_at", "outcome", "http_status",
                "profile_id", "token_id", "assets_seen",
            })
        raw = json.dumps(events)
        self.assertNotIn(self.token, raw)
        self.assertNotIn("ansible_password", raw)
        self.assertNotIn("203.0.113.77", raw)
        self.assertIn(self.token_id, raw)
        self.assertEqual(len(InventoryImporter(self.repo).list_imports(self.profile)), 1)

    def test_audit_failure_returns_503_without_lying_about_commit(self):
        with self.client() as client:
            with patch("vulnfolio.ingest_server.record_audit", side_effect=OSError("disk failure")):
                response = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(len(InventoryImporter(self.repo).list_imports(self.profile)), 1)
            replay = client.post(self.url, json=self.envelope, headers=self.headers)
            self.assertEqual(replay.status_code, 201)
            self.assertTrue(replay.json()["duplicate"])

    def test_rate_limiter_bounded_keys_and_reset(self):
        time_value = [0.0]
        limiter = IngestRateLimiter(peer_limit=1, max_keys=2, window_seconds=10,
                                   clock=lambda: time_value[0])
        self.assertEqual(limiter.check_peer("one"), (0, False))
        self.assertEqual(limiter.check_peer("one"), (10, True))
        self.assertEqual(limiter.check_peer("one"), (10, False))
        self.assertEqual(limiter.check_peer("two"), (0, False))
        self.assertEqual(limiter.check_peer("three"), (10, False))  # bounded, fail closed
        time_value[0] = 11.0
        self.assertEqual(limiter.check_peer("three"), (0, False))
        self.assertLessEqual(len(limiter._buckets), 2)

    def test_audit_explicit_retention(self):
        with self.client() as client:
            self.assertEqual(client.post(self.url, json=self.envelope,
                                         headers=self.headers).status_code, 201)
        self.assertEqual(len(recent_audit(self.repo)), 1)
        self.assertEqual(prune_audit(self.repo, 30), 0)
        with self.assertRaises(ValueError):
            prune_audit(self.repo, 0)
        with self.assertRaises(ValueError):
            recent_audit(self.repo, 501)


if __name__ == "__main__":
    unittest.main()
