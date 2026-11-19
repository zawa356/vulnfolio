"""M0: offline, repeatable tests. Never contacts CIRCL in CI."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import httpx
from fastapi.testclient import TestClient

from vulnfolio.vulnerabilities import from_cve_record, SourceFormatError, validate_cve_id
from vulnfolio.vulnerability_source import VulnerabilityLookupSource, SourceUnavailable
from vulnfolio.vulnerability_storage import VulnerabilityRepository
from vulnfolio.vulnerability_sync import sync_ids
from vulnfolio.vulnerability_api import create_app

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "cve_record.json").read_text())
ID = "CVE-2099-12345"


class CVENormalizationTests(unittest.TestCase):
    def test_normalizes_cve5_record(self) -> None:
        record = from_cve_record(FIXTURE, ID, "https://vulnerability.circl.lu/api/vulnerability/" + ID)
        self.assertEqual(record.id, ID)
        self.assertEqual(record.title, "Example synthetic vulnerability")
        self.assertIn("Synthetic record", record.description)
        self.assertEqual(record.cvss_score, 8.1)
        self.assertEqual(record.cvss_severity, "HIGH")
        self.assertEqual(len(record.references), 1)
        self.assertEqual(record.published_at, "2099-01-02T03:04:05Z")

    def test_refuses_mismatched_id_and_untrusted_data_shape(self) -> None:
        with self.assertRaises(SourceFormatError):
            from_cve_record(FIXTURE, "CVE-2099-54321", "https://example.invalid")
        with self.assertRaises(SourceFormatError):
            from_cve_record({"dataType": "HTML"}, ID, "https://example.invalid")

    def test_id_validation_rejects_url_and_sql_punctuation(self) -> None:
        for item in ("CVE-2024-12/other", "https://example.invalid", "CVE-2024-3094' OR 1=1", ""):
            with self.subTest(item=item), self.assertRaises(ValueError):
                validate_cve_id(item)
        self.assertEqual(validate_cve_id(" cve-2024-3094 "), "CVE-2024-3094")


class SourceAdapterTests(unittest.TestCase):
    def test_live_shape_with_mock_transport_and_identifying_user_agent(self) -> None:
        seen = []
        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(200, json=FIXTURE)
        source = VulnerabilityLookupSource(transport=httpx.MockTransport(handler))
        record, raw = source.fetch(ID.lower())
        self.assertEqual(record.id, ID)
        self.assertEqual(raw["dataType"], "CVE_RECORD")
        self.assertEqual(seen[0].url.path, "/api/vulnerability/" + ID)
        self.assertIn("vulnfolio", seen[0].headers["User-Agent"])
        self.assertEqual(seen[0].headers["Accept"], "application/json")

    def test_429_does_not_retry_automatically(self) -> None:
        called = []
        def handler(req):
            called.append(1)
            return httpx.Response(429, headers={"Retry-After": "60"})
        source = VulnerabilityLookupSource(transport=httpx.MockTransport(handler))
        with self.assertRaisesRegex(SourceUnavailable, "429"):
            source.fetch(ID)
        self.assertEqual(len(called), 1)

    def test_empty_response_refused(self) -> None:
        source = VulnerabilityLookupSource(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={})))
        with self.assertRaises(SourceUnavailable):
            source.fetch(ID)

    def test_rejects_insecure_non_loopback_base_url(self) -> None:
        with self.assertRaises(ValueError):
            VulnerabilityLookupSource("http://example.com")


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.db_path = Path(self.directory.name) / "vulnfolio.db"
        self.repo = VulnerabilityRepository(self.db_path)
        self.record = from_cve_record(FIXTURE, ID, "https://example.invalid/api/vulnerability/" + ID)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_upsert_preserves_first_seen_and_count(self) -> None:
        self.repo.upsert(self.record, FIXTURE)
        first = self.repo.get(ID)["first_fetched_at"]
        self.repo.upsert(self.record, FIXTURE)
        self.assertEqual(self.repo.list()["metadata"]["count"], 1)
        self.assertEqual(self.repo.get(ID)["first_fetched_at"], first)
        self.assertEqual(self.repo.raw(ID)["cveMetadata"]["cveId"], ID)
        self.assertNotIn("raw_json", self.repo.get(ID))
        self.assertEqual(self.repo.health()["status"], "ready")

    def test_failure_preserves_existing_data_and_reports_degraded(self) -> None:
        self.repo.upsert(self.record, FIXTURE)
        self.repo.mark_failure("vulnerability-lookup", "Upstream returned HTTP 503")
        self.assertEqual(self.repo.get(ID)["id"], ID)
        self.assertEqual(self.repo.health()["status"], "degraded")
        self.assertIn("503", self.repo.health()["upstream"]["last_error"])
        self.repo.upsert(self.record, FIXTURE)
        self.assertEqual(self.repo.health()["status"], "ready")
        self.assertIsNone(self.repo.health()["upstream"]["last_error"])

    def test_search_and_pagination(self) -> None:
        self.repo.upsert(self.record, FIXTURE)
        self.assertEqual(self.repo.list("2099")["metadata"]["count"], 1)
        self.assertEqual(self.repo.list("unrelated")["data"], [])
        self.assertEqual(self.repo.list("%")["metadata"]["count"], 0)
        self.assertEqual(self.repo.list(page=2, per_page=1)["data"], [])

    def test_local_api_reads_db_and_serves_tabler_html(self) -> None:
        self.repo.upsert(self.record, FIXTURE)
        app = create_app(self.db_path)
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/v1/health").json()["vulnerability_count"], 1)
            listed = client.get("/api/v1/vulnerabilities?q=synthetic").json()
            self.assertEqual(listed["metadata"]["count"], 1)
            detail = client.get("/api/v1/vulnerabilities/" + ID)
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json()["references"], ["https://example.invalid/security/CVE-2099-12345"])
            self.assertEqual(client.get("/api/v1/vulnerabilities/CVE-2099-9999").status_code, 404)
            self.assertEqual(client.get("/api/v1/vulnerabilities/garbage").status_code, 422)
            self.assertEqual(client.get("/api/v1/vulnerabilities?page=0").status_code, 422)
            self.assertEqual(client.get("/api/v1/vulnerabilities?per_page=1000").status_code, 422)
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn("@tabler/core@1.7.5", page.text)
            self.assertIn("Vulnerabilities", page.text)
            js = client.get("/static/app.js")
            self.assertEqual(js.status_code, 200)
            self.assertIn("textContent", js.text)

    def test_failed_cli_sync_stops_after_rate_limit(self) -> None:
        called = []
        def handler(req):
            called.append(1)
            return httpx.Response(429)
        source = VulnerabilityLookupSource(transport=httpx.MockTransport(handler))
        success, failed = sync_ids([ID, "CVE-2099-00002"], self.repo, source)
        self.assertEqual((success, failed), (0, 1))
        self.assertEqual(len(called), 1)
        self.assertEqual(self.repo.health()["status"], "degraded")


if __name__ == "__main__":
    unittest.main()
