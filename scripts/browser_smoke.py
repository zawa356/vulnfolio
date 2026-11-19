"""One-shot Chromium test of the real M0 HTML/JS against a local API.

The fixture is SYNTHETIC; no external vulnerability API is queried.
The Tabler CDN is blocked in this functional test to avoid reliance on its uptime.
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import socket
import subprocess
import sys
import time

import httpx
from playwright.sync_api import sync_playwright
from vulnfolio.vulnerability_storage import VulnerabilityRepository
from vulnfolio.vulnerabilities import from_cve_record

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "cve_record.json"
CVE = "CVE-2099-12345"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    with TemporaryDirectory() as directory:
        db = Path(directory) / "m0-browser.db"
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        repo = VulnerabilityRepository(db)
        record = from_cve_record(raw, CVE, "https://example.invalid/api/vulnerability/" + CVE)
        repo.upsert(record, raw)
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, VULNFOLIO_DB=str(db))
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "vulnfolio.vulnerability_api:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            with httpx.Client(timeout=2) as client:
                for _ in range(80):
                    if server.poll() is not None:
                        raise RuntimeError("Uvicorn exited early")
                    try:
                        if client.get(base + "/api/v1/health").status_code == 200:
                            break
                    except httpx.RequestError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Uvicorn did not become ready")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                errors = []
                page.on("pageerror", lambda err: errors.append(str(err)))
                # The UI must remain functional if the optional CDN cannot load.
                page.route("https://cdn.jsdelivr.net/**", lambda route: route.abort())
                page.goto(base, wait_until="domcontentloaded", timeout=20000)
                page.locator("#vulnerability-rows a", has_text=CVE).wait_for(timeout=10000)
                assert page.locator("#count").inner_text() == "1"
                page.locator("#q").fill("no-such-CVE-2099")
                page.locator("#q").press("Enter")
                page.get_by_text("No matching records.", exact=True).wait_for()
                page.locator("#q").fill(CVE)
                page.locator("#q").press("Enter")
                page.locator("#vulnerability-rows a", has_text=CVE).click()
                detail = page.locator("#detail")
                assert detail.is_visible()
                page.wait_for_function(
                    "() => document.getElementById('detail-description').textContent.includes('Synthetic record for tests only.')",
                    timeout=10000,
                )
                text = page.locator("#detail-description").inner_text()
                assert "Synthetic record for tests only." in text
                assert "<script>" in text, "escaped literal markup must remain plain text"
                assert page.locator("#detail-description script").count() == 0
                refs = page.locator("#detail-references a")
                assert refs.count() == 1
                assert refs.first.get_attribute("href") == "https://example.invalid/security/CVE-2099-12345"
                page.locator("#close-detail").click()
                assert not detail.is_visible()
                assert not errors, f"Unexpected JS runtime errors: {errors}"
                browser.close()
            print("BROWSER M0 PASS: real Chromium search -> detail -> escaped description -> references")
        finally:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)


if __name__ == "__main__":
    main()
