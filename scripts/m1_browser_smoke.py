"""Full local M1 browser flow with synthetic data, no external API calls."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
from playwright.sync_api import sync_playwright

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.vulnerabilities import from_cve_record

ROOT = Path(__file__).resolve().parent.parent
CVE = "CVE-2099-23456"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    with TemporaryDirectory() as directory:
        db = Path(directory) / "m1-browser.db"
        raw = json.loads((ROOT / "tests" / "fixtures" / "cve_affected.json").read_text())
        repo = AssetRepository(db)
        repo.upsert(from_cve_record(raw, CVE, "https://example.invalid/" + CVE), raw)
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, VULNFOLIO_DB=str(db))
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "vulnfolio.vulnerability_api:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
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
                    raise RuntimeError("Uvicorn health timed out")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                errors = []
                page.on("pageerror", lambda err: errors.append(str(err)))
                page.route("https://cdn.jsdelivr.net/**", lambda route: route.abort())
                page.goto(base + "/environment", wait_until="domcontentloaded")
                page.locator("#profile-name").fill("Test Project")
                page.get_by_role("button", name="Add profile").click()
                page.locator("#profile-select option", has_text="Test Project").wait_for(state="attached", timeout=10000)

                page.locator("#asset-name").fill("rhel01")
                page.locator("#asset-os").fill("Linux")
                page.locator("#asset-version").fill("RHEL 9.4")
                page.get_by_role("button", name="Add asset to profile").click()
                page.locator("#asset-select option", has_text="rhel01").wait_for(state="attached", timeout=10000)

                page.locator("#product-vendor").fill("Acme")
                page.locator("#product-name").fill("fluxctl")
                page.locator("#product-version").fill("1.2.0")
                page.locator("#product-form button").click()
                page.locator("#candidate-rows").get_by_text(CVE).wait_for(state="attached", timeout=10000)
                assert page.locator("#candidate-rows tr").count() == 1
                assert "Exact version listed" in page.locator("#candidate-rows").inner_text()
                page.locator("#candidate-rows select").select_option("mitigated")
                page.locator("#candidate-rows input").fill("Test mitigation complete")
                page.locator("#candidate-rows button").click()
                page.get_by_text("No potential matches in this local dataset.", exact=False).wait_for(state="attached", timeout=10000)
                page.locator("#include-closed").check()
                page.locator("#candidate-rows").get_by_text(CVE).wait_for(state="attached", timeout=10000)
                assert page.locator("#candidate-rows select").input_value() == "mitigated"
                assert page.locator("#candidate-rows input").input_value() == "Test mitigation complete"

                page.reload(wait_until="domcontentloaded")
                page.locator("#profile-select option", has_text="Test Project").wait_for(state="attached", timeout=10000)
                page.locator("#include-closed").check()
                page.locator("#candidate-rows").get_by_text(CVE).wait_for(state="attached", timeout=10000)
                assert page.locator("#candidate-rows select").input_value() == "mitigated"

                # A second profile proves that importing a canonical collector
                # envelope creates assets and candidates without manual entry.
                page.locator("#profile-name").fill("Import Project")
                page.get_by_role("button", name="Add profile").click()
                page.locator("#profile-select option", has_text="Import Project").wait_for(
                    state="attached", timeout=10000
                )
                profile_id = page.locator("#profile-id").inner_text()
                assert len(profile_id) == 32
                incoming = json.loads((ROOT / "tests" / "fixtures" / "ansible.json").read_text())
                incoming["hosts"]["rhel-demo"]["ansible_facts"]["packages"]["fluxctl"] = [
                    {"name": "fluxctl", "version": "1.2.0", "source": "rpm"}
                ]
                envelope = AnsibleAdapter().normalize(incoming, profile_id)
                page.locator("#import-file").set_input_files({
                    "name": "collected.json",
                    "mimeType": "application/json",
                    "buffer": json.dumps(envelope).encode("utf-8"),
                })
                page.get_by_role("button", name="Import to selected profile").click()
                page.get_by_text("Imported: 2 assets", exact=False).wait_for(timeout=10000)
                page.locator("#candidate-rows").get_by_text(CVE).wait_for(timeout=10000)
                assert "vendor unverified" in page.locator("#candidate-rows").inner_text()
                assert "imported" in page.locator("#product-rows").inner_text().lower()
                assert not errors, errors
                browser.close()
            print("M1 BROWSER PASS: manual profile/asset/assessment + canonical JSON upload -> candidates")
        finally:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)


if __name__ == "__main__":
    main()
