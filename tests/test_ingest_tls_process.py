"""Real local TLS process E2E; all data and certificates are synthetic."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest

import httpx

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.asset_storage import AssetRepository
from vulnfolio.ingest_credentials import issue_token, read_token
from vulnfolio.ingest_upload import UploadError, send
from vulnfolio.inventory_import import InventoryImporter


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is needed for local TLS acceptance")
class HTTPSProcessTests(unittest.TestCase):
    def test_cryptographically_verified_https_upload_from_cli_to_live_uvicorn(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "localhost.crt"
            key = root / "localhost.key"
            result = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
            ], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, "Local OpenSSL certificate creation failed")
            db = root / "inventory.sqlite"
            repo = AssetRepository(db)
            profile = repo.create_profile("TLS synthetic test")["id"]
            auth_store = root / "auth" / "tokens.json"
            bearer_file = root / "auth" / "client.token"
            issue_token(auth_store, profile, bearer_file)
            raw = json.loads((Path(__file__).parent / "fixtures" / "ansible.json").read_text())
            envelope = AnsibleAdapter().normalize(raw, profile)
            source = root / "collected.json"
            source.write_text(json.dumps(envelope), encoding="utf-8")
            port = free_port()
            origin = f"https://127.0.0.1:{port}"
            env = dict(os.environ, VULNFOLIO_DB=str(db),
                       VULNFOLIO_INGEST_TOKENS_FILE=str(auth_store))
            server = subprocess.Popen([
                sys.executable, "-m", "uvicorn", "vulnfolio.ingest_server:app",
                "--host", "127.0.0.1", "--port", str(port),
                "--ssl-keyfile", str(key), "--ssl-certfile", str(cert),
                "--no-proxy-headers", "--log-level", "error",
            ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with httpx.Client(verify=str(cert), trust_env=False, timeout=1) as client:
                    for _ in range(80):
                        self.assertIsNone(server.poll(), "HTTPS server exited before readiness")
                        try:
                            if client.get(origin + "/api/v1/health").status_code == 404:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(0.1)
                    else:
                        self.fail("Local Uvicorn TLS server never became ready")

                # The actual TCP/TLS listener must NOT expose administrative routes,
                # even to a local caller. Probe using the TLS process itself.
                with httpx.Client(verify=str(cert), trust_env=False, timeout=3) as client:
                    for path in ("/", "/api/v1/health", "/api/v1/vulnerabilities",
                                 "/api/v1/profiles", "/environment", "/docs",
                                 "/openapi.json", "/static/app.js"):
                        self.assertEqual(client.get(origin + path).status_code, 404, path)
                # The normal uploader CLI (not TestClient) performs a verified
                # HTTP round-trip and should write a single batch to SQLite.
                cmd = [
                    sys.executable, "-m", "vulnfolio.ingest_upload",
                    "--base-url", origin,
                    "--profile", profile, "--input", str(source),
                    "--token-file", str(bearer_file), "--ca-file", str(cert),
                    "--attempts", "1",
                ]
                first = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertIn("duplicate=false", first.stdout)
                second = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertIn("duplicate=true", second.stdout)
                self.assertEqual(len(InventoryImporter(AssetRepository(db)).list_imports(profile)), 1)
                self.assertEqual(len(AssetRepository(db).list_assets(profile)), 2)

                with self.assertRaises(UploadError):
                    # Cert is self-signed: system default trust must REJECT it.
                    send(origin, profile, source.read_bytes(), read_token(bearer_file),
                         attempts=1)
                bad = subprocess.run([
                    *cmd[:-4], "--attempts", "1"
                ], capture_output=True, text=True, timeout=20)
                self.assertNotEqual(bad.returncode, 0, "CLI without CA must reject self-signed TLS")
                self.assertNotIn(read_token(bearer_file), first.stdout + first.stderr +
                                 bad.stdout + bad.stderr)
            finally:
                server.terminate()
                try:
                    server.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
