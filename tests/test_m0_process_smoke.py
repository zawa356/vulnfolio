"""M0 process-level smoke: CLI -> mock HTTP source -> SQLite -> uvicorn -> HTTP UI.

Runs without contacting any public service. The upstream API payload is a
synthetic CVE 5.1 record served from a local HTTP server. Tested in CI.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import json
import os
import socket
import subprocess
import sys
import time
import unittest

import httpx

FIXTURE = (Path(__file__).parent / "fixtures" / "cve_record.json").read_bytes()
ID = "CVE-2099-12345"


class LocalCVEHandler(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):
        type(self).calls += 1
        if self.path != "/api/vulnerability/" + ID:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(FIXTURE)))
        self.end_headers()
        self.wfile.write(FIXTURE)

    def log_message(self, format, *args):
        return


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ProcessSmokeTests(unittest.TestCase):
    def test_cli_to_sqlite_to_running_http_and_tabler(self):
        with TemporaryDirectory() as temp:
            db = str(Path(temp) / "app.db")
            upstream = ThreadingHTTPServer(("127.0.0.1", 0), LocalCVEHandler)
            LocalCVEHandler.calls = 0
            worker = Thread(target=upstream.serve_forever, daemon=True)
            worker.start()
            server = None
            try:
                address = "http://127.0.0.1:" + str(upstream.server_address[1])
                env = dict(os.environ)
                env["VULNFOLIO_DB"] = db
                command = [
                    sys.executable, "-m", "vulnfolio.vulnerability_sync",
                    "--id", ID, "--db", db, "--source-url", address,
                ]
                imported = subprocess.run(command, env=env, capture_output=True,
                                          text=True, timeout=15)
                self.assertEqual(imported.returncode, 0, imported.stderr + imported.stdout)
                self.assertIn(ID, imported.stdout)
                self.assertEqual(LocalCVEHandler.calls, 1)

                port = unused_port()
                base = f"http://127.0.0.1:{port}"
                server = subprocess.Popen([
                    sys.executable, "-m", "uvicorn", "vulnfolio.vulnerability_api:app",
                    "--host", "127.0.0.1", "--port", str(port),
                    "--log-level", "error",
                ], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                with httpx.Client(timeout=2) as client:
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline:
                        if server.poll() is not None:
                            self.fail("uvicorn exited before health check")
                        try:
                            response = client.get(base + "/api/v1/health")
                            if response.status_code == 200:
                                break
                        except httpx.RequestError:
                            pass
                        time.sleep(0.1)
                    else:
                        self.fail("uvicorn HTTP health timed out")
                    self.assertEqual(response.json()["vulnerability_count"], 1)
                    self.assertEqual(response.json()["status"], "ready")
                    data = client.get(base + "/api/v1/vulnerabilities").json()
                    self.assertEqual(data["metadata"]["count"], 1)
                    self.assertEqual(data["data"][0]["id"], ID)
                    detail = client.get(base + "/api/v1/vulnerabilities/" + ID).json()
                    self.assertEqual(detail["cvss_score"], 8.1)
                    self.assertEqual(client.get(base + "/").status_code, 200)
                    self.assertIn("@tabler/core@1.7.5", client.get(base + "/").text)
                    self.assertEqual(client.get(base + "/static/app.js").status_code, 200)
            finally:
                if server is not None:
                    server.terminate()
                    try:
                        server.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.communicate(timeout=5)
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    unittest.main()
