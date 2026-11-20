"""Versioned JSON Schemas match importer behavior and collector CLI output.

jsonschema is test-only: no dependency is added to the running service.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator, FormatChecker

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.collector_export import hostname_file
from vulnfolio.contracts import upgrade_inventory_envelope_v02
from vulnfolio.inventory_import import validate_envelope

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures"
PROFILE = "a" * 32


class EnvelopeSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {}
        for version in ("0.1.0", "0.2.0"):
            filename = ROOT / "contracts" / f"collection-envelope-{version}.schema.json"
            doc = json.loads(filename.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(doc)
            cls.schemas[version] = Draft202012Validator(doc, format_checker=FormatChecker())

    def validate_version(self, report):
        version = report["schema_version"]
        self.schemas[version].validate(report)
        validate_envelope(report, report["profile_id"])

    def test_ansible_v01_and_explicit_v02_are_importer_compatible(self):
        fixture = json.loads((FIXTURE / "ansible.json").read_text())
        old = AnsibleAdapter().normalize(fixture, PROFILE)
        self.validate_version(old)
        upgraded = upgrade_inventory_envelope_v02(old, {
            "rhel-demo": "host:synthetic-stable-01",
        })
        self.validate_version(upgraded)
        self.assertEqual(upgraded["schema_version"], "0.2.0")
        rhel = next(o for o in upgraded["observations"] if o["asset_id"] == "rhel-demo")
        self.assertEqual(rhel["asset_key"], "host:synthetic-stable-01")
        self.assertEqual(rhel["coverage"]["packages"], "partial")
        self.assertEqual(rhel["coverage"]["patches"], "unknown")
        self.assertNotIn("coverage", old["observations"][0])  # no mutation

    def test_schema_rejects_false_unknown_and_bad_dates(self):
        old = AnsibleAdapter().normalize(
            json.loads((FIXTURE / "ansible.json").read_text()), PROFILE
        )
        upgraded = upgrade_inventory_envelope_v02(old)
        bad = deepcopy(upgraded)
        bad["observations"][0]["coverage"]["packages"] = "unknown"
        self.assertTrue(list(self.schemas["0.2.0"].iter_errors(bad)))
        bad = deepcopy(upgraded)
        bad["observed_at"] = "2026-11-20T00:00:00"  # timezone missing
        self.assertTrue(list(self.schemas["0.2.0"].iter_errors(bad)))
        bad = deepcopy(upgraded)
        bad["findings"] = [{"vulnerability_id": "CVE-2099-23456"}]
        self.assertTrue(list(self.schemas["0.2.0"].iter_errors(bad)))

    def test_explicit_complete_empty_is_valid_and_unknown_is_not_empty_proof(self):
        fixture = json.loads((FIXTURE / "ansible.json").read_text())
        report = upgrade_inventory_envelope_v02(AnsibleAdapter().normalize(fixture, PROFILE))
        for item in report["observations"]:
            item["packages"] = []
            item["patches"] = []
            item["coverage"] = {"packages": "complete", "patches": "complete"}
        self.validate_version(report)
        for item in report["observations"]:
            item["coverage"] = {"packages": "unknown", "patches": "unknown"}
        self.validate_version(report)

    def test_collector_cli_can_emit_v02_with_private_stable_key_map(self):
        with TemporaryDirectory() as dirname:
            root = Path(dirname)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            host = "rhel-demo"
            payload = json.loads((FIXTURE / "ansible.json").read_text())["hosts"][host]
            (artifacts / hostname_file(host)).write_text(
                json.dumps({"asset_id": host, "ansible_facts": payload["ansible_facts"]}),
                encoding="utf-8",
            )
            keyfile = root / "keys.json"
            keyfile.write_text(json.dumps({host: "machine:uuid-synthetic-123"}), encoding="utf-8")
            output = root / "result.json"
            cmd = [
                sys.executable, "-m", "vulnfolio.collector_export",
                "--artifacts", str(artifacts), "--expected-host", host,
                "--profile", PROFILE, "--output", str(output),
                "--schema-version", "0.2.0", "--asset-key-map", str(keyfile),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.validate_version(report)
            self.assertEqual(report["observations"][0]["asset_key"],
                             "machine:uuid-synthetic-123")
            self.assertEqual(report["observations"][0]["coverage"]["packages"], "partial")
            self.assertEqual(report["observations"][0]["coverage"]["patches"], "unknown")


if __name__ == "__main__":
    unittest.main()
