"""Synthetic fixtures prove one shared contract for three scanner inputs."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from vulnfolio.adapters import get_adapter
from vulnfolio.cli import convert
from vulnfolio.contracts import InputError, SCHEMA_VERSION

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class AdapterContractTests(unittest.TestCase):
    def load(self, driver: str, name: str) -> dict:
        return convert(driver, "demo-profile", (FIXTURES / name).read_bytes())

    def test_ansible_inventory_and_partial_failure(self) -> None:
        data = self.load("ansible", "ansible.json")
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["status"], "partial_success")
        self.assertEqual(data["collector"]["driver"], "ansible")
        self.assertEqual(len(data["observations"]), 2)
        self.assertEqual(len(data["findings"]), 0)
        self.assertEqual(data["errors"][0]["asset_id"], "offline-demo")
        rhel = next(a for a in data["observations"] if a["asset_id"] == "rhel-demo")
        self.assertEqual(rhel["packages"][0]["epoch"], "1")
        self.assertEqual(rhel["packages"][0]["release"], "27.el9_4")
        self.assertEqual(rhel["packages"][0]["arch"], "x86_64")
        windows = next(a for a in data["observations"] if a["asset_id"] == "win-demo")
        self.assertEqual(windows["patches"], ["KB5000000"])

    def test_vuls_reports_observation_and_finding_separately(self) -> None:
        data = self.load("vuls", "vuls.json")
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["observations"][0]["asset_id"], "rhel-demo")
        self.assertEqual(data["findings"][0]["vulnerability_id"], "CVE-2099-0001")
        self.assertEqual(data["findings"][0]["assertion"], "scanner_reported")

    def test_openvas_keeps_non_cve_nvt_and_multiple_cves(self) -> None:
        data = self.load("openvas", "openvas.xml")
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["observations"]), 2)
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual({x["vulnerability_id"] for x in data["findings"]},
                         {"CVE-2099-0001", "CVE-2099-0002", None})
        self.assertTrue(all(x["scanner_rule_id"] for x in data["findings"]))
        self.assertEqual(data["observations"][0]["inventory_scope"], "host_observed")

    def test_shared_envelope_keys(self) -> None:
        exports = [
            self.load("ansible", "ansible.json"),
            self.load("vuls", "vuls.json"),
            self.load("openvas", "openvas.xml"),
        ]
        self.assertTrue(all(set(x) == set(exports[0]) for x in exports))
        self.assertTrue(all(x["profile_id"] == "demo-profile" for x in exports))

    def test_unknown_adapter_rejected(self) -> None:
        with self.assertRaises(InputError):
            get_adapter("untrusted")

    def test_profile_is_explicit_and_required(self) -> None:
        with self.assertRaises(InputError):
            convert("vuls", "", (FIXTURES / "vuls.json").read_bytes())

    def test_invalid_payload_rejected(self) -> None:
        with self.assertRaises(InputError):
            convert("ansible", "demo-profile", b"not json")
        with self.assertRaises(InputError):
            convert("openvas", "demo-profile", b"<bad")

    def test_xml_doctype_rejected(self) -> None:
        with self.assertRaises(InputError):
            convert("openvas", "demo-profile", b'<!DOCTYPE r><r/>')

    def test_malicious_vulnerability_inference_not_in_ansible(self) -> None:
        """Inventory-only input must not be silently classified as confirmed CVE."""
        data = self.load("ansible", "ansible.json")
        self.assertFalse(data["findings"])

    def test_json_output_serializable(self) -> None:
        data = self.load("openvas", "openvas.xml")
        self.assertIsInstance(json.loads(json.dumps(data))["observations"], list)


if __name__ == "__main__":
    unittest.main()
