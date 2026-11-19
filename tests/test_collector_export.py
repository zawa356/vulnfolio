"""No-network collector contract tests: pure artifact normalization and safety."""
from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnfolio.collector_export import (
    CollectorError, hostname_file, intended_hosts, normalize_artifacts, save_report,
)
from vulnfolio.inventory_import import validate_envelope

PROFILE = "synthetic-profile"


def linux_facts(host: str = "linux-node") -> dict:
    return {
        "asset_id": host,
        "ansible_facts": {
            "ansible_os_family": "RedHat",
            "ansible_distribution": "RedHat",
            "ansible_distribution_version": "9.5",
            "packages": {
                "openssl": [
                    {
                        "name": "openssl", "version": "3.0.7", "release": "27.el9",
                        "epoch": "1", "arch": "x86_64", "source": "rpm"
                    }
                ]
            },
            "ansible_password": "MUST_NOT_LEAK",
            "ansible_env": {"SECRET_TOKEN": "MUST_NOT_LEAK"},
        },
        "private_field": "MUST_NOT_LEAK",
    }


def windows_facts(host: str = "windows-node") -> dict:
    return {
        "asset_id": host,
        "ansible_facts": {
            "ansible_os_family": "Windows",
            "ansible_distribution": "Microsoft Windows Server",
            "ansible_distribution_version": "10.0.20348",
            "os_build": "20348",
            "windows_kb": ["KB5000000"],
            "packages": {
                "Synthetic Tool": [{"name": "Synthetic Tool", "version": "1.2", "source": "windows_registry"}]
            },
        },
    }


def write_artifact(path: Path, host: str, payload: dict) -> None:
    (path / hostname_file(host)).write_text(json.dumps(payload), encoding="utf-8")


class InventorySelectionTests(unittest.TestCase):
    def test_select_only_two_explicit_groups_with_children(self):
        inventory = {
            "vulnfolio_linux": {"children": ["linux_group"]},
            "linux_group": {"hosts": ["linux-node"]},
            "vulnfolio_windows": {"hosts": ["windows-node"]},
            "all": {"hosts": ["unrelated-node"]},
            "_meta": {"hostvars": {"linux-node": {"ansible_password": "private"}}},
        }
        self.assertEqual(intended_hosts(inventory), ["linux-node", "windows-node"])

    def test_rejects_cross_group_target_and_missing_target(self):
        with self.assertRaises(CollectorError):
            intended_hosts({"vulnfolio_linux": {"hosts": ["same"]},
                            "vulnfolio_windows": {"hosts": ["same"]}})
        with self.assertRaises(CollectorError):
            intended_hosts({"all": {"hosts": ["not-in-collector-groups"]}})

    def test_hostnames_used_as_sha256_filenames(self):
        name = "../../unsafe/node"
        filename = hostname_file(name)
        self.assertTrue(filename.endswith(".json"))
        self.assertNotIn("/", filename)
        self.assertNotIn("..", filename)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_linux_windows_and_unreachable_host(self):
        write_artifact(self.path, "linux-node", linux_facts())
        write_artifact(self.path, "windows-node", windows_facts())
        report = normalize_artifacts(
            self.path, ["linux-node", "windows-node", "offline-node"], PROFILE
        )
        self.assertEqual(report["schema_version"], "0.1.0")
        self.assertEqual(report["collector"]["driver"], "ansible")
        self.assertEqual(report["status"], "partial_success")
        self.assertEqual(len(report["observations"]), 2)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["errors"], [{"asset_id": "offline-node",
                                             "reason": "unreachable_or_collection_failed"}])
        validate_envelope(report, PROFILE)  # Must be directly importable by M1b.
        hosts = {row["asset_id"]: row for row in report["observations"]}
        pkg = hosts["linux-node"]["packages"][0]
        self.assertEqual((pkg["epoch"], pkg["release"], pkg["arch"], pkg["manager"]),
                         ("1", "27.el9", "x86_64", "rpm"))
        self.assertEqual(hosts["windows-node"]["patches"], ["KB5000000"])
        self.assertEqual(hosts["windows-node"]["os"]["build"], "20348")
        self.assertEqual(hosts["windows-node"]["packages"][0]["manager"], "windows_registry")
        self.assertNotIn("MUST_NOT_LEAK", json.dumps(report))
        self.assertNotIn("ansible_password", json.dumps(report))

    def test_corrupt_and_wrong_identity_artifacts_become_host_errors(self):
        (self.path / hostname_file("broken")).write_bytes(b"bad json")
        write_artifact(self.path, "spoof", linux_facts("wrong-name"))
        report = normalize_artifacts(self.path, ["broken", "spoof"], PROFILE)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["errors"]), 2)
        self.assertEqual(report["observations"], [])

    def test_collection_is_failed_if_controller_exits_nonzero(self):
        write_artifact(self.path, "linux-node", linux_facts())
        report = normalize_artifacts(self.path, ["linux-node"], PROFILE,
                                     failed_controller=True)
        self.assertEqual(report["status"], "partial_success")
        self.assertTrue(any(e["asset_id"] == "_collector" for e in report["errors"]))

    def test_secure_exclusive_output_and_size_validation(self):
        write_artifact(self.path, "linux-node", linux_facts())
        report = normalize_artifacts(self.path, ["linux-node"], PROFILE)
        output = self.path / "private" / "inventory.json"
        save_report(output, report)
        self.assertEqual(json.loads(output.read_text())["observations"][0]["asset_id"],
                         "linux-node")
        if os.name == "posix":
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(CollectorError):
            save_report(output, report)

    def test_artifact_does_not_contain_unrelated_hostvars(self):
        payload = linux_facts()
        payload["ansible_facts"]["password"] = "MUST_NOT_LEAK"
        write_artifact(self.path, "linux-node", payload)
        report = normalize_artifacts(self.path, ["linux-node"], PROFILE)
        self.assertNotIn("MUST_NOT_LEAK", json.dumps(report))
        self.assertEqual(len(report["observations"]), 1)


if __name__ == "__main__":
    unittest.main()
