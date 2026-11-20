"""The copy/paste offline demo must work on a new checkout without remote data."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from vulnfolio.asset_storage import AssetRepository
from vulnfolio.inventory_import import InventoryImporter

ROOT = Path(__file__).resolve().parent.parent


class OfflineDemoTests(unittest.TestCase):
    def test_user_demo_creates_synthetic_inventory_and_refuses_overwrite(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "synthetic.sqlite"
            command = [sys.executable, str(ROOT / "scripts" / "m1d_demo.py"),
                       "--db", str(db)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("SYNTHETIC DATA ONLY", first.stdout)
            self.assertTrue(db.is_file())
            repo = AssetRepository(db)
            profiles = repo.list_profiles()
            self.assertEqual(len(profiles), 1)
            assets = repo.list_assets(profiles[0]["id"])
            self.assertEqual({a["name"] for a in assets},
                             {"lab-linux", "lab-windows"})
            linux = next(a for a in assets if a["name"] == "lab-linux")
            win = next(a for a in assets if a["name"] == "lab-windows")
            self.assertEqual({s["collector"] for s in
                              InventoryImporter(repo).source_snapshots(linux["id"])},
                             {"ansible", "vuls"})
            self.assertEqual(InventoryImporter(repo).asset_snapshot(win["id"])["os_build"],
                             "20348")
            self.assertEqual(repo.candidates(profiles[0]["id"])["data"][0]
                             ["assessment"]["status"], "investigating")
            second = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(len(AssetRepository(db).list_profiles()), 1)


if __name__ == "__main__":
    unittest.main()
