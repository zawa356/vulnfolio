"""Offline Vuls JSON report importer. Does not run a scan."""
from __future__ import annotations

from typing import Any

from vulnfolio.contracts import canonical_package, envelope, finding, InputError, require_mapping, to_string


class VulsAdapter:
    name = "vuls"
    capabilities = frozenset({"asset_inventory", "installed_packages", "vulnerability_findings"})

    def normalize(self, data: Any, profile_id: str) -> dict[str, Any]:
        servers = data if isinstance(data, list) else [data]
        if not servers:
            raise InputError("vuls report: no servers")
        observations: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        observed_at: str | None = None
        for raw in servers:
            server = require_mapping(raw, "vuls server")
            asset_id = to_string(server.get("serverName"))
            if not asset_id:
                raise InputError("vuls serverName is required")
            observed_at = observed_at or to_string(server.get("scannedAt"))
            pkg_data = require_mapping(server.get("packages", {}), "vuls packages")
            packages = []
            for name, pkg_raw in pkg_data.items():
                pkg = dict(require_mapping(pkg_raw, f"vuls package {name}"))
                pkg.setdefault("name", name)
                packages.append(canonical_package(pkg))
            windows_kb = server.get("windowsKB") or {}
            if not isinstance(windows_kb, dict):
                raise InputError("vuls windowsKB must be object")
            applied = windows_kb.get("applied") or []
            if not isinstance(applied, list):
                raise InputError("vuls applied KB list must be array")
            observations.append({
                "asset_id": asset_id,
                "os": {
                    "family": to_string(server.get("family")),
                    "distribution": to_string(server.get("family")),
                    "version": to_string(server.get("release")),
                    "build": None,
                },
                "packages": packages,
                "patches": [str(kb) for kb in applied],
                "inventory_scope": "reported",
                "source": self.name,
            })
            vulns = require_mapping(server.get("scannedCves", {}), "vuls scannedCves")
            for cve_id, raw_cve in vulns.items():
                record = require_mapping(raw_cve, f"scannedCves[{cve_id}]")
                vuln_id = to_string(record.get("cveID") or cve_id)
                findings.append(finding(
                    asset_id=asset_id, driver=self.name, vulnerability_id=vuln_id,
                    evidence="Vuls scannedCves", scanner_rule_id=None,
                ))
            for reason in server.get("errors", []) or []:
                errors.append({"asset_id": asset_id, "reason": str(reason)})
        return envelope(
            driver=self.name, profile_id=profile_id, capabilities=self.capabilities,
            observations=observations, findings=findings, errors=errors, observed_at=observed_at,
        )
