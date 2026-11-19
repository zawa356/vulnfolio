"""Normalize a curated Ansible hostvars/package_facts export.

This is deliberately a defined interchange input, not an ansible-runner plugin.
Accepted shapes:
  {"hosts": {"host1": {"ansible_facts": {"packages": {...}}}}}
  {"_meta": {"hostvars": {"host1": {"ansible_facts": {...}}}}}
"""
from __future__ import annotations

from typing import Any

from vulnfolio.contracts import canonical_package, envelope, InputError, require_mapping, to_string


class AnsibleAdapter:
    name = "ansible"
    capabilities = frozenset({"asset_inventory", "installed_packages", "windows_kb"})

    def normalize(self, data: Any, profile_id: str) -> dict[str, Any]:
        root = require_mapping(data, "ansible result")
        hosts = root.get("hosts")
        if hosts is None:
            hosts = require_mapping(root.get("_meta", {}), "_meta").get("hostvars")
        hosts = require_mapping(hosts, "hosts/hostvars")
        observations: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for host, raw_host in hosts.items():
            entry = require_mapping(raw_host, f"host {host}")
            if entry.get("error") or entry.get("unreachable"):
                errors.append({"asset_id": str(host), "reason": str(entry.get("error") or "unreachable")})
                continue
            facts = require_mapping(entry.get("ansible_facts", entry), f"facts for {host}")
            pkg_index = facts.get("packages", facts.get("ansible_facts_packages", {}))
            pkg_index = require_mapping(pkg_index, f"packages for {host}")
            packages = []
            for name, variants in pkg_index.items():
                if not isinstance(variants, list):
                    raise InputError(f"packages[{name}]: expected list")
                for variant in variants:
                    pkg = dict(require_mapping(variant, "package entry"))
                    pkg.setdefault("name", name)
                    packages.append(canonical_package(pkg))
            raw_kbs = facts.get("windows_kb", [])
            if not isinstance(raw_kbs, list):
                raise InputError("windows_kb: expected list")
            os_family = to_string(facts.get("os_family") or facts.get("ansible_os_family"))
            observations.append({
                "asset_id": str(host),
                "os": {
                    "family": os_family,
                    "distribution": to_string(facts.get("distribution") or facts.get("ansible_distribution")),
                    "version": to_string(facts.get("distribution_version") or facts.get("ansible_distribution_version")),
                    "build": to_string(facts.get("os_build")),
                },
                "packages": packages,
                "patches": [str(x) for x in raw_kbs],
                "inventory_scope": "reported",
                "source": self.name,
            })
        return envelope(
            driver=self.name, profile_id=profile_id, capabilities=self.capabilities,
            observations=observations, findings=[], errors=errors,
            observed_at=to_string(root.get("collected_at")),
        )
