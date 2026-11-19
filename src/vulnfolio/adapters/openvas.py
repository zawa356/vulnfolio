"""Offline Greenbone GMP XML report importer (findings, not package inventory).

Import of *saved XML reports* only. Running a network/credentialed scan is out
of scope. Each scan result is a scanner claim, not independent confirmation.
"""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from vulnfolio.contracts import envelope, finding, InputError

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class OpenVASAdapter:
    name = "openvas"
    capabilities = frozenset({"vulnerability_findings", "network_scan_results"})

    def normalize(self, data: Any, profile_id: str) -> dict[str, Any]:
        if not isinstance(data, (str, bytes)):
            raise InputError("openvas expects a GMP XML report")
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise InputError("XML DTD and entities are not accepted")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise InputError("invalid GMP XML report") from exc
        findings: list[dict[str, Any]] = []
        hosts: set[str] = set()
        for result in root.findall(".//results/result"):
            host = (result.findtext("host") or "").strip()
            if not host:
                continue
            hosts.add(host)
            nvt = result.find("nvt")
            oid = nvt.get("oid") if nvt is not None else None
            cve_text = nvt.findtext("cve") if nvt is not None else None
            severity = (result.findtext("severity") or "").strip() or None
            ids = sorted(set(m.upper() for m in _CVE.findall(cve_text or "")))
            if not ids:
                ids = [None]  # Preserve non-CVE NVT as a finding; never invent a CVE.
            for cve in ids:
                findings.append(finding(
                    asset_id=host, driver=self.name, vulnerability_id=cve,
                    scanner_rule_id=oid, severity=severity, evidence="GMP result",
                ))
        observations = [{
            "asset_id": host,
            "os": {"family": None, "distribution": None, "version": None, "build": None},
            "packages": [], "patches": [], "inventory_scope": "host_observed",
            "source": self.name,
        } for host in sorted(hosts)]
        return envelope(
            driver=self.name, profile_id=profile_id, capabilities=self.capabilities,
            observations=observations, findings=findings, errors=[],
        )
