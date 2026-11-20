"""Small, versioned canonical ingestion contract (not a vulnerability verdict).

The input adapters are pure data converters. They MUST NOT execute remote scans
or treat a reported CVE as independently confirmed.
"""
from __future__ import annotations

from typing import Any, Mapping, Protocol

SCHEMA_VERSION = "0.1.0"


class InputError(ValueError):
    """Invalid or unsupported source payload."""


class Adapter(Protocol):
    name: str
    capabilities: frozenset[str]

    def normalize(self, data: Any, profile_id: str) -> dict[str, Any]:
        """Convert a source result to a canonical envelope without scanning."""


def require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{context}: expected JSON object")
    return value


def to_string(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def canonical_package(raw: Mapping[str, Any]) -> dict[str, str | None]:
    """Keep RPM epoch/release/arch, not only a package's display version."""
    return {
        "name": to_string(raw.get("name")),
        "version": to_string(raw.get("version")),
        "release": to_string(raw.get("release")),
        "epoch": to_string(raw.get("epoch")),
        "arch": to_string(raw.get("arch")),
        "manager": to_string(raw.get("source") or raw.get("manager")),
    }


def envelope(
    *,
    driver: str,
    profile_id: str,
    capabilities: frozenset[str],
    observations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    errors: list[dict[str, str]],
    observed_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise InputError("profile_id is required")
    if errors:
        status = "partial_success" if observations or findings else "failed"
    else:
        status = "success" if observations or findings else "empty"
    return {
        "schema_version": SCHEMA_VERSION,
        "profile_id": profile_id,
        "collector": {"driver": driver, "capabilities": sorted(capabilities)},
        "observed_at": observed_at,
        "status": status,
        "observations": observations,
        "findings": findings,
        "errors": errors,
    }


def finding(
    *,
    asset_id: str,
    driver: str,
    vulnerability_id: str | None,
    scanner_rule_id: str | None = None,
    severity: str | None = None,
    evidence: str | None = None,
) -> dict[str, str | None]:
    """A scanner claim is evidence, not a confirmed vulnerability."""
    return {
        "asset_id": asset_id,
        "vulnerability_id": vulnerability_id,
        "scanner_rule_id": scanner_rule_id,
        "severity": severity,
        "evidence": evidence,
        "source": driver,
        "assertion": "scanner_reported",
    }


def upgrade_inventory_envelope_v02(
    report: Mapping[str, Any],
    asset_keys: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Opt-in v0.2 inventory output, conservatively marked partial/unknown.

    Do not equate Ansible 'package_facts returned data' with proven complete
    host coverage, and never label Windows Get-HotFix exhaustive. Explicit
    'complete' is only permitted after a caller has independently verified it.
    """
    from datetime import datetime, timezone
    import copy

    converted = copy.deepcopy(dict(report))
    if converted.get("schema_version") != "0.1.0":
        raise InputError("Only v0.1 envelopes may be upgraded to v0.2")
    if converted.get("findings"):
        raise InputError("This inventory upgrader does not handle vulnerability findings")
    converted["schema_version"] = "0.2.0"
    converted["observed_at"] = converted.get("observed_at") or (
        datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    mapping = dict(asset_keys or {})
    seen_names: set[str] = set()
    for raw in converted.get("observations", []):
        name = raw["asset_id"]
        seen_names.add(name)
        packages, patches = raw["packages"], raw["patches"]
        raw["coverage"] = {
            "packages": "partial" if packages else "unknown",
            "patches": "partial" if patches else "unknown",
        }
        if name in mapping:
            raw["asset_key"] = mapping[name]
    if set(mapping) - seen_names:
        raise InputError("Asset-key map refers to hosts absent from the collected observations")
    return converted
