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
