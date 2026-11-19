"""Conservative asset-to-CVE *candidate* matching.

Only structured CVE 5 'affected' entries can create a candidate. No substring
matches of the CVE prose, no speculative CPE mapping, no inferred patch status,
and NO version range evaluation. A candidate is not a vulnerability verdict.
"""
from __future__ import annotations

import json
from typing import Any, Mapping


def _key(raw: Any) -> str:
    return " ".join(str(raw or "").strip().casefold().split())


def _affected_entries(raw: Any):
    if not isinstance(raw, dict) or raw.get("dataType") != "CVE_RECORD":
        return
    containers = raw.get("containers")
    if not isinstance(containers, dict):
        return
    for name in ("cna", "adp"):
        group = containers.get(name)
        entries = [group] if isinstance(group, dict) else group if isinstance(group, list) else []
        for container in entries:
            if not isinstance(container, dict):
                continue
            affected = container.get("affected")
            if not isinstance(affected, list):
                continue
            for entry in affected:
                if isinstance(entry, dict):
                    yield name, entry


def _version_evidence(entry: Mapping[str, Any], version: str) -> tuple[str, str] | None:
    """Return None only if exact version was explicitly marked unaffected."""
    revisions = entry.get("versions")
    if not isinstance(revisions, list):
        return ("product_only", "version has not been evaluated")
    for revision in revisions:
        if not isinstance(revision, dict):
            continue
        if _key(revision.get("version")) != _key(version) or not version:
            continue
        state = _key(revision.get("status"))
        if state == "unaffected":
            return None
        if state == "affected":
            return ("exact_version_listed_affected", "this exact version is listed as affected by the source")
    return ("product_only", "version ranges, backports and fixes have not been evaluated")


def candidates_for_inventory(products: list[dict[str, Any]], cves: list[Any]) -> list[dict[str, Any]]:
    """Return one candidate per asset/CVE; retain the strongest observed basis."""
    inventory: dict[str, list[dict[str, Any]]] = {}
    for product in products:
        name = _key(product.get("name"))
        if name:
            inventory.setdefault(name, []).append(product)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for row in cves:
        cve_id, title, blob = row["id"], row["title"], row["raw_json"]
        try:
            raw = json.loads(blob)
        except (TypeError, ValueError):
            continue
        for origin, affected in _affected_entries(raw):
            product_name = _key(affected.get("product"))
            if not product_name or product_name in {"n/a", "unknown", "*"}:
                continue
            source_vendor = _key(affected.get("vendor"))
            for installed in inventory.get(product_name, []):
                asset_vendor = _key(installed.get("vendor"))
                # If both vendors are known and differ, avoid an unrelated match.
                if source_vendor and source_vendor not in {"n/a", "unknown", "*"} and asset_vendor and source_vendor != asset_vendor:
                    continue
                version_evidence = _version_evidence(affected, str(installed.get("version") or ""))
                if version_evidence is None:
                    continue
                basis, explanation = version_evidence
                vendor_verified = bool(asset_vendor and source_vendor == asset_vendor)
                item = {
                    "asset_id": installed["asset_id"],
                    "asset_name": installed["asset_name"],
                    "product_id": installed["id"],
                    "product_name": installed["name"],
                    "installed_version": installed.get("version", ""),
                    "cve_id": cve_id,
                    "cve_title": title,
                    "match_basis": basis,
                    "vendor_verified": vendor_verified,
                    "source_container": origin,
                    "evidence": f"CVE {origin}.affected product name matched exactly; {explanation}. "
                                + ("Vendor matched." if vendor_verified else "Vendor not verified.")
                                + " This is a candidate, not a confirmed affected asset.",
                }
                key = (installed["asset_id"], cve_id)
                prior = found.get(key)
                score = (basis == "exact_version_listed_affected", vendor_verified)
                if prior is None or score > (
                    prior["match_basis"] == "exact_version_listed_affected", prior["vendor_verified"]
                ):
                    found[key] = item
    return list(found.values())
