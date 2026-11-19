"""M1c Ansible collector orchestration and offline export.

Only named inventory groups are targeted. Ansible records sanitized OS/package
facts on the controller; the exporter builds the existing CollectionEnvelope.
Target authentication and Windows/Linux connections are delegated to Ansible.
No outbound upload, asset deletion, or remote patch operations are performed.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Any

from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.contracts import InputError, envelope
from vulnfolio.inventory_import import validate_envelope, ImportValidationError
from vulnfolio.vulnerability_storage import utcnow

PLAYBOOK = Path(__file__).resolve().parents[2] / "collector" / "ansible" / "collect.yml"
MAX_ARTIFACT_SIZE = 4 * 1024 * 1024
MAX_ENVELOPE_SIZE = 2 * 1024 * 1024
MAX_HOSTS = 200
FACT_KEYS = frozenset({
    "packages", "ansible_facts_packages", "os_family", "ansible_os_family",
    "distribution", "ansible_distribution",
    "distribution_version", "ansible_distribution_version",
    "os_build", "windows_kb",
})


class CollectorError(ValueError):
    """Bad inventory, output, or controller tool invocation."""


def hostname_file(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname or len(hostname) > 180:
        raise CollectorError("Invalid inventory hostname")
    return sha256(hostname.encode("utf-8")).hexdigest() + ".json"


def intended_hosts(inventory: dict[str, Any]) -> list[str]:
    """Expand only explicit vulnfolio_linux and vulnfolio_windows groups."""
    if not isinstance(inventory, dict):
        raise CollectorError("Ansible inventory is not a JSON object")

    def in_group(name: str, visited: set[str]) -> set[str]:
        if name in visited:
            return set()
        visited.add(name)
        item = inventory.get(name, {})
        if not isinstance(item, dict):
            raise CollectorError("Invalid inventory group")
        hosts = item.get("hosts") or []
        children = item.get("children") or []
        if not isinstance(hosts, list) or not isinstance(children, list):
            raise CollectorError("Invalid inventory hosts/children")
        result = set()
        for host in hosts:
            if not isinstance(host, str):
                raise CollectorError("Inventory hostname must be text")
            hostname_file(host)
            result.add(host)
        for child in children:
            if not isinstance(child, str):
                raise CollectorError("Inventory group child must be text")
            result |= in_group(child, visited)
        return result

    linux = in_group("vulnfolio_linux", set())
    windows = in_group("vulnfolio_windows", set())
    if linux & windows:
        raise CollectorError("Host cannot belong to Linux and Windows collection groups")
    selected = sorted(linux | windows)
    if not selected:
        raise CollectorError("No target hosts in vulnfolio_linux/vulnfolio_windows")
    if len(selected) > MAX_HOSTS:
        raise CollectorError(f"Too many target hosts (limit {MAX_HOSTS})")
    return selected


def normalize_artifacts(
    artifacts: Path, hosts: list[str], profile_id: str, failed_controller: bool = False
) -> dict[str, Any]:
    """Offline transformation suitable for CI; never opens an SSH/WinRM connection."""
    hosts = list(dict.fromkeys(hosts))
    if not hosts or len(hosts) > MAX_HOSTS:
        raise CollectorError("Expected 1 to 200 hostnames")
    converter = AnsibleAdapter()
    observations = []
    errors = []
    for hostname in hosts:
        artifact = artifacts / hostname_file(hostname)
        if not artifact.is_file():
            errors.append({"asset_id": hostname, "reason": "unreachable_or_collection_failed"})
            continue
        if artifact.stat().st_size > MAX_ARTIFACT_SIZE:
            errors.append({"asset_id": hostname, "reason": "artifact_too_large"})
            continue
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("asset_id") != hostname:
                raise CollectorError("Artifact identity mismatch")
            facts = payload.get("ansible_facts")
            if not isinstance(facts, dict):
                raise CollectorError("Missing facts")
            # Strip *all* unrelated facts, hostvars, and credential keys.
            stripped = {key: facts[key] for key in FACT_KEYS if key in facts}
            normalized = converter.normalize(
                {"hosts": {hostname: {"ansible_facts": stripped}}}, profile_id
            )
            observations.extend(normalized["observations"])
        except (OSError, UnicodeError, ValueError, InputError, TypeError):
            errors.append({"asset_id": hostname, "reason": "invalid_collection_artifact"})
    if failed_controller and len(errors) < 200:
        errors.append({"asset_id": "_collector", "reason": "ansible_playbook_failed"})
    return envelope(
        driver="ansible", profile_id=profile_id, capabilities=converter.capabilities,
        observations=observations, findings=[], errors=errors, observed_at=utcnow(),
    )


def _invoke(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"Ansible controller unavailable or timed out: {type(exc).__name__}") from exc


def read_inventory_hosts(path: Path) -> list[str]:
    """Ansible output includes secrets in hostvars: parse only group names and discard."""
    result = _invoke(["ansible-inventory", "-i", str(path), "--list"], timeout=60)
    if result.returncode:
        raise CollectorError("Unable to inspect Ansible inventory; check inventory/configuration")
    if len(result.stdout) > 10 * 1024 * 1024:
        raise CollectorError("Ansible inventory is unexpectedly large")
    try:
        inventory = json.loads(result.stdout)
    except ValueError as exc:
        raise CollectorError("Ansible inventory command returned invalid JSON") from exc
    return intended_hosts(inventory)


def save_report(output: Path, report: dict[str, Any]) -> None:
    try:
        validate_envelope(report, report["profile_id"])
    except (ImportValidationError, KeyError, TypeError) as exc:
        raise CollectorError("Generated envelope is not accepted by the current M1b importer") from exc
    data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_ENVELOPE_SIZE:
        raise CollectorError(
            "Collector JSON exceeds the M1b 2 MiB upload limit; use smaller inventory batches"
        )
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise CollectorError("Output already exists; choose a new private path") from exc
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only Ansible inventory to vulnfolio CollectionEnvelope")
    p.add_argument("--profile", required=True, help="existing Profile ID in My Environment")
    p.add_argument("--output", type=Path, required=True, help="new JSON path, mode 0600")
    p.add_argument("--inventory", type=Path, help="Ansible inventory with vulnfolio_linux/windows groups")
    p.add_argument("--artifacts", type=Path, help="OFFLINE mode: existing host JSON artifacts")
    p.add_argument("--expected-host", action="append", default=[],
                   help="OFFLINE mode: expected hostname (repeatable)")
    args = p.parse_args()
    if not args.profile.strip():
        p.error("--profile must not be empty")
    try:
        if args.artifacts:
            if not args.expected_host and not args.inventory:
                raise CollectorError("Offline --artifacts requires --expected-host or --inventory")
            if args.expected_host and args.inventory:
                raise CollectorError("Use either --expected-host or --inventory in offline mode")
            hosts = args.expected_host or read_inventory_hosts(args.inventory)
            report = normalize_artifacts(args.artifacts, hosts, args.profile)
            ansible_failed = False
        else:
            if not args.inventory or args.expected_host:
                raise CollectorError("Live mode requires --inventory (no --expected-host)")
            if not PLAYBOOK.is_file():
                raise CollectorError("Collector playbook missing; install from repository checkout")
            hosts = read_inventory_hosts(args.inventory)
            with TemporaryDirectory(prefix="vulnfolio-collect-") as directory:
                cmd = [
                    "ansible-playbook", "-i", str(args.inventory), str(PLAYBOOK),
                    "--extra-vars", json.dumps({"vf_collection_dir": directory}),
                ]
                # Do not persist inventory/host output to a log: it may contain
                # identifiers and, depending on Ansible config, secret values.
                try:
                    result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL, timeout=900, check=False)
                    ansible_failed = result.returncode != 0
                except (OSError, subprocess.TimeoutExpired):
                    ansible_failed = True
                report = normalize_artifacts(Path(directory), hosts, args.profile,
                                             failed_controller=ansible_failed)
        save_report(args.output, report)
    except (CollectorError, OSError) as exc:
        p.error(str(exc))
    print(f"Saved {args.output} — {len(report['observations'])} host observations, "
          f"{len(report['errors'])} collection errors; status={report['status']}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
