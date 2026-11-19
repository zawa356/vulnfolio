"""Offline normalizer CLI. No network, remote access or scan side effects."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnfolio.adapters import get_adapter
from vulnfolio.contracts import InputError

MAX_INPUT_BYTES = 10 * 1024 * 1024


def convert(driver: str, profile_id: str, raw: bytes) -> dict:
    adapter = get_adapter(driver)
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("input file exceeds 10 MiB PoC limit")
    if driver == "openvas":
        payload = raw
    else:
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise InputError("invalid JSON input") from exc
    return adapter.normalize(payload, profile_id)


def main() -> int:
    parser = argparse.ArgumentParser(description="vulnfolio Phase 0 offline importer")
    parser.add_argument("--driver", choices=("ansible", "vuls", "openvas"), required=True)
    parser.add_argument("--profile", required=True, help="target profile ID (never auto-detected)")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    try:
        report = convert(args.driver, args.profile, args.input.read_bytes())
    except (InputError, OSError) as exc:
        parser.error(str(exc))
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
