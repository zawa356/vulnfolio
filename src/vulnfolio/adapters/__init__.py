"""Built-in offline ingestion adapters (no target scanning)."""
from __future__ import annotations

from typing import Any

from vulnfolio.contracts import Adapter, InputError
from vulnfolio.adapters.ansible import AnsibleAdapter
from vulnfolio.adapters.vuls import VulsAdapter
from vulnfolio.adapters.openvas import OpenVASAdapter

REGISTRY: dict[str, Adapter] = {
    "ansible": AnsibleAdapter(),
    "vuls": VulsAdapter(),
    "openvas": OpenVASAdapter(),
}


def get_adapter(name: str) -> Adapter:
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise InputError(f"unsupported adapter: {name}") from exc
