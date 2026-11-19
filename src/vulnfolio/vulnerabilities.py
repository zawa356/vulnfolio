"""Canonical vulnerability record and CVE 5.x normalizer.

CVE Record data and scanner findings are separate concepts. This module does
not infer exploit activity or asset impact from CVSS scores or references.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Mapping
import re

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class SourceFormatError(ValueError):
    """Source returned an unknown or inconsistent record."""


def validate_cve_id(value: str) -> str:
    if not isinstance(value, str) or not CVE_ID.fullmatch(value.strip()):
        raise ValueError("Expected a CVE ID, e.g. CVE-2024-3094")
    return value.strip().upper()


def _datetime(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) <= 64 and value else None


def _clean_text(value: Any, length: int = 4096) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:length]


def _english_description(cna: Mapping[str, Any]) -> str:
    descriptions = cna.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    descriptions = [d for d in descriptions if isinstance(d, dict)]
    chosen = next((d for d in descriptions if str(d.get("lang", "")).lower().startswith("en")), None)
    chosen = chosen or (descriptions[0] if descriptions else {})
    return _clean_text(chosen.get("value"), 10000)


def _references(cna: Mapping[str, Any], adp: list[Any]) -> list[str]:
    links: list[str] = []
    for container in [cna, *adp]:
        if not isinstance(container, dict):
            continue
        refs = container.get("references")
        if not isinstance(refs, list):
            continue
        for ref in refs:
            url = ref.get("url") if isinstance(ref, dict) else None
            if isinstance(url, str) and url.startswith(("https://", "http://")) and len(url) <= 2048:
                if url not in links:
                    links.append(url)
            if len(links) >= 30:
                return links
    return links


def _cvss(cna: Mapping[str, Any], adp: list[Any]) -> tuple[float | None, str | None]:
    candidates = [cna, *[x for x in adp if isinstance(x, dict)]]
    for container in candidates:
        metrics = container.get("metrics")
        if not isinstance(metrics, list):
            continue
        for entry in metrics:
            if not isinstance(entry, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                obj = entry.get(key)
                if isinstance(obj, dict):
                    score = obj.get("baseScore")
                    if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
                        severity = obj.get("baseSeverity")
                        return float(score), _clean_text(severity, 32).upper() or None
    return None, None


@dataclass(frozen=True)
class Vulnerability:
    id: str
    title: str
    description: str
    published_at: str | None
    updated_at: str | None
    cvss_score: float | None
    cvss_severity: str | None
    references: list[str]
    provider: str = "vulnerability-lookup"
    source_url: str = ""

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


def from_cve_record(raw: Any, requested_id: str, source_url: str) -> Vulnerability:
    expected = validate_cve_id(requested_id)
    if not isinstance(raw, dict) or raw.get("dataType") != "CVE_RECORD":
        raise SourceFormatError("Expected a CVE Record (dataType=CVE_RECORD)")
    metadata = raw.get("cveMetadata")
    containers = raw.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise SourceFormatError("CVE Record is missing metadata or containers")
    actual = metadata.get("cveId")
    if not isinstance(actual, str) or actual.upper() != expected:
        raise SourceFormatError("CVE identifier mismatch in provider response")
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        raise SourceFormatError("CVE Record is missing the CNA container")
    adp = containers.get("adp")
    adp = adp if isinstance(adp, list) else []
    description = _english_description(cna)
    title = _clean_text(cna.get("title"), 300)
    if not title:
        title = (description[:140].rstrip() + "…") if len(description) > 140 else (description or expected)
    score, severity = _cvss(cna, adp)
    return Vulnerability(
        id=expected,
        title=title,
        description=description,
        published_at=_datetime(metadata.get("datePublished") or cna.get("datePublic")),
        updated_at=_datetime(metadata.get("dateUpdated")),
        cvss_score=score,
        cvss_severity=severity,
        references=_references(cna, adp),
        source_url=source_url,
    )
