"""Deterministic normalizers for tool output."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from core.investigation.models import Evidence, ServiceObservation

_SERVICE = re.compile(
    r"^\s*(?P<port>\d{1,5})/(?P<protocol>[a-z0-9]+)\s+(?P<state>open(?:\|filtered)?|closed|filtered|unfiltered)\s+(?P<service>\S+)(?:\s+(?P<details>.*?))?\s*$",
    re.IGNORECASE,
)
_COMPLETE = re.compile(r"^Nmap done:", re.MULTILINE)
_VERSION = re.compile(r"(?<!\w)v?\d+(?:\.\d+)+(?:[\w.+~-]*)?")


@dataclass(frozen=True)
class NmapExtraction:
    evidence: Evidence
    services: list[ServiceObservation]


def _product_version(details: str) -> tuple[str | None, str | None]:
    details = details.strip()
    if not details:
        return None, None
    match = _VERSION.search(details)
    if match is None:
        return details, None
    return details[: match.start()].strip(" -") or None, match.group(0)


def extract_nmap(
    raw_output: str,
    *,
    asset_id: str,
    capability_id: str = "network.service.inventory",
    evidence_id: str | None = None,
    exit_code: int | None = 0,
    timed_out: bool = False,
    truncated: bool = False,
    observed_at: datetime | None = None,
    error: str | None = None,
) -> NmapExtraction:
    """Normalize Nmap output without treating incomplete scans as negative evidence."""
    evidence_id = evidence_id or f"evidence-{uuid4()}"
    rows = []
    for line in raw_output.splitlines():
        match = _SERVICE.match(line)
        if match is None:
            continue
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            continue
        product, version = _product_version(match.group("details") or "")
        rows.append(
            (
                port,
                match.group("protocol").lower(),
                match.group("state").lower(),
                match.group("service"),
                product,
                version,
            )
        )
    if timed_out:
        status = "timeout"
    elif exit_code not in (None, 0):
        status = "failed"
    elif truncated or not _COMPLETE.search(raw_output):
        status = "partial"
    else:
        status = "completed"
    complete = status == "completed"
    evidence = Evidence(
        evidence_id=evidence_id,
        asset_id=asset_id,
        capability_id=capability_id,
        tool_name="nmap",
        execution_status=status,
        facts={
            "scanner": "nmap",
            "scan_completed": complete,
            "service_count": len(rows),
            "open_service_count": sum(row[2].startswith("open") for row in rows),
        },
        raw_output_sha256=hashlib.sha256(raw_output.encode("utf-8")).hexdigest(),
        observed_at=observed_at or datetime.now(timezone.utc),
        complete=complete,
        truncated=truncated,
        error=error,
    )
    services = [
        ServiceObservation(
            asset_id=asset_id,
            port=p,
            protocol=proto,
            state=state,
            service=service,
            product=product,
            version=version,
            evidence_id=evidence_id,
        )
        for p, proto, state, service, product, version in rows
    ]
    return NmapExtraction(evidence=evidence, services=services)
