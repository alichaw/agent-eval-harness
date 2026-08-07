from __future__ import annotations

import re
from typing import Literal, cast

from core.orchestration.models import ExecutionResult, Fact, Observation
from core.redaction import Redactor

_NMAP = re.compile(r"^\s*(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_POSTURE_TERMS = {
    "ssh.posture_check": ("ssh", "banner", "host key", "algorithm", "cipher", "kex"),
    "rdp.posture_check": ("nla", "credssp", "tls", "security layer", "encryption"),
    "smb.posture_check": ("smb", "dialect", "signing", "anonymous", "guest", "share"),
}


def normalize(
    capability_id: str, asset_id: str, result: ExecutionResult, max_bytes: int
) -> Observation:
    raw = Redactor(salt=b"orchestration-output-redaction", redact_credentials=True).text(
        result.output
    )
    encoded = raw.encode()
    truncated = len(encoded) > max_bytes
    if truncated:
        raw = encoded[:max_bytes].decode(errors="replace")
    facts = list(result.facts)
    warnings = list(result.parser_warnings)
    if capability_id == "network.service_discovery":
        facts.extend(
            Fact(type="open_port", values={"port": int(p), "service": s.lower()})
            for p, s in _NMAP.findall(raw)
        )
        if result.status == "succeeded" and not facts and "Nmap done:" not in raw:
            warnings.append("nmap completion marker absent")
            status = "partial"
        else:
            status = result.status
    elif capability_id in _POSTURE_TERMS:
        terms = _POSTURE_TERMS[capability_id]
        for line in raw.splitlines():
            clean = line.strip()
            if clean and any(term in clean.lower() for term in terms):
                facts.append(
                    Fact(
                        type="posture_finding",
                        values={"summary": clean[:300]},
                    )
                )
        status = result.status
    else:
        status = result.status
    return Observation(
        capability_id=capability_id,
        status=cast(Literal["succeeded", "failed", "cancelled", "partial"], status),
        facts=facts[:100],
        evidence_ids=result.evidence_ids,
        asset_id=asset_id,
        sanitized=True,
        truncated=truncated,
        parser_warnings=warnings,
    )
