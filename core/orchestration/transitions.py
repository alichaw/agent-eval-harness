from __future__ import annotations

from core.orchestration.catalog import CapabilityCatalog
from core.orchestration.models import RunContext


def eligible_capabilities(run: RunContext, catalog: CapabilityCatalog) -> list[str]:
    if not run.observations:
        candidates: set[str] = {"network.service_discovery"}
    else:
        candidates = set()
        ports = {
            int(f.values["port"])
            for observation in run.observations
            if observation.status == "succeeded"
            for f in observation.facts
            if f.type == "open_port" and str(f.values.get("port", "")).isdigit()
        }
        if 22 in ports:
            candidates.add("ssh.posture_check")
        if 3389 in ports:
            candidates.add("rdp.posture_check")
        if ports & {139, 445}:
            candidates.add("smb.posture_check")
        # Only trusted orchestration input may add this evidence marker. Model
        # text and observations are never interpreted as T3 authorization.
        if "valid_t3_authorization" in run.evidence_types:
            candidates.add("host.controlled_remote_action")
    unavailable = set(run.executed) | set(run.denied) | set(run.failed)
    return sorted(
        capability
        for capability in candidates
        if capability in catalog.entries and capability not in unavailable
    )
