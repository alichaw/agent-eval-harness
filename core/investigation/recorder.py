"""Deterministically record policy and execution outcomes in investigation state."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from core.investigation.extractors import extract_nmap
from core.investigation.models import Evidence, InvestigationState
from core.investigation.router import SERVICE_INVENTORY


def record_step_result(
    state: InvestigationState,
    *,
    capability_id: str,
    profile_id: str,
    tool_name: str,
    admitted: bool,
    verified: bool,
    output: str,
    verdict: str = "allow",
    run_id: str = "",
    action_id: str = "",
    observed_at: datetime | None = None,
) -> InvestigationState:
    """Return a validated copy; admission alone is never treated as success."""
    executed = set(state.executed_capabilities)
    failed = set(state.failed_capabilities)
    pending = set(state.pending_approval_capabilities)
    blocked = set(state.blocked_capabilities)
    evidence = list(state.evidence)
    services = list(state.services)

    if not admitted:
        if verdict == "require_approval":
            pending.add(capability_id)
        else:
            blocked.add(capability_id)
        return _validated_copy(
            state,
            pending_approval_capabilities=pending,
            blocked_capabilities=blocked,
        )

    pending.discard(capability_id)
    raw_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()
    evidence_id = f"{state.investigation_id}-{len(evidence) + 1}"
    when = observed_at or datetime.now(timezone.utc)

    if capability_id == SERVICE_INVENTORY:
        extraction = extract_nmap(
            output,
            asset_id=state.asset_id,
            capability_id=capability_id,
            evidence_id=evidence_id,
            exit_code=0 if verified else 1,
            observed_at=when,
            error=None if verified else "executor reported failure",
        )
        item = extraction.evidence
        item = item.model_copy(
            update={
                "run_id": run_id or None,
                "action_id": action_id or None,
                "profile_id": profile_id,
                "policy_verdict": verdict,
                "result_digest": raw_hash,
                "verified": verified,
            }
        )
        new_services = extraction.services
    else:
        item = Evidence(
            evidence_id=evidence_id,
            asset_id=state.asset_id,
            capability_id=capability_id,
            tool_name=tool_name,
            execution_status="completed" if verified else "failed",
            facts={"profile_id": profile_id},
            raw_output_sha256=raw_hash,
            observed_at=when,
            complete=verified,
            error=None if verified else "executor reported failure",
            run_id=run_id or None,
            action_id=action_id or None,
            profile_id=profile_id,
            policy_verdict=verdict,
            result_digest=raw_hash,
            verified=verified,
        )
        new_services = []

    evidence.append(item)
    services.extend(new_services)
    if verified and item.complete:
        executed.add(capability_id)
    else:
        failed.add(capability_id)

    return _validated_copy(
        state,
        evidence=evidence,
        services=services,
        executed_capabilities=executed,
        pending_approval_capabilities=pending,
        failed_capabilities=failed,
        blocked_capabilities=blocked,
    )


def _validated_copy(state: InvestigationState, **updates) -> InvestigationState:
    data = state.model_dump()
    data.update(updates)
    return InvestigationState.model_validate(data)
