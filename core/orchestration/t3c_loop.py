"""Resumable T3-C approval boundary inside one orchestration run."""

from __future__ import annotations

import time
from collections.abc import Callable

from core.orchestration.catalog import Capability
from core.orchestration.models import RunContext, RunStatus
from core.orchestration.observations import normalize
from core.orchestration.t3c_approval import PendingAction, T3CApprovalStore, T3CPermit


class T3CLoopApproval:
    def __init__(
        self,
        store: T3CApprovalStore,
        *,
        kill_switch: Callable[[], bool],
        max_output_bytes: int = 65536,
    ):
        self.store = store
        self.kill_switch = kill_switch
        self.max_output_bytes = max_output_bytes
        self.store.initialize()

    def request(
        self,
        run: RunContext,
        capability: Capability,
        *,
        authorization_id: str,
        protected_scope_digest: str,
        prerequisite_evidence_references: tuple[str, ...],
        policy_decision_reference: str,
        deployment_config_version: str,
        approval_ttl_seconds: int = 300,
        now: int | None = None,
    ) -> PendingAction:
        selected = int(time.time()) if now is None else now
        if capability.phase != "t3c" or not authorization_id:
            raise ValueError("t3c_authorization_required")
        if self.kill_switch():
            raise ValueError("kill_switch_engaged")
        action_id = self.store.action_id(
            run.run_id, capability.capability_id, protected_scope_digest
        )
        pending = PendingAction(
            run_id=run.run_id,
            pending_action_id=action_id,
            authorization_id=authorization_id,
            asset_id=run.asset_id,
            capability_id=capability.capability_id,
            profile_id=capability.profile_id or capability.canonical_action or "",
            protected_scope_digest=protected_scope_digest,
            requested_at=selected,
            approval_expires_at=selected + approval_ttl_seconds,
            policy_decision_reference=policy_decision_reference,
            prerequisite_evidence_references=prerequisite_evidence_references,
            attempt_count=0,
            current_loop_state="waiting_for_approval",
            deployment_config_version=deployment_config_version,
        )
        self.store.create_pending(pending)
        run.status = RunStatus.WAITING_FOR_APPROVAL
        run.pending_capability = capability.capability_id
        run.pending_action_id = action_id
        return pending

    def approve(
        self,
        run: RunContext,
        *,
        approved_by: str,
        ttl_seconds: int = 300,
        now: int | None = None,
    ) -> T3CPermit:
        if run.status is not RunStatus.WAITING_FOR_APPROVAL or not run.pending_action_id:
            raise ValueError("run_not_waiting_for_approval")
        permit = self.store.approve(
            run.pending_action_id, approved_by=approved_by, ttl_seconds=ttl_seconds, now=now
        )
        run.status = RunStatus.APPROVED_PENDING_RESUME
        return permit

    def deny(self, run: RunContext) -> RunContext:
        if run.status is not RunStatus.WAITING_FOR_APPROVAL or not run.pending_action_id:
            raise ValueError("run_not_waiting_for_approval")
        self.store.deny(run.pending_action_id)
        run.status = RunStatus.APPROVAL_DENIED
        run.stop_reason = "t3c_approval_denied"
        return run

    def resume(
        self,
        run: RunContext,
        capability: Capability,
        permit: T3CPermit,
        executor,
        *,
        protected_scope_digest: str,
        prerequisite_evidence_references: tuple[str, ...],
        deployment_config_version: str,
        now: int | None = None,
    ) -> RunContext:
        if run.status is not RunStatus.APPROVED_PENDING_RESUME or not run.pending_action_id:
            raise ValueError("run_not_resumable")
        if self.kill_switch():
            self.store.finish(run.pending_action_id, "cancelled")
            run.status = RunStatus.CANCELLED
            return run
        persisted = self.store.get_pending(run.pending_action_id)
        expected = PendingAction(
            **{
                **persisted.__dict__,
                "protected_scope_digest": protected_scope_digest,
                "prerequisite_evidence_references": prerequisite_evidence_references,
                "deployment_config_version": deployment_config_version,
            }
        )
        if (
            persisted.run_id != run.run_id
            or persisted.asset_id != run.asset_id
            or persisted.capability_id != capability.capability_id
            or persisted.profile_id != (capability.profile_id or capability.canonical_action or "")
            or persisted != expected
        ):
            raise ValueError("pending_action_binding_mismatch")
        self.store.consume(permit, persisted, now=now)
        run.status = RunStatus.RUNNING
        result = executor.execute(capability, run)
        run.tool_calls += 1
        observation = normalize(
            capability.capability_id, run.asset_id, result, self.max_output_bytes
        )
        run.observations.append(observation)
        run.evidence_types.update(result.evidence_types)
        if observation.status == "succeeded":
            run.executed.append(capability.capability_id)
            self.store.finish(persisted.pending_action_id, "succeeded")
        else:
            self.store.finish(persisted.pending_action_id, "failed")
            run.consecutive_failures += 1
        run.pending_action_id = None
        run.pending_capability = None
        run.status = RunStatus.RUNNING
        return run
