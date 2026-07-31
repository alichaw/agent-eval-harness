"""HexStrike-only real executor for the bounded T3-A operation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import asdict
from typing import Any

import requests

from core.safety import KillSwitch
from core.t3.access import (
    SESSION_POLICY,
    BoundedLabSshExecutionPlan,
    PrivilegeContextOutcome,
    T3AccessOutcome,
    T3CommandId,
    T3CommandResult,
)
from core.t3.assurance import AssuranceContext, AssuranceProfile
from core.t3.binding import canonical_digest
from core.t3.executor import T3Executor

T3A_OPERATION_ID = "windows.ssh.identity.v1"
T3A_RESULT_SCHEMA = "hexstrike-t3a-result/v1"
T3A_PERMIT_SCHEMA = "hexstrike-t3a-permit/v1"
T3A_COMMANDS = (
    T3CommandId.CURRENT_IDENTITY,
    T3CommandId.HOST_IDENTITY,
    T3CommandId.PRIVILEGE_CONTEXT,
)
T3A_REGISTRY_DIGEST = canonical_digest([item.value for item in T3A_COMMANDS])


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def issue_execution_permit(secret: bytes, claims: dict[str, Any]) -> str:
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    return f"{_encode(payload)}.{_encode(hmac.new(secret, payload, hashlib.sha256).digest())}"


class HexStrikeT3AExecutor(T3Executor):
    """Send one approved canonical T3-A operation to HexStrike; never fall back."""

    def __init__(
        self,
        *,
        base_url: str,
        permit_secret: bytes,
        enablement: str | None,
        permitted_target: str,
        kill_switch: KillSwitch | None,
        approval_fingerprint: str,
        runtime_binding_fingerprint: str,
        assurance: AssuranceContext | None = None,
        timeout: float = 70.0,
        session: Any = requests,
    ):
        self.base_url = base_url.rstrip("/")
        self.permit_secret = permit_secret
        self.enabled = enablement == "true"
        self.permitted_target = permitted_target
        self.kill_switch = kill_switch
        self.approval_fingerprint = approval_fingerprint
        self.runtime_binding_fingerprint = runtime_binding_fingerprint
        self.assurance = assurance or AssuranceContext(AssuranceProfile.HARDENED)
        self.timeout = timeout
        self.session = session
        self.invocation_count = 0

    def run(self, plan: BoundedLabSshExecutionPlan) -> T3AccessOutcome:
        self.invocation_count += 1
        if not self.enabled:
            return self._failed(plan, "lab_execution_disabled")
        if self.assurance.profile is AssuranceProfile.HARDENED and len(self.permit_secret) < 32:
            return self._failed(plan, "execution_permit_secret_unavailable")
        if self.kill_switch is not None and self.kill_switch.engaged():
            return self._failed(plan, "stopped_by_kill_switch", stopped=True)
        if (
            plan.target != self.permitted_target
            or plan.port != 22
            or plan.command_ids != T3A_COMMANDS
        ):
            return self._failed(plan, "runtime_binding_mismatch")
        now = int(time.time())
        claims = {
            "schema_version": T3A_PERMIT_SCHEMA,
            "permit_id": hashlib.sha256(
                f"{plan.action_id}:{now}:{time.time_ns()}".encode()
            ).hexdigest()[:32],
            "nonce": _encode(hashlib.sha256(f"{time.time_ns()}".encode()).digest()[:24]),
            "issued_at": now,
            "expires_at": now + 60,
            "asset_id": plan.source_asset_id,
            "profile_id": plan.profile_id,
            "operation_id": T3A_OPERATION_ID,
            "target": plan.target,
            "port": plan.port,
            "credential_ref": plan.credential_handle,
            "pinned_host_key": plan.pinned_host_key,
            "command_ids": [item.value for item in plan.command_ids],
            "command_registry_digest": T3A_REGISTRY_DIGEST,
            "approval_fingerprint": self.approval_fingerprint,
            "runtime_binding_fingerprint": self.runtime_binding_fingerprint,
            "limits": asdict(SESSION_POLICY),
            "result_schema": T3A_RESULT_SCHEMA,
        }
        hardened = self.assurance.profile is AssuranceProfile.HARDENED
        authorization_id = str(claims["permit_id"])
        token = issue_execution_permit(self.permit_secret, claims) if hardened else ""
        permit_digest = hashlib.sha256(token.encode()).hexdigest() if hardened else ""
        try:
            response = self.session.post(
                (
                    f"{self.base_url}/api/v1/t3a/executions"
                    if hardened
                    else f"{self.base_url}/api/v1/t3a/poc-executions"
                ),
                json=(
                    {"permit": token}
                    if hardened
                    else {
                        "authorization_id": authorization_id,
                        "canonical_action": {
                            key: value
                            for key, value in claims.items()
                            if key not in {"schema_version", "permit_id", "nonce"}
                        },
                    }
                ),
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return self._failed(plan, "hexstrike_execution_rejected")
            data = response.json()
        except Exception:  # noqa: BLE001 - remote details must not enter artifacts
            return self._failed(plan, "hexstrike_unavailable")
        try:
            authorization_field = "permit_id" if hardened else "authorization_id"
            if (
                set(data)
                != {
                    "schema_version",
                    authorization_field,
                    "operation_id",
                    "status",
                    "authentication_succeeded",
                    "session_closed",
                    "cleanup_succeeded",
                    "credential_lease_invalidated",
                    "command_results",
                }
                or data["schema_version"]
                != (T3A_RESULT_SCHEMA if hardened else "hexstrike-t3a-poc-result/v1")
                or data[authorization_field] != authorization_id
                or data["operation_id"] != T3A_OPERATION_ID
                or data["status"] != "completed"
                or [item["command_id"] for item in data["command_results"]]
                != [item.value for item in T3A_COMMANDS]
            ):
                raise ValueError("invalid result")
            results = tuple(
                T3CommandResult(
                    command_id=item["command_id"],
                    attempted=item["attempted"] is True,
                    return_code=item["return_code"],
                    outcome=item["outcome"],
                    sanitized_stdout=item["sanitized_stdout"],
                    sanitized_stderr="",
                    duration_seconds=float(item["duration_seconds"]),
                    evidence_predicate_passed=item["evidence_predicate_passed"] is True,
                )
                for item in data["command_results"]
            )
            if len(results) != 3 or not all(item.evidence_predicate_passed for item in results):
                raise ValueError("incomplete result")
        except (KeyError, TypeError, ValueError):
            return self._failed(plan, "hexstrike_response_invalid")
        return T3AccessOutcome(
            status="completed",
            rule="completed",
            completed=True,
            assessment_succeeded=True,
            authentication_succeeded=data["authentication_succeeded"] is True,
            commands_requested=3,
            commands_attempted=3,
            commands_succeeded=3,
            commands_failed=0,
            commands_denied=0,
            privilege_context_outcome=PrivilegeContextOutcome.OBSERVED.value,
            stopped_by_kill_switch=False,
            session_closed=data["session_closed"] is True,
            cleanup_succeeded=data["cleanup_succeeded"] is True,
            credential_lease_invalidated=data["credential_lease_invalidated"] is True,
            policy_violations=(),
            residual_effects=False,
            command_results=results,
            trace_codes=(
                ("hexstrike_permit_consumed", "hexstrike_execution_completed")
                if hardened
                else (
                    "signed_execution_permit_skipped_by_profile",
                    "operator_approval_authorization_consumed",
                    "hexstrike_execution_completed",
                )
            ),
            execution_permit_id=authorization_id if hardened else "",
            execution_permit_digest=permit_digest,
        )

    @staticmethod
    def _failed(
        plan: BoundedLabSshExecutionPlan, rule: str, *, stopped: bool = False
    ) -> T3AccessOutcome:
        return T3AccessOutcome(
            status=rule,
            rule=rule,
            completed=False,
            assessment_succeeded=False,
            authentication_succeeded=False,
            commands_requested=len(plan.command_ids),
            commands_attempted=0,
            commands_succeeded=0,
            commands_failed=0,
            commands_denied=len(plan.command_ids),
            privilege_context_outcome=PrivilegeContextOutcome.INCONCLUSIVE.value,
            stopped_by_kill_switch=stopped,
            session_closed=True,
            cleanup_succeeded=True,
            credential_lease_invalidated=False,
            policy_violations=(rule,),
            residual_effects=False,
            command_results=(),
            trace_codes=(rule,),
            real_action_performed=False,
        )
