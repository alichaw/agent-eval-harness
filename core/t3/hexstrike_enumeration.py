"""HexStrike-only real executor for fixed T3-B Windows enumeration."""

from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace
from typing import Any

import requests

from core.safety import KillSwitch
from core.t3.assurance import AssuranceContext, AssuranceProfile
from core.t3.enumeration import (
    T3B_PROFILE,
    T3B_STAGE,
    ExecutionMode,
    T3BActionEvidence,
    T3BExecutionPlan,
    T3BOutcome,
    verify_observation,
)
from core.t3.hexstrike_access import issue_execution_permit

T3B_OPERATION_ID = "windows.host.enumeration.readonly.v1"
T3B_PERMIT_SCHEMA = "hexstrike-t3b-permit/v1"
T3B_RESULT_SCHEMA = "hexstrike-t3b-result/v1"


class HexStrikeT3BExecutor:
    """One permit-authenticated HexStrike call with no local transport fallback."""

    execution_mode = ExecutionMode.LAB_REAL

    def __init__(
        self,
        *,
        base_url: str,
        permit_secret: bytes,
        enablement: str | None,
        kill_switch: KillSwitch,
        assurance: AssuranceContext | None = None,
        timeout: float = 75.0,
        session: Any = requests,
    ):
        self.base_url = base_url.rstrip("/")
        self.permit_secret = permit_secret
        self.enabled = enablement == "true"
        self.kill_switch = kill_switch
        self.assurance = assurance or AssuranceContext(AssuranceProfile.HARDENED)
        self.timeout = timeout
        self.session = session
        self.transport = SimpleNamespace(transport_type="hexstrike_t3b_v1")
        self.invocation_count = 0

    def run(self, plan: T3BExecutionPlan) -> T3BOutcome:
        self.invocation_count += 1
        if not self.enabled:
            return self._failed("lab_execution_disabled")
        if self.assurance.profile is AssuranceProfile.HARDENED and len(self.permit_secret) < 32:
            return self._failed("execution_permit_secret_unavailable")
        if self.kill_switch.engaged():
            return self._failed("kill_switch_engaged", stopped=True)
        now = int(time.time())
        claims = {
            "schema_version": T3B_PERMIT_SCHEMA,
            "permit_id": hashlib.sha256(
                f"{plan.bindings.request_action_id}:{time.time_ns()}".encode()
            ).hexdigest()[:32],
            "nonce": hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest(),
            "issued_at": now,
            "expires_at": now + 60,
            "asset_id": plan.asset_id,
            "profile_id": T3B_PROFILE,
            "stage": T3B_STAGE,
            "operation_id": T3B_OPERATION_ID,
            "target": plan.target,
            "port": plan.port,
            "credential_ref": plan.credential_ref,
            "pinned_host_key": plan.pinned_host_key,
            "prerequisite_run_id": plan.prerequisite_run_id,
            "approval_fingerprint": plan.bindings.fingerprint,
            "runtime_binding_fingerprint": plan.bindings.runtime_binding_fingerprint,
            "command_ids": list(plan.bindings.command_ids),
            "registry_digest": plan.bindings.registry_digest,
            "definition_digests": [item.digest for item in plan.definitions],
            "limits": {
                "max_commands": plan.bindings.max_command_count,
                "max_sessions": plan.bindings.max_session_count,
                "per_command_timeout_seconds": plan.bindings.per_command_timeout_seconds,
                "total_timeout_seconds": plan.bindings.total_timeout_seconds,
                "stdout_limit": plan.bindings.stdout_limit,
                "stderr_limit": plan.bindings.stderr_limit,
                "total_output_limit": plan.bindings.total_output_limit,
            },
            "result_schema": T3B_RESULT_SCHEMA,
        }
        hardened = self.assurance.profile is AssuranceProfile.HARDENED
        authorization_id = str(claims["permit_id"])
        token = issue_execution_permit(self.permit_secret, claims) if hardened else ""
        try:
            response = self.session.post(
                (
                    f"{self.base_url}/api/v1/t3b/executions"
                    if hardened
                    else f"{self.base_url}/api/v1/t3b/poc-executions"
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
                return self._failed("hexstrike_execution_rejected")
            data = response.json()
        except Exception:  # noqa: BLE001
            return self._failed("hexstrike_unavailable")
        try:
            authorization_field = "permit_id" if hardened else "authorization_id"
            expected = {
                "schema_version",
                authorization_field,
                "operation_id",
                "status",
                "authentication_succeeded",
                "session_closed",
                "cleanup_succeeded",
                "credential_lease_invalidated",
                "action_results",
            }
            if (
                set(data) != expected
                or data["schema_version"]
                != (T3B_RESULT_SCHEMA if hardened else "hexstrike-t3b-poc-result/v1")
                or data[authorization_field] != authorization_id
                or data["operation_id"] != T3B_OPERATION_ID
                or data["status"] != "verified"
                or data["authentication_succeeded"] is not True
                or data["session_closed"] is not True
                or data["cleanup_succeeded"] is not True
                or data["credential_lease_invalidated"] is not True
                or [item["action_id"] for item in data["action_results"]]
                != list(plan.bindings.command_ids)
            ):
                raise ValueError("invalid response")
            records = []
            for definition, item in zip(plan.definitions, data["action_results"], strict=True):
                item_fields = {
                    "action_id",
                    "definition_digest",
                    "started_at",
                    "completed_at",
                    "duration_seconds",
                    "exit_status",
                    "stdout",
                    "stderr",
                    "stdout_original_bytes",
                    "stdout_retained_bytes",
                    "stderr_original_bytes",
                    "stderr_retained_bytes",
                    "stdout_truncated",
                    "stderr_truncated",
                    "stdout_decoding_errors",
                    "stderr_decoding_errors",
                }
                verification, summary = verify_observation(
                    definition.action_id,
                    item["stdout"],
                    item["stdout_truncated"],
                )
                if (
                    set(item) != item_fields
                    or item["definition_digest"] != definition.digest
                    or item["exit_status"] != 0
                    or item["stderr_truncated"] is not False
                    or item["stdout_decoding_errors"] is not False
                    or item["stderr_decoding_errors"] is not False
                    or item["stdout_retained_bytes"] != len(item["stdout"].encode())
                    or item["stderr_retained_bytes"] != len(item["stderr"].encode())
                    or item["stdout_retained_bytes"] > item["stdout_original_bytes"]
                    or item["stderr_retained_bytes"] > item["stderr_original_bytes"]
                    or verification != "verified"
                ):
                    raise ValueError("unverified action")
                records.append(
                    T3BActionEvidence(
                        action_id=definition.action_id.value,
                        definition_digest=definition.digest,
                        stage=T3B_STAGE,
                        asset_id=plan.asset_id,
                        session_ref=authorization_id,
                        started_at=item["started_at"],
                        completed_at=item["completed_at"],
                        duration_seconds=float(item["duration_seconds"]),
                        exit_status=0,
                        stdout=item["stdout"],
                        stderr=item["stderr"],
                        stdout_truncated=item["stdout_truncated"],
                        stderr_truncated=item["stderr_truncated"],
                        execution_status="completed",
                        verification_status=verification,
                        observation_summary=summary,
                        cleanup_status="verified",
                        stdout_original_bytes=item["stdout_original_bytes"],
                        stdout_retained_bytes=item["stdout_retained_bytes"],
                        stderr_original_bytes=item["stderr_original_bytes"],
                        stderr_retained_bytes=item["stderr_retained_bytes"],
                        stdout_decoding_errors=item["stdout_decoding_errors"],
                        stderr_decoding_errors=item["stderr_decoding_errors"],
                    )
                )
        except (KeyError, TypeError, ValueError):
            return self._failed("hexstrike_response_invalid")
        return T3BOutcome(
            status="verified",
            completed=True,
            assessment_succeeded=True,
            authentication_succeeded=data["authentication_succeeded"] is True,
            session_closed=data["session_closed"] is True,
            cleanup_succeeded=data["cleanup_succeeded"] is True,
            credential_lease_invalidated=data["credential_lease_invalidated"] is True,
            stopped_by_kill_switch=False,
            residual_session_uncertainty=False,
            action_evidence=tuple(records),
            trace_codes=(
                *(
                    ("hexstrike_permit_consumed",)
                    if hardened
                    else (
                        "signed_execution_permit_skipped_by_profile",
                        "operator_approval_authorization_consumed",
                    )
                ),
                "credential_resolution_started",
                "credential_lease_created",
                "session_requested",
                "session_opened",
                "action_started",
                "session_closed",
                "credential_lease_invalidated",
            ),
            execution_permit_id=authorization_id if hardened else "",
            execution_permit_digest=(
                hashlib.sha256(token.encode()).hexdigest() if hardened else ""
            ),
        )

    @staticmethod
    def _failed(rule: str, *, stopped: bool = False) -> T3BOutcome:
        return T3BOutcome(
            rule,
            False,
            False,
            False,
            True,
            True,
            False,
            stopped,
            False,
            (),
            (rule,),
        )
