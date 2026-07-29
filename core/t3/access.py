"""Bounded T3-A SSH access with a closed command and session boundary."""

from __future__ import annotations

import hashlib
import json
import re
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.investigation.models import InvestigationState
from core.profiles import AssetRegistry
from core.safety import KillSwitch
from core.t3.executor import (
    LAB_SSH_PORT,
    MAX_OBSERVATION_BYTES,
    MAX_OBSERVATION_LINES,
    LabSshConnection,
    LabSshCredential,
    LabSshCredentialResolver,
    LabSshTransportError,
    LabSshTransportResult,
    T3Executor,
    valid_pinned_host_key,
)
from core.t3.models import T3ActionRequest, T3Stage, t3_action_fingerprint

T3_ACCESS_PROFILE = "t3-access-bounded"
T3_ACCESS_CAPABILITY = T3_ACCESS_PROFILE
T3_ACCESS_METHOD = "bounded-ssh-observation"
T3_ACCESS_PURPOSE = "bounded remote access and privilege context verification"
T3_ACCESS_SCOPE = "isolated_lab"
T3_ACCESS_PLATFORM = "windows_openssh"
T3_MAX_COMMANDS = 4
T3_IDLE_TIMEOUT_SECONDS = 30
T3_ABSOLUTE_TIMEOUT_SECONDS = 60


class T3CommandId(str, Enum):
    CURRENT_IDENTITY = "current_identity"
    HOST_IDENTITY = "host_identity"
    PRIVILEGE_CONTEXT = "privilege_context"


class SessionState(str, Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    CREDENTIAL_RESOLVED = "credential_resolved"
    SESSION_REQUESTED = "session_requested"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    ACTIVE = "active"
    COMMAND_RUNNING = "command_running"
    CLOSING = "closing"
    CLOSED = "closed"
    AUTHENTICATION_FAILED = "authentication_failed"
    TIMED_OUT = "timed_out"
    REVOKED = "revoked"
    FAILED = "failed"
    CLEANUP_FAILED = "cleanup_failed"


class PrivilegeContextOutcome(str, Enum):
    OBSERVED = "privilege_context_observed"
    NOT_OBSERVED = "privilege_context_not_observed"
    FAILED = "assessment_failed"
    INCONCLUSIVE = "assessment_inconclusive"
    PLATFORM_INCOMPATIBLE = "platform_incompatible"


@dataclass(frozen=True)
class T3SessionPolicy:
    max_sessions: int = 1
    max_commands: int = T3_MAX_COMMANDS
    idle_timeout_seconds: int = T3_IDLE_TIMEOUT_SECONDS
    absolute_timeout_seconds: int = T3_ABSOLUTE_TIMEOUT_SECONDS
    interactive_shell: bool = False
    privilege_escalation: bool = False
    credential_access: bool = False
    file_upload: bool = False
    file_download: bool = False
    persistence: bool = False
    lateral_movement: bool = False
    network_pivoting: bool = False
    arbitrary_process_execution: bool = False
    cleanup_required: bool = True


SESSION_POLICY = T3SessionPolicy()


def t3_access_approval_fingerprint(request: T3ActionRequest) -> str:
    """Bind the action plus immutable purpose, effects, and session limits."""
    document = {
        "action_fingerprint": t3_action_fingerprint(request),
        "purpose": T3_ACCESS_PURPOSE,
        "intended_effects": ["authenticate_once", "fixed_read_only_observations"],
        "session_policy": asdict(SESSION_POLICY),
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class T3AccessProposal(BaseModel):
    """The complete agent-facing T3-A input surface."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(pattern=r"^t3-access-bounded$")
    objective: str = Field(min_length=1, max_length=256)
    command_ids: list[T3CommandId] = Field(min_length=1, max_length=T3_MAX_COMMANDS)

    @field_validator("asset_id", "objective")
    @classmethod
    def _strip_nonempty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped or stripped != value:
            raise ValueError("value must be non-empty without surrounding whitespace")
        return stripped

    @field_validator("command_ids")
    @classmethod
    def _unique_commands(cls, value: list[T3CommandId]) -> list[T3CommandId]:
        if len(set(value)) != len(value):
            raise ValueError("command IDs must be unique")
        return value


def materialize_t3_access_request(
    proposal: T3AccessProposal,
    *,
    action_id: str,
    state: InvestigationState,
    assets: AssetRegistry,
) -> T3ActionRequest:
    """Turn an agent proposal into a registry- and evidence-derived control request."""
    if proposal.asset_id != state.asset_id:
        raise ValueError("proposal asset does not match investigation")
    asset = assets.resolve(proposal.asset_id)
    credential_ref = asset.get("credential_ref")
    if not isinstance(credential_ref, str) or not credential_ref.strip():
        raise ValueError("registered credential reference required")
    suitable = [
        finding
        for finding in state.findings
        if finding.asset_id == proposal.asset_id
        and finding.status == "confirmed"
        and finding.classification in {"confirmed_vulnerability", "exploitable"}
    ]
    if not suitable:
        raise ValueError("confirmed initial-access prerequisite required")
    finding_ids = sorted(finding.finding_id for finding in suitable)
    evidence_ids = sorted(
        {evidence_id for finding in suitable for evidence_id in finding.evidence_ids}
    )
    return T3ActionRequest(
        action_id=action_id,
        stage=T3Stage.INITIAL_ACCESS,
        source_asset_id=proposal.asset_id,
        capability_id=proposal.profile_id,
        method=T3_ACCESS_METHOD,
        finding_refs=finding_ids,
        evidence_refs=evidence_ids,
        credential_ref=credential_ref.strip(),
        command_scope=[command.value for command in proposal.command_ids],
        written_justification=proposal.objective,
    )


@dataclass(frozen=True)
class BoundedLabSshExecutionPlan:
    action_id: str
    source_asset_id: str
    profile_id: str
    target: str
    port: int
    credential_handle: str
    pinned_host_key: str
    command_ids: tuple[T3CommandId, ...]
    session_policy: T3SessionPolicy = field(default_factory=T3SessionPolicy)


@dataclass(frozen=True)
class T3CommandResult:
    command_id: str
    attempted: bool
    return_code: int | None
    outcome: str
    sanitized_stdout: str
    sanitized_stderr: str
    duration_seconds: float
    evidence_predicate_passed: bool


@dataclass(frozen=True)
class T3AccessOutcome:
    status: str
    rule: str
    completed: bool
    assessment_succeeded: bool
    authentication_succeeded: bool
    commands_requested: int
    commands_attempted: int
    commands_succeeded: int
    commands_failed: int
    commands_denied: int
    privilege_context_outcome: str
    stopped_by_kill_switch: bool
    session_closed: bool
    cleanup_succeeded: bool
    credential_lease_invalidated: bool
    policy_violations: tuple[str, ...]
    residual_effects: bool
    command_results: tuple[T3CommandResult, ...]
    trace_codes: tuple[str, ...]
    mock_only: bool = False
    real_action_performed: bool = True
    arbitrary_command_exposed: bool = False

    def result_document(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("trace_codes")
        return value


class BoundedSshSession(ABC):
    @abstractmethod
    def observe(self, command_id: T3CommandId) -> LabSshTransportResult: ...

    @abstractmethod
    def close(self) -> None: ...


class BoundedSshTransport(ABC):
    @abstractmethod
    def open(
        self,
        connection: LabSshConnection,
        credential: LabSshCredential,
        platform: str,
    ) -> BoundedSshSession: ...


_FIXED_WINDOWS_COMMANDS = {
    T3CommandId.CURRENT_IDENTITY: "whoami",
    T3CommandId.HOST_IDENTITY: "hostname",
    T3CommandId.PRIVILEGE_CONTEXT: "whoami /groups",
}
_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class _ParamikoBoundedSession(BoundedSshSession):
    def __init__(self, client: Any):
        self._client = client
        self._closed = False

    def observe(self, command_id: T3CommandId) -> LabSshTransportResult:
        if self._closed:
            raise LabSshTransportError("t3_session_closed")
        command = _FIXED_WINDOWS_COMMANDS.get(command_id)
        if command is None:
            raise LabSshTransportError("t3_command_not_allowed")
        stdout = stderr = None
        try:
            _, stdout, stderr = self._client.exec_command(
                command,
                timeout=T3_IDLE_TIMEOUT_SECONDS,
                get_pty=False,
                environment=None,
            )
            stdout.channel.settimeout(T3_IDLE_TIMEOUT_SECONDS)
            output = stdout.read(MAX_OBSERVATION_BYTES + 1)
            error = stderr.read(MAX_OBSERVATION_BYTES + 1)
            return LabSshTransportResult(
                output,
                error,
                stdout.channel.recv_exit_status(),
            )
        except Exception as exc:
            raise LabSshTransportError("t3_command_failed", observation_started=True) from exc
        finally:
            for stream in (stdout, stderr):
                if stream is not None:
                    stream.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._client.close()


class ParamikoBoundedSshTransport(BoundedSshTransport):
    """Open exactly one pinned-key SSH session; expose only closed observations."""

    def open(
        self,
        connection: LabSshConnection,
        credential: LabSshCredential,
        platform: str,
    ) -> BoundedSshSession:
        if platform != T3_ACCESS_PLATFORM:
            raise LabSshTransportError("t3_platform_incompatible")
        if connection.port != LAB_SSH_PORT or not valid_pinned_host_key(connection.pinned_host_key):
            raise LabSshTransportError("t3_target_not_permitted")
        try:
            import paramiko
        except ImportError as exc:
            raise LabSshTransportError("lab_ssh_dependency_unavailable") from exc
        if not isinstance(credential.private_key, paramiko.PKey):
            raise LabSshTransportError("lab_credential_invalid")
        entry = paramiko.hostkeys.HostKeyEntry.from_line(connection.pinned_host_key)
        if entry is None or entry.key is None:
            raise LabSshTransportError("lab_host_key_invalid")
        client = paramiko.SSHClient()
        try:
            client.get_host_keys().add(connection.target, entry.key.get_name(), entry.key)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=connection.target,
                port=LAB_SSH_PORT,
                username=credential.username,
                pkey=credential.private_key,
                timeout=T3_IDLE_TIMEOUT_SECONDS,
                banner_timeout=T3_IDLE_TIMEOUT_SECONDS,
                auth_timeout=T3_IDLE_TIMEOUT_SECONDS,
                allow_agent=False,
                look_for_keys=False,
            )
            return _ParamikoBoundedSession(client)
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise LabSshTransportError("lab_ssh_host_key_failed") from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise LabSshTransportError("lab_ssh_authentication_failed") from exc
        except Exception as exc:
            client.close()
            raise LabSshTransportError("lab_ssh_connection_failed") from exc


def _sanitize(result: LabSshTransportResult) -> str:
    if len(result.stdout) > MAX_OBSERVATION_BYTES or len(result.stderr) > MAX_OBSERVATION_BYTES:
        raise ValueError("bounded output exceeded")
    text = result.stdout.decode("utf-8", errors="replace")
    text = _ANSI_ESCAPE.sub("", text)
    text = "".join(
        char for char in text if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )
    lines = text.splitlines()
    if not lines or len(lines) > MAX_OBSERVATION_LINES:
        raise ValueError("invalid bounded output")
    value = "\n".join(line.strip() for line in lines).strip()
    if not value:
        raise ValueError("invalid bounded output")
    return value


class BoundedLabSshT3Executor(T3Executor):
    """One approval, one credential lease, one session, and up to four fixed reads."""

    def __init__(
        self,
        resolver: LabSshCredentialResolver,
        transport: BoundedSshTransport,
        *,
        enablement: str | None,
        permitted_target: str,
        kill_switch: KillSwitch | None = None,
    ):
        self.resolver = resolver
        self.transport = transport
        self.enabled = enablement == "true"
        self.permitted_target = permitted_target
        self.kill_switch = kill_switch
        self.invocation_count = 0

    def run(self, plan: BoundedLabSshExecutionPlan) -> T3AccessOutcome:
        self.invocation_count += 1
        codes = ["credential_resolution_started"]
        results: list[T3CommandResult] = []
        credential = None
        session = None
        authenticated = False
        stopped = False
        cleanup = False
        lease_invalidated = False
        failure_rule = ""
        started = time.monotonic()
        try:
            if self.kill_switch is not None and self.kill_switch.engaged():
                codes.extend(
                    (
                        "kill_switch_activated",
                        "session_closure_initiated",
                        "credential_lease_invalidated",
                        "cleanup_result",
                    )
                )
                return self._outcome(
                    plan, results, codes, "stopped_by_kill_switch", False, False, True, True, True
                )
            try:
                credential = self.resolver.resolve_for_lab_ssh(
                    plan.credential_handle, plan.source_asset_id
                )
                if not isinstance(credential, LabSshCredential):
                    raise TypeError("invalid credential")
            except Exception:  # noqa: BLE001
                codes.extend(
                    (
                        "credential_resolution_failed",
                        "session_closure_initiated",
                        "credential_lease_invalidated",
                        "cleanup_result",
                    )
                )
                return self._outcome(
                    plan,
                    results,
                    codes,
                    "credential_resolution_failed",
                    False,
                    False,
                    False,
                    True,
                    True,
                )
            codes.extend(("credential_resolution_completed", "credential_lease_created"))
            connection = LabSshConnection(
                plan.target, plan.port, T3_IDLE_TIMEOUT_SECONDS, plan.pinned_host_key
            )
            codes.extend(("session_requested", "authentication_attempted"))
            try:
                session = self.transport.open(connection, credential, T3_ACCESS_PLATFORM)
                authenticated = True
                codes.extend(("authentication_succeeded", "session_active"))
            except LabSshTransportError as exc:
                failure_rule = exc.rule
                codes.append(
                    "authentication_failed"
                    if exc.rule == "lab_ssh_authentication_failed"
                    else "session_failed"
                )
            except Exception:  # noqa: BLE001
                failure_rule = "lab_ssh_connection_failed"
                codes.append("session_failed")
            if authenticated and session is not None:
                for command_id in plan.command_ids:
                    if self.kill_switch is not None and self.kill_switch.engaged():
                        stopped = True
                        failure_rule = "stopped_by_kill_switch"
                        codes.append("kill_switch_activated")
                        break
                    if time.monotonic() - started >= plan.session_policy.absolute_timeout_seconds:
                        failure_rule = "timed_out"
                        codes.append("session_timed_out")
                        break
                    codes.extend(("command_requested", "command_allowed", "command_attempted"))
                    command_started = time.monotonic()
                    try:
                        raw = session.observe(command_id)
                        value = _sanitize(raw)
                        passed = raw.exit_status == 0 and not raw.stderr and bool(value)
                        outcome = "succeeded" if passed else "failed"
                        results.append(
                            T3CommandResult(
                                command_id.value,
                                True,
                                raw.exit_status,
                                outcome,
                                value if passed else "",
                                "",
                                max(0.0, time.monotonic() - command_started),
                                passed,
                            )
                        )
                        codes.append("command_result")
                        if not passed:
                            failure_rule = "command_failed"
                    except LabSshTransportError as exc:
                        failure_rule = exc.rule
                        results.append(
                            T3CommandResult(
                                command_id.value, True, None, "failed", "", "", 0.0, False
                            )
                        )
                        codes.append("command_result")
                        break
                    except Exception:  # noqa: BLE001
                        failure_rule = "command_output_invalid"
                        results.append(
                            T3CommandResult(
                                command_id.value, True, None, "failed", "", "", 0.0, False
                            )
                        )
                        codes.append("command_result")
                        break
        finally:
            codes.append("session_closure_initiated")
            if session is not None:
                try:
                    session.close()
                    cleanup = True
                    codes.append("session_closed")
                except Exception:  # noqa: BLE001
                    cleanup = False
                    failure_rule = "cleanup_failed"
                    codes.append("cleanup_failed")
            else:
                cleanup = True
            credential = None
            lease_invalidated = True
            codes.extend(("credential_lease_invalidated", "cleanup_result"))

        success = (
            authenticated
            and len(results) == len(plan.command_ids)
            and all(item.evidence_predicate_passed for item in results)
            and cleanup
            and not stopped
        )
        status = "completed" if success else (failure_rule or "failed")
        return self._outcome(
            plan,
            results,
            codes,
            status,
            success,
            authenticated,
            stopped,
            cleanup,
            lease_invalidated,
        )

    @staticmethod
    def _outcome(
        plan: BoundedLabSshExecutionPlan,
        results: list[T3CommandResult],
        codes: list[str],
        status: str,
        success: bool,
        authenticated: bool,
        stopped: bool,
        cleanup: bool,
        lease_invalidated: bool,
    ) -> T3AccessOutcome:
        privilege = PrivilegeContextOutcome.INCONCLUSIVE
        for result in results:
            if result.command_id == T3CommandId.PRIVILEGE_CONTEXT.value:
                privilege = (
                    PrivilegeContextOutcome.OBSERVED
                    if result.evidence_predicate_passed
                    else PrivilegeContextOutcome.FAILED
                )
        succeeded = sum(item.outcome == "succeeded" for item in results)
        failed = sum(item.outcome == "failed" for item in results)
        return T3AccessOutcome(
            status=status,
            rule=status,
            completed=success,
            assessment_succeeded=success,
            authentication_succeeded=authenticated,
            commands_requested=len(plan.command_ids),
            commands_attempted=len(results),
            commands_succeeded=succeeded,
            commands_failed=failed,
            commands_denied=0,
            privilege_context_outcome=privilege.value,
            stopped_by_kill_switch=stopped,
            session_closed=cleanup,
            cleanup_succeeded=cleanup,
            credential_lease_invalidated=lease_invalidated,
            policy_violations=(),
            residual_effects=not cleanup,
            command_results=tuple(results),
            trace_codes=tuple(codes),
            real_action_performed=authenticated or bool(results),
        )
