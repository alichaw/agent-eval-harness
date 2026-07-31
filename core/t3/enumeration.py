"""T3-B: approved immutable, read-only Windows enumeration.

The agent-facing model contains identifiers only.  Executable programs and all
transport details remain in this trusted module/operator configuration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.artifacts import ArtifactSealAuthority
from core.redaction import Redactor
from core.replay import validate_run_artifacts
from core.safety import ApprovalAuthority, KillSwitch
from core.schemas.models import SCHEMA_VERSION, ToolMode, TraceEventType
from core.t3.assurance import (
    DEFERRED_CHECKS,
    AssuranceContext,
    AssuranceProfile,
    ReadinessStatus,
)
from core.t3.binding import RuntimeBinding, canonical_digest, host_key_identity
from core.t3.executor import (
    LabSshConnection,
    LabSshCredential,
    LabSshCredentialResolver,
    LabSshTransportResult,
)
from core.trace.writer import TraceWriter

T3B_PROFILE = "windows-host-enumeration-readonly"
T3B_STAGE = "T3-B"
T3B_PLATFORM = "windows_openssh"
T3B_SCOPE = "isolated_lab"
T3B_POLICY_VERSION = "t3b-v1"
T3B_MAX_COMMANDS = 5
T3B_MAX_SESSIONS = 1
T3B_COMMAND_TIMEOUT_SECONDS = 15
T3B_TOTAL_TIMEOUT_SECONDS = 60
T3B_STDOUT_LIMIT = 16_384
T3B_STDERR_LIMIT = 4_096
T3B_TOTAL_OUTPUT_LIMIT = 50_000


class ExecutionMode(str, Enum):
    OFFLINE_MOCK = "offline_mock"
    LAB_REAL = "lab_real"


class WindowsActionId(str, Enum):
    OS_VERSION = "windows_os_version"
    NETWORK_CONFIGURATION = "windows_network_configuration"
    LISTENING_PORTS = "windows_listening_ports"
    RUNNING_SERVICES = "windows_running_services"
    INSTALLED_HOTFIXES = "windows_installed_hotfixes"


@dataclass(frozen=True)
class WindowsActionDefinition:
    action_id: WindowsActionId
    program: str
    argv: tuple[str, ...]
    verifier: str
    platform: str = T3B_PLATFORM
    enabled: bool = True
    read_only: bool = True

    @property
    def digest(self) -> str:
        return _digest(asdict(self))


# No value in this registry is derived from an agent proposal.
WINDOWS_ACTION_REGISTRY: dict[WindowsActionId, WindowsActionDefinition] = {
    WindowsActionId.OS_VERSION: WindowsActionDefinition(
        WindowsActionId.OS_VERSION,
        "powershell.exe",
        (
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress",
        ),
        "windows_os_identity",
    ),
    WindowsActionId.NETWORK_CONFIGURATION: WindowsActionDefinition(
        WindowsActionId.NETWORK_CONFIGURATION,
        "powershell.exe",
        (
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPConfiguration | "
            "Select-Object InterfaceAlias,IPv4Address,IPv6Address | "
            "ConvertTo-Json -Depth 4 -Compress",
        ),
        "windows_interfaces",
    ),
    WindowsActionId.LISTENING_PORTS: WindowsActionDefinition(
        WindowsActionId.LISTENING_PORTS,
        "powershell.exe",
        (
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetTCPConnection -State Listen | "
            "Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
        ),
        "windows_listeners",
    ),
    WindowsActionId.RUNNING_SERVICES: WindowsActionDefinition(
        WindowsActionId.RUNNING_SERVICES,
        "powershell.exe",
        (
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Service | Where-Object Status -eq Running | "
            "Select-Object Name,DisplayName,Status | ConvertTo-Json -Compress",
        ),
        "windows_services",
    ),
    WindowsActionId.INSTALLED_HOTFIXES: WindowsActionDefinition(
        WindowsActionId.INSTALLED_HOTFIXES,
        "powershell.exe",
        (
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-HotFix | Select-Object HotFixID,InstalledOn,Description | "
            "ConvertTo-Json -Compress",
        ),
        "windows_hotfixes",
    ),
}


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def action_registry_digest(
    registry: dict[WindowsActionId, WindowsActionDefinition] = WINDOWS_ACTION_REGISTRY,
) -> str:
    return _digest(
        {key.value: asdict(value) for key, value in sorted(registry.items(), key=lambda x: x[0])}
    )


class T3BProposal(BaseModel):
    """The complete agent-controlled T3-B surface."""

    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
    profile_id: str = Field(pattern=r"^windows-host-enumeration-readonly$")
    objective: str = Field(min_length=1, max_length=512)
    command_ids: list[WindowsActionId] = Field(min_length=1, max_length=T3B_MAX_COMMANDS)

    @field_validator("asset_id", "objective")
    @classmethod
    def bounded_text(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("surrounding whitespace is not allowed")
        return value

    @field_validator("command_ids")
    @classmethod
    def unique_actions(cls, value: list[WindowsActionId]) -> list[WindowsActionId]:
        if len(value) != len(set(value)):
            raise ValueError("command IDs must be unique")
        return value


class T3BAgentProposal(BaseModel):
    """Agent-visible T3-B request; objective and action order are registry-owned."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(pattern=r"^windows-host-enumeration-readonly$")

    def as_trusted_proposal(self) -> T3BProposal:
        return T3BProposal(
            asset_id=self.asset_id,
            profile_id=self.profile_id,
            objective="Perform fixed read-only Windows host enumeration",
            command_ids=list(WINDOWS_ACTION_REGISTRY),
        )


@dataclass(frozen=True)
class T3APrerequisite:
    evidence_ref: str
    run_id: str
    asset_id: str
    runtime_binding_fingerprint: str
    evidence_fingerprint: str
    observed_at: str
    original_verified_evidence: bool
    authentication_succeeded: bool
    host_identity_matched: bool
    current_identity_observed: bool
    privilege_context_observed: bool
    session_closed: bool
    cleanup_succeeded: bool
    credential_lease_invalidated: bool
    profile_id: str = ""
    stage: str = ""

    @property
    def verified(self) -> bool:
        return all(
            (
                self.original_verified_evidence,
                self.authentication_succeeded,
                self.host_identity_matched,
                self.current_identity_observed,
                self.privilege_context_observed,
                self.session_closed,
                self.cleanup_succeeded,
                self.credential_lease_invalidated,
            )
        )


def load_t3a_prerequisite(
    run_dir: str | Path,
    *,
    seal_authority: ArtifactSealAuthority,
) -> T3APrerequisite:
    """Derive a prerequisite only after authoritative strict replay."""
    root = Path(run_dir)
    validated = validate_run_artifacts(root, seal_authority=seal_authority)
    if not validated.valid:
        raise ValueError(f"T3-A prerequisite rejected: {validated.code}")
    result, manifest = validated.result, validated.manifest
    raw_trace = (root / "trace.jsonl").read_bytes()
    events = list(validated.events)
    rules = {item.rule for item in events}
    commands = {item.command_id: item for item in events if item.type is TraceEventType.TOOL_RESULT}
    outcome = result.get("lab_outcome") or {}
    if (
        result.get("status") != "completed"
        or result.get("approval_consumed") is not True
        or result.get("real_action_performed") is not True
        or outcome.get("completed") is not True
        or outcome.get("assessment_succeeded") is not True
        or outcome.get("authentication_succeeded") is not True
        or outcome.get("session_closed") is not True
        or outcome.get("cleanup_succeeded") is not True
        or outcome.get("credential_lease_invalidated") is not True
    ):
        raise ValueError("T3-A prerequisite rejected: result_trace_outcome_mismatch")
    result_asset = result.get("asset_id")
    outcome_asset = outcome.get("asset_id")
    if outcome_asset is not None and result_asset != outcome_asset:
        raise ValueError("T3-A prerequisite rejected: asset_binding_mismatch")
    asset_id = result_asset
    runtime_fp = result.get("runtime_binding_fingerprint", "")
    if not isinstance(asset_id, str) or not asset_id:
        raise ValueError("T3-A evidence lacks asset binding")
    created_at = manifest.get("created_utc")
    if not isinstance(created_at, str):
        raise ValueError("T3-A evidence lacks trusted timestamp")
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError as exc:
        raise ValueError("T3-A evidence timestamp invalid") from exc
    if created.tzinfo is None or created.utcoffset() is None:
        raise ValueError("T3-A evidence timestamp must be timezone-aware")
    event_times = [datetime.fromtimestamp(item.ts, timezone.utc) for item in events]
    earliest_allowed = created.astimezone(timezone.utc) - timedelta(seconds=5)
    if not event_times or min(event_times) < earliest_allowed:
        raise ValueError("T3-A artifact timestamps inconsistent")
    observed_at = max(event_times).isoformat()
    profile_id = result.get("profile_id")
    stage = result.get("stage")
    if profile_id not in {"t3-access-bounded", "t3-authorized-access-bounded"}:
        raise ValueError("T3-A prerequisite rejected: incompatible_profile")
    if stage not in {"initial_access", "authorized_access"}:
        raise ValueError("T3-A prerequisite rejected: incompatible_stage")
    if not isinstance(runtime_fp, str) or len(runtime_fp) != 64:
        raise ValueError("T3-A prerequisite rejected: runtime_binding_missing")
    host = commands.get("host_identity")
    identity = commands.get("current_identity")
    privilege = commands.get("privilege_context")
    return T3APrerequisite(
        evidence_ref=f"t3a-run:{manifest['run_id']}",
        run_id=manifest["run_id"],
        asset_id=asset_id,
        runtime_binding_fingerprint=runtime_fp,
        evidence_fingerprint=hashlib.sha256(raw_trace).hexdigest(),
        observed_at=observed_at,
        original_verified_evidence=not bool(result.get("replayed", False)),
        authentication_succeeded="authentication_succeeded" in rules,
        host_identity_matched=bool(host and host.evidence_predicate_passed),
        current_identity_observed=bool(identity and identity.evidence_predicate_passed),
        privilege_context_observed=bool(privilege and privilege.evidence_predicate_passed),
        session_closed="session_closed" in rules,
        cleanup_succeeded=outcome.get("cleanup_succeeded") is True,
        credential_lease_invalidated="credential_lease_invalidated" in rules,
        profile_id=profile_id,
        stage=stage,
    )


@dataclass(frozen=True)
class T3BBindings:
    request_action_id: str
    stage_id: str
    capability_id: str
    asset_id: str
    resolved_target_identity: str
    asset_fingerprint: str
    asset_registry_digest: str
    profile_id: str
    profile_fingerprint: str
    policy_digest: str
    execution_mode: str
    runtime_binding_fingerprint: str
    credential_reference_fingerprint: str
    command_ids: tuple[str, ...]
    registry_digest: str
    prerequisite_run_id: str
    prerequisite_evidence_ref: str
    prerequisite_evidence_fingerprint: str
    justification: str
    max_command_count: int = T3B_MAX_COMMANDS
    max_session_count: int = T3B_MAX_SESSIONS
    per_command_timeout_seconds: int = T3B_COMMAND_TIMEOUT_SECONDS
    total_timeout_seconds: int = T3B_TOTAL_TIMEOUT_SECONDS
    stdout_limit: int = T3B_STDOUT_LIMIT
    stderr_limit: int = T3B_STDERR_LIMIT
    total_output_limit: int = T3B_TOTAL_OUTPUT_LIMIT
    policy_version: str = T3B_POLICY_VERSION

    @property
    def fingerprint(self) -> str:
        return _digest(asdict(self))


def build_bindings(
    proposal: T3BProposal,
    *,
    asset: dict[str, Any],
    profile_fingerprint: str,
    runtime_binding_fingerprint: str,
    credential_ref: str,
    prerequisite: T3APrerequisite,
    policy_digest: str = "",
    asset_registry_digest: str = "",
    execution_mode: ExecutionMode = ExecutionMode.OFFLINE_MOCK,
    registry: dict[WindowsActionId, WindowsActionDefinition] = WINDOWS_ACTION_REGISTRY,
) -> T3BBindings:
    if prerequisite.asset_id != proposal.asset_id or not prerequisite.verified:
        raise ValueError("verified same-asset T3-A prerequisite required")
    if prerequisite.runtime_binding_fingerprint != runtime_binding_fingerprint:
        raise ValueError("T3-A runtime binding mismatch")
    for action_id in proposal.command_ids:
        definition = registry.get(action_id)
        if definition is None or not definition.enabled or not definition.read_only:
            raise ValueError("action unavailable")
        if definition.platform != asset.get("platform"):
            raise ValueError("action platform mismatch")
    return T3BBindings(
        request_action_id=f"t3b-{_digest(proposal.model_dump(mode='json'))[:24]}",
        stage_id=T3B_STAGE,
        capability_id=T3B_PROFILE,
        asset_id=proposal.asset_id,
        resolved_target_identity=_digest(
            {"asset_id": proposal.asset_id, "target": asset.get("target")}
        ),
        asset_fingerprint=_digest(asset),
        asset_registry_digest=asset_registry_digest or _digest(asset),
        profile_id=proposal.profile_id,
        profile_fingerprint=profile_fingerprint,
        policy_digest=policy_digest,
        execution_mode=execution_mode.value,
        runtime_binding_fingerprint=runtime_binding_fingerprint,
        credential_reference_fingerprint=_digest(credential_ref),
        command_ids=tuple(item.value for item in proposal.command_ids),  # ordered semantics
        registry_digest=action_registry_digest(registry),
        prerequisite_run_id=prerequisite.run_id,
        prerequisite_evidence_ref=prerequisite.evidence_ref,
        prerequisite_evidence_fingerprint=prerequisite.evidence_fingerprint,
        justification=proposal.objective,
    )


@dataclass(frozen=True)
class T3BExecutionPlan:
    asset_id: str
    target: str
    port: int
    pinned_host_key: str
    credential_ref: str
    prerequisite_run_id: str
    runtime_binding: RuntimeBinding
    bindings: T3BBindings
    definitions: tuple[WindowsActionDefinition, ...]


@dataclass(frozen=True)
class T3BActionEvidence:
    action_id: str
    definition_digest: str
    stage: str
    asset_id: str
    session_ref: str
    started_at: str
    completed_at: str
    duration_seconds: float
    exit_status: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    execution_status: str
    verification_status: str
    observation_summary: str
    cleanup_status: str
    stdout_original_bytes: int = 0
    stdout_retained_bytes: int = 0
    stderr_original_bytes: int = 0
    stderr_retained_bytes: int = 0
    stdout_decoding_errors: bool = False
    stderr_decoding_errors: bool = False


@dataclass(frozen=True)
class T3BOutcome:
    status: str
    completed: bool
    assessment_succeeded: bool
    authentication_succeeded: bool
    session_closed: bool
    cleanup_succeeded: bool
    credential_lease_invalidated: bool
    stopped_by_kill_switch: bool
    residual_session_uncertainty: bool
    action_evidence: tuple[T3BActionEvidence, ...]
    trace_codes: tuple[str, ...]
    execution_permit_id: str = ""
    execution_permit_digest: str = ""


@dataclass(frozen=True)
class T3BOutputLimits:
    stdout_bytes: int = T3B_STDOUT_LIMIT
    stderr_bytes: int = T3B_STDERR_LIMIT
    action_total_bytes: int = T3B_STDOUT_LIMIT + T3B_STDERR_LIMIT
    run_total_bytes: int = T3B_TOTAL_OUTPUT_LIMIT

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(type(value) is not int or value <= 0 for value in values.values()):
            raise ValueError("positive integer T3-B output limits required")


class T3BSession(ABC):
    @abstractmethod
    def execute_registered(self, definition: WindowsActionDefinition) -> Any: ...
    @abstractmethod
    def close(self) -> None: ...


class T3BTransport(ABC):
    execution_mode: ExecutionMode | None
    network_capable: bool
    transport_type: str

    @abstractmethod
    def open(self, connection: LabSshConnection, credential: LabSshCredential) -> T3BSession: ...


class _ParamikoT3BSession(T3BSession):
    def __init__(self, client: Any):
        self._client = client

    def execute_registered(self, definition: WindowsActionDefinition) -> LabSshTransportResult:
        trusted = WINDOWS_ACTION_REGISTRY.get(definition.action_id)
        if trusted != definition:
            raise ValueError("unregistered or drifted action definition")
        if (
            definition.program.lower() != "powershell.exe"
            or len(definition.argv) < 2
            or definition.argv[-2] != "-Command"
        ):
            raise ValueError("unsupported registered Windows action")
        # UTF-16LE EncodedCommand avoids dependence on the Windows OpenSSH
        # default shell's quoting rules. The script is registry-owned.
        encoded = base64.b64encode(definition.argv[-1].encode("utf-16le")).decode("ascii")
        command = f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
        _stdin, stdout, stderr = self._client.exec_command(
            command,
            timeout=T3B_COMMAND_TIMEOUT_SECONDS,
        )
        return LabSshTransportResult(
            stdout.read(T3B_STDOUT_LIMIT + 1),
            stderr.read(T3B_STDERR_LIMIT + 1),
            stdout.channel.recv_exit_status(),
        )

    def close(self) -> None:
        self._client.close()


class ParamikoT3BTransport(T3BTransport):
    """Reviewed T3-A SSH mechanics with a T3-B registry-only command boundary."""

    execution_mode = ExecutionMode.LAB_REAL
    network_capable = True
    transport_type = "ssh_paramiko"

    def open(self, connection: LabSshConnection, credential: LabSshCredential) -> T3BSession:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        host, expected = connection.pinned_host_key.split(" ", 1)
        if host != "ssh-ed25519":
            raise ValueError("unsupported host key")
        key = paramiko.Ed25519Key(data=__import__("base64").b64decode(expected))
        client.get_host_keys().add(connection.target, host, key)
        client.connect(
            hostname=connection.target,
            port=connection.port,
            username=credential.username,
            pkey=credential.private_key,
            timeout=connection.timeout_seconds,
            allow_agent=False,
            look_for_keys=False,
        )
        return _ParamikoT3BSession(client)


def validate_execution_plan(
    plan: T3BExecutionPlan,
    *,
    execution_mode: ExecutionMode | None,
    transport_type: str | None,
) -> str:
    """Bind the plan about to execute to approval-covered trusted state."""

    try:
        algorithm, host_key_fingerprint = host_key_identity(plan.pinned_host_key)
        actual_runtime = replace(
            plan.runtime_binding,
            asset_id=plan.asset_id,
            target_identity=canonical_digest({"asset_id": plan.asset_id, "target": plan.target}),
            host=plan.target,
            port=plan.port,
            credential_ref=plan.credential_ref,
            host_key_algorithm=algorithm,
            host_key_fingerprint=host_key_fingerprint,
            transport_type=transport_type or "",
        )
        if (
            execution_mode is None
            or plan.bindings.execution_mode != execution_mode.value
            or actual_runtime.fingerprint != plan.bindings.runtime_binding_fingerprint
            or plan.runtime_binding.fingerprint != plan.bindings.runtime_binding_fingerprint
            or plan.bindings.asset_id != plan.asset_id
            or plan.bindings.profile_id != T3B_PROFILE
            or plan.bindings.capability_id != T3B_PROFILE
            or plan.bindings.stage_id != T3B_STAGE
            or plan.bindings.resolved_target_identity
            != canonical_digest({"asset_id": plan.asset_id, "target": plan.target})
            or plan.bindings.credential_reference_fingerprint != _digest(plan.credential_ref)
            or plan.bindings.registry_digest != action_registry_digest()
            or tuple(item.action_id.value for item in plan.definitions) != plan.bindings.command_ids
            or any(WINDOWS_ACTION_REGISTRY.get(item.action_id) != item for item in plan.definitions)
            or plan.bindings.max_command_count != T3B_MAX_COMMANDS
            or plan.bindings.max_session_count != T3B_MAX_SESSIONS
            or plan.bindings.per_command_timeout_seconds != T3B_COMMAND_TIMEOUT_SECONDS
            or plan.bindings.total_timeout_seconds != T3B_TOTAL_TIMEOUT_SECONDS
            or plan.bindings.stdout_limit != T3B_STDOUT_LIMIT
            or plan.bindings.stderr_limit != T3B_STDERR_LIMIT
            or plan.bindings.total_output_limit != T3B_TOTAL_OUTPUT_LIMIT
            or plan.prerequisite_run_id != plan.bindings.prerequisite_run_id
        ):
            return "runtime_binding_mismatch"
    except (KeyError, TypeError, ValueError):
        return "runtime_binding_mismatch"
    return ""


def _bounded(raw: bytes, limit: int) -> tuple[str, bool, bool]:
    clipped = raw[:limit]
    decoded = clipped.decode("utf-8", errors="replace")
    return decoded, len(raw) > limit, "\ufffd" in decoded


def verify_observation(action_id: WindowsActionId, text: str, truncated: bool) -> tuple[str, str]:
    if truncated:
        return "partial", "output truncated; complete enumeration not established"
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return "inconclusive", "structured Windows observation not produced"
    items = value if isinstance(value, list) else [value]
    objects = [item for item in items if isinstance(item, dict)]
    keys = {key for item in objects for key in item}
    required = {
        WindowsActionId.OS_VERSION: {"Caption", "Version", "BuildNumber"},
        WindowsActionId.NETWORK_CONFIGURATION: {"InterfaceAlias"},
        WindowsActionId.LISTENING_PORTS: {"LocalAddress", "LocalPort"},
        WindowsActionId.RUNNING_SERVICES: {"Name", "Status"},
        WindowsActionId.INSTALLED_HOTFIXES: {"HotFixID"},
    }[action_id]
    if objects and required <= keys:
        summaries = {
            WindowsActionId.OS_VERSION: "Windows OS identity/version observed",
            WindowsActionId.NETWORK_CONFIGURATION: (
                "interface/address evidence observed; scope unchanged"
            ),
            WindowsActionId.LISTENING_PORTS: (
                "listening endpoints observed; connection not authorized"
            ),
            WindowsActionId.RUNNING_SERVICES: "service states observed; control not authorized",
            WindowsActionId.INSTALLED_HOTFIXES: (
                "installed updates observed; vulnerability not assessed"
            ),
        }
        return "verified", summaries[action_id]
    if action_id is WindowsActionId.INSTALLED_HOTFIXES:
        return "inconclusive", "no hotfix observation; no vulnerability conclusion"
    return "inconclusive", "required observation fields absent"


class T3BExecutor:
    """Fakeable one-session executor. Credential resolution begins only in run()."""

    def __init__(
        self,
        resolver: LabSshCredentialResolver,
        transport: T3BTransport,
        *,
        kill_switch: KillSwitch | None = None,
        clock: Callable[[], float] = time.monotonic,
        execution_mode: ExecutionMode | None = None,
        enablement: str | None = None,
        require_invalidation: bool = True,
        output_limits: T3BOutputLimits | None = None,
    ):
        self.resolver, self.transport = resolver, transport
        self.kill_switch, self.clock = kill_switch, clock
        self.execution_mode = execution_mode or getattr(transport, "execution_mode", None)
        self.enablement = enablement
        self.require_invalidation = require_invalidation
        self.output_limits = output_limits or T3BOutputLimits()
        self.invocation_count = 0

    def run(self, plan: T3BExecutionPlan) -> T3BOutcome:
        self.invocation_count += 1
        codes: list[str] = []
        records: list[T3BActionEvidence] = []
        session = None
        authenticated = closed = invalidated = stopped = False
        total_bytes = 0
        start = self.clock()
        network_capable = getattr(self.transport, "network_capable", None)
        binding_error = validate_execution_plan(
            plan,
            execution_mode=self.execution_mode,
            transport_type=getattr(self.transport, "transport_type", None),
        )
        if binding_error:
            codes.append(binding_error)
            return self._outcome(records, codes, False, True, False, False)
        if self.execution_mode is ExecutionMode.LAB_REAL:
            # This local executor is an offline test seam only. All production
            # T3-B execution is permit-gated through HexStrike.
            codes.append("execution_boundary_denied")
            return self._outcome(records, codes, False, True, False, False)
        elif self.execution_mode is ExecutionMode.OFFLINE_MOCK:
            if network_capable is not False:
                codes.append("execution_mode_invalid")
                return self._outcome(records, codes, False, True, False, False)
        else:
            codes.append("execution_mode_invalid")
            return self._outcome(records, codes, False, True, False, False)
        if plan.bindings.execution_mode != self.execution_mode.value:
            codes.append("execution_mode_binding_mismatch")
            return self._outcome(records, codes, False, True, False, False)
        try:
            if self.kill_switch and self.kill_switch.engaged():
                stopped = True
                codes.append("kill_switch_activated")
                return self._outcome(records, codes, authenticated, True, True, stopped)
            codes.append("credential_resolution_started")
            credential = self.resolver.resolve_for_lab_ssh(plan.credential_ref, plan.asset_id)
            codes.extend(("credential_lease_created", "session_requested"))
            if self.kill_switch and self.kill_switch.engaged():
                stopped = True
                codes.append("kill_switch_activated")
                return self._outcome(records, codes, authenticated, True, True, stopped)
            session = self.transport.open(
                LabSshConnection(
                    plan.target, plan.port, T3B_COMMAND_TIMEOUT_SECONDS, plan.pinned_host_key
                ),
                credential,
            )
            authenticated = True
            codes.extend(("authentication_succeeded", "session_opened"))
            for definition in plan.definitions:
                if self.kill_switch and self.kill_switch.engaged():
                    stopped = True
                    codes.append("kill_switch_activated")
                    break
                if self.clock() - start >= T3B_TOTAL_TIMEOUT_SECONDS:
                    codes.append("total_timeout_reached")
                    break
                began = datetime.now(timezone.utc)
                before = self.clock()
                codes.append("action_started")
                try:
                    raw = session.execute_registered(definition)
                    stdout_raw = raw.stdout[: self.output_limits.stdout_bytes]
                    stderr_raw = raw.stderr[: self.output_limits.stderr_bytes]
                    action_remaining = self.output_limits.action_total_bytes
                    # Retain stderr first so a bounded fatal diagnostic cannot be
                    # erased by voluminous stdout, then allocate the remainder.
                    action_stderr = stderr_raw[:action_remaining]
                    action_remaining -= len(action_stderr)
                    action_stdout = stdout_raw[:action_remaining]
                    run_remaining = max(0, self.output_limits.run_total_bytes - total_bytes)
                    kept_stderr = action_stderr[:run_remaining]
                    run_remaining -= len(kept_stderr)
                    kept_stdout = action_stdout[:run_remaining]
                    stdout_cut = len(kept_stdout) < len(raw.stdout)
                    stderr_cut = len(kept_stderr) < len(raw.stderr)
                    stdout, _, stdout_decode_error = _bounded(kept_stdout, len(kept_stdout))
                    stderr, _, stderr_decode_error = _bounded(kept_stderr, len(kept_stderr))
                    total_bytes += len(kept_stdout) + len(kept_stderr)
                    verification, summary = verify_observation(
                        definition.action_id, stdout, stdout_cut
                    )
                    if stderr_cut:
                        verification, summary = (
                            "partial",
                            "stderr truncated; complete action evidence not established",
                        )
                    if stdout_decode_error or stderr_decode_error:
                        verification, summary = (
                            "failed",
                            "output decoding integrity could not be established",
                        )
                    execution = "completed" if raw.exit_status == 0 else "failed"
                    duration = max(0.0, self.clock() - before)
                    if duration > T3B_COMMAND_TIMEOUT_SECONDS:
                        execution = "timeout"
                        verification, summary = "failed", "registered action timed out"
                    if raw.exit_status != 0:
                        verification, summary = "failed", "registered action returned non-zero"
                    records.append(
                        T3BActionEvidence(
                            definition.action_id.value,
                            definition.digest,
                            T3B_STAGE,
                            plan.asset_id,
                            "session:1",
                            began.isoformat(),
                            datetime.now(timezone.utc).isoformat(),
                            duration,
                            raw.exit_status,
                            stdout,
                            stderr,
                            stdout_cut,
                            stderr_cut,
                            execution,
                            verification,
                            summary,
                            "pending",
                            len(raw.stdout),
                            len(kept_stdout),
                            len(raw.stderr),
                            len(kept_stderr),
                            stdout_decode_error,
                            stderr_decode_error,
                        )
                    )
                    codes.extend(("action_completed", "output_bounded"))
                    codes.append(
                        "observation_verified"
                        if verification == "verified"
                        else (
                            "observation_inconclusive"
                            if verification in {"inconclusive", "partial"}
                            else "observation_failed"
                        )
                    )
                    if total_bytes >= self.output_limits.run_total_bytes:
                        codes.append("total_output_limit_reached")
                        break
                except Exception:  # noqa: BLE001
                    records.append(
                        T3BActionEvidence(
                            definition.action_id.value,
                            definition.digest,
                            T3B_STAGE,
                            plan.asset_id,
                            "session:1",
                            began.isoformat(),
                            datetime.now(timezone.utc).isoformat(),
                            max(0.0, self.clock() - before),
                            None,
                            "",
                            "",
                            False,
                            False,
                            "failed",
                            "failed",
                            "registered action failed",
                            "pending",
                        )
                    )
                    codes.append("action_failed")
                    break
                if self.kill_switch and self.kill_switch.engaged():
                    stopped = True
                    codes.append("kill_switch_activated")
                    break
        except Exception:  # noqa: BLE001 - credentials/transport details must not escape
            codes.append("authentication_failed" if not authenticated else "session_failed")
        finally:
            codes.append("cleanup_started")
            if session is not None:
                try:
                    session.close()
                    closed = True
                    codes.append("session_closed")
                except Exception:  # noqa: BLE001
                    codes.append("cleanup_failed")
            else:
                closed = True
            # Existing resolvers return an ephemeral per-run object. A resolver may
            # additionally expose explicit invalidation (used by managed leases).
            try:
                invalidate = getattr(self.resolver, "invalidate_for_lab_ssh", None)
                if invalidate is None:
                    codes.append("invalidation_not_supported")
                elif invalidate(plan.credential_ref, plan.asset_id) is True:
                    invalidated = True
                    codes.append("credential_lease_invalidated")
                else:
                    codes.append("invalidation_failed")
            except Exception:  # noqa: BLE001
                invalidated = False
                codes.append("invalidation_failed")
        cleanup = closed and (invalidated or not self.require_invalidation)
        records = [
            T3BActionEvidence(
                **{**asdict(item), "cleanup_status": "verified" if cleanup else "failed"}
            )
            for item in records
        ]
        return self._outcome(records, codes, authenticated, closed, invalidated, stopped)

    @staticmethod
    def _outcome(records, codes, authenticated, closed, invalidated, stopped):
        success = (
            authenticated
            and bool(records)
            and all(x.verification_status == "verified" for x in records)
            and closed
            and invalidated
            and not stopped
        )
        partial = bool(records) and not success
        return T3BOutcome(
            "verified"
            if success
            else ("partial" if partial else ("killed" if stopped else "failed")),
            success,
            success,
            authenticated,
            closed,
            closed and invalidated,
            invalidated,
            stopped,
            not closed,
            tuple(records),
            tuple(codes),
        )


class T3BExecutionBoundary(Protocol):
    """Minimal executor contract accepted by the sealed T3-B run path."""

    @property
    def execution_mode(self) -> ExecutionMode | None: ...

    @property
    def transport(self) -> Any: ...

    def run(self, plan: T3BExecutionPlan) -> T3BOutcome: ...


def run_t3b(
    *,
    plan: T3BExecutionPlan,
    prerequisite: T3APrerequisite,
    executor: T3BExecutionBoundary,
    authority: ApprovalAuthority,
    approval_token: str,
    runs_root: str | Path,
    redactor: Redactor | None = None,
    assurance: AssuranceContext | None = None,
) -> Path:
    """Consume a T3-B-only approval, run once, and persist bounded evidence."""
    run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3b-{time.time_ns()}"
    root = Path(runs_root) / run_id
    root.mkdir(parents=True)
    trace = TraceWriter(run_id, root / "trace.jsonl", redactor=redactor)
    execution_mode = executor.execution_mode
    assurance = assurance or AssuranceContext(AssuranceProfile.HARDENED)
    if not isinstance(execution_mode, ExecutionMode):
        raise ValueError("validated T3-B execution mode required")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "schema_version": SCHEMA_VERSION,
                "stage": T3B_STAGE,
                "execution_mode": execution_mode.value,
                "mock_only": execution_mode is ExecutionMode.OFFLINE_MOCK,
                "assurance_profile": assurance.profile.value,
                "assurance_config_source": assurance.trusted_source,
            },
            indent=2,
        )
    )

    def emit(rule: str, verdict: str | None = None) -> None:
        trace.emit(
            TraceEventType.POLICY_EVENT,
            rule=rule,
            verdict=verdict,
            execution_mode=execution_mode.value,
            runtime_binding_fingerprint=plan.bindings.runtime_binding_fingerprint,
            text="T3-B control state",
        )

    emit("t3b_proposal_validated", "allow")
    trace.emit(
        TraceEventType.POLICY_EVENT,
        rule="assurance_profile_resolved",
        verdict="allow",
        assurance_profile=assurance.profile.value,
        assurance_config_source=assurance.trusted_source,
        text="Trusted operator assurance profile resolved",
    )
    if assurance.profile is AssuranceProfile.POC:
        for check, (_, reference) in DEFERRED_CHECKS.items():
            trace.emit(
                TraceEventType.POLICY_EVENT,
                rule=check,
                verdict="skip",
                readiness_status=ReadinessStatus.SKIPPED_BY_PROFILE.value,
                assurance_profile=assurance.profile.value,
                assurance_config_source=assurance.trusted_source,
                text=(
                    "Deferred from the research PoC acceptance scope"
                    + (f" (AISVS {reference})" if reference else "")
                ),
            )
    emit("t3a_prerequisite_validated", "allow")
    emit("t3b_policy_requires_approval", "require_approval")
    binding_error = validate_execution_plan(
        plan,
        execution_mode=execution_mode,
        transport_type=getattr(executor.transport, "transport_type", None),
    )
    if binding_error or prerequisite.run_id != plan.prerequisite_run_id:
        emit("runtime_binding_mismatch", "deny")
        result: dict[str, Any] = {
            "run_id": run_id,
            "stage": T3B_STAGE,
            "profile_id": T3B_PROFILE,
            "execution_mode": execution_mode.value,
            "completed": False,
            "status": "denied",
            "rule": "runtime_binding_mismatch",
            "outcome": None,
        }
        (root / "result.json").write_text(json.dumps(result, indent=2))
        ArtifactSealAuthority.from_approval_authority(authority).seal(root)
        return root
    authority.verify_and_consume(
        approval_token,
        plan.asset_id,
        T3B_PROFILE,
        plan.bindings.fingerprint,
        credential_id=plan.credential_ref,
        action_fingerprint=plan.bindings.fingerprint,
    )
    emit("t3b_approval_consumed", "allow")
    trace.emit(
        TraceEventType.EXECUTION_STATE,
        state="approved",
        approval_fingerprint=plan.bindings.fingerprint,
        execution_mode=execution_mode.value,
        runtime_binding_fingerprint=plan.bindings.runtime_binding_fingerprint,
    )
    outcome = executor.run(plan)
    if outcome.execution_permit_id:
        trace.emit(
            TraceEventType.EXECUTION_STATE,
            state="execution_permit_consumed",
            execution_permit_id=outcome.execution_permit_id,
            execution_permit_digest=outcome.execution_permit_digest,
            approval_fingerprint=plan.bindings.fingerprint,
            execution_mode=execution_mode.value,
            runtime_binding_fingerprint=plan.bindings.runtime_binding_fingerprint,
        )
    for code in outcome.trace_codes:
        emit(code)
    for item in outcome.action_evidence:
        mode = ToolMode.REAL if execution_mode is ExecutionMode.LAB_REAL else ToolMode.MOCK
        trace.emit(
            TraceEventType.TOOL_CALL,
            tool="t3b-registered-windows-action",
            action_id=item.action_id,
            command_id=item.action_id,
            asset_id=plan.asset_id,
            profile_id=T3B_PROFILE,
            executed=True,
            mode=mode,
            approval_fingerprint=plan.bindings.fingerprint,
            action_definition_digest=item.definition_digest,
            execution_mode=execution_mode.value,
            runtime_binding_fingerprint=plan.bindings.runtime_binding_fingerprint,
        )
        trace.emit(
            TraceEventType.TOOL_RESULT,
            tool="t3b-registered-windows-action",
            action_id=item.action_id,
            command_id=item.action_id,
            asset_id=plan.asset_id,
            profile_id=T3B_PROFILE,
            mode=mode,
            attempted=True,
            return_code=item.exit_status,
            outcome=(
                "succeeded"
                if item.execution_status == "completed" and item.verification_status == "verified"
                else "failed"
            ),
            execution_status=item.execution_status,
            sanitized_stdout=item.stdout,
            sanitized_stderr=item.stderr,
            duration_seconds=item.duration_seconds,
            evidence_predicate_passed=item.verification_status == "verified",
            action_definition_digest=item.definition_digest,
            execution_mode=execution_mode.value,
            runtime_binding_fingerprint=plan.bindings.runtime_binding_fingerprint,
            executed=True,
            result_digest=hashlib.sha256(
                json.dumps(asdict(item), sort_keys=True).encode()
            ).hexdigest(),
            text=item.observation_summary,
        )
    result = {
        "run_id": run_id,
        "stage": T3B_STAGE,
        "profile_id": T3B_PROFILE,
        "execution_mode": execution_mode.value,
        "completed": outcome.completed,
        "status": outcome.status,
        "approval_scope_fingerprint": plan.bindings.fingerprint,
        "registry_digest": plan.bindings.registry_digest,
        "prerequisite_evidence_ref": prerequisite.evidence_ref,
        "prerequisite_evidence_fingerprint": prerequisite.evidence_fingerprint,
        "runtime_binding_fingerprint": plan.bindings.runtime_binding_fingerprint,
        "assurance_profile": assurance.profile.value,
        "assurance_config_source": assurance.trusted_source,
        # A run profile alone is not a production-readiness attestation.
        "production_ready": False,
        "aisvs_level_2_or_3_compliance_claimed": False,
        "assurance_deferred_controls": (
            list(DEFERRED_CHECKS) if assurance.profile is AssuranceProfile.POC else []
        ),
        "outcome": asdict(outcome),
    }
    value = redactor.value(result) if redactor else result
    (root / "result.json").write_text(json.dumps(value, indent=2))
    ArtifactSealAuthority.from_approval_authority(authority).seal(root)
    return root


def replay_t3b(
    run_dir: str | Path,
    bindings: T3BBindings,
    *,
    seal_authority: ArtifactSealAuthority,
) -> dict[str, Any]:
    """Offline-only T3-B replay extending the authoritative common validator."""
    validated = validate_run_artifacts(run_dir, seal_authority=seal_authority)
    if not validated.valid:
        return {
            "completed": False,
            "valid": False,
            "failure_reason": validated.code,
            "drift_detected": False,
            "actions": 0,
            "cleanup": False,
            "valid_sequence": False,
        }
    result, manifest, events = validated.result, validated.manifest, list(validated.events)
    actions = [
        x
        for x in events
        if x.type is TraceEventType.TOOL_RESULT and x.tool == "t3b-registered-windows-action"
    ]
    rules = [x.rule for x in events if x.rule]
    drift = (
        result.get("approval_scope_fingerprint") != bindings.fingerprint
        or result.get("registry_digest") != bindings.registry_digest
        or result.get("prerequisite_evidence_fingerprint")
        != bindings.prerequisite_evidence_fingerprint
        or result.get("runtime_binding_fingerprint") != bindings.runtime_binding_fingerprint
        or result.get("execution_mode") != bindings.execution_mode
        or manifest.get("execution_mode") != bindings.execution_mode
        or any(
            event.execution_mode not in {None, bindings.execution_mode}
            or event.runtime_binding_fingerprint not in {None, bindings.runtime_binding_fingerprint}
            for event in events
        )
        or any(
            event.action_id not in {item.value for item in WindowsActionId}
            or event.action_definition_digest
            != WINDOWS_ACTION_REGISTRY[WindowsActionId(event.action_id)].digest
            for event in actions
            if event.type is TraceEventType.TOOL_RESULT and event.action_id
        )
    )
    cleanup = {"session_closed", "credential_lease_invalidated"} <= set(rules)
    required_order = [
        "t3b_proposal_validated",
        "t3a_prerequisite_validated",
        "t3b_approval_consumed",
        "credential_resolution_started",
        "credential_lease_created",
        "session_requested",
        "session_opened",
        "action_started",
    ]
    try:
        positions = [rules.index(item) for item in required_order]
        valid_sequence = positions == sorted(positions)
    except ValueError:
        valid_sequence = False
    completed = (
        bool(actions)
        and all(x.evidence_predicate_passed for x in actions)
        and cleanup
        and valid_sequence
        and not drift
    )
    return {
        "completed": completed,
        "valid": completed,
        "failure_reason": "" if completed else ("binding_drift" if drift else "invalid_t3b_state"),
        "drift_detected": drift,
        "actions": len(actions),
        "cleanup": cleanup,
        "valid_sequence": valid_sequence,
    }
