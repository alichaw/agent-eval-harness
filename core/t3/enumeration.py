"""T3-B: approved immutable, read-only Windows enumeration.

The agent-facing model contains identifiers only.  Executable programs and all
transport details remain in this trusted module/operator configuration.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.redaction import Redactor
from core.safety import ApprovalAuthority, KillSwitch
from core.schemas.models import SCHEMA_VERSION, TraceEvent, TraceEventType
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


def load_t3a_prerequisite(run_dir: str | Path) -> T3APrerequisite:
    """Derive a prerequisite only from stored original T3-A artifacts."""
    root = Path(run_dir)
    result = json.loads((root / "result.json").read_text(encoding="utf-8"))
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    raw_trace = (root / "trace.jsonl").read_bytes()
    events = [TraceEvent.model_validate_json(line) for line in raw_trace.splitlines()]
    rules = {item.rule for item in events}
    commands = {item.command_id: item for item in events if item.type is TraceEventType.TOOL_RESULT}
    outcome = result.get("lab_outcome") or {}
    asset_id = outcome.get("asset_id") or result.get("asset_id")
    runtime_fp = result.get("runtime_binding_fingerprint", "")
    if not isinstance(asset_id, str) or not asset_id:
        raise ValueError("T3-A evidence lacks asset binding")
    observed_at = manifest.get("created_utc")
    if not isinstance(observed_at, str):
        raise ValueError("T3-A evidence lacks trusted timestamp")
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
    )


@dataclass(frozen=True)
class T3BBindings:
    stage_id: str
    asset_id: str
    asset_fingerprint: str
    profile_id: str
    profile_fingerprint: str
    runtime_binding_fingerprint: str
    credential_reference_fingerprint: str
    command_ids: tuple[str, ...]
    registry_digest: str
    prerequisite_evidence_fingerprint: str
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
        stage_id=T3B_STAGE,
        asset_id=proposal.asset_id,
        asset_fingerprint=_digest(asset),
        profile_id=proposal.profile_id,
        profile_fingerprint=profile_fingerprint,
        runtime_binding_fingerprint=runtime_binding_fingerprint,
        credential_reference_fingerprint=_digest(credential_ref),
        command_ids=tuple(item.value for item in proposal.command_ids),  # ordered semantics
        registry_digest=action_registry_digest(registry),
        prerequisite_evidence_fingerprint=prerequisite.evidence_fingerprint,
    )


@dataclass(frozen=True)
class T3BExecutionPlan:
    asset_id: str
    target: str
    port: int
    pinned_host_key: str
    credential_ref: str
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


class T3BSession(ABC):
    @abstractmethod
    def execute_registered(self, definition: WindowsActionDefinition) -> Any: ...
    @abstractmethod
    def close(self) -> None: ...


class T3BTransport(ABC):
    @abstractmethod
    def open(self, connection: LabSshConnection, credential: LabSshCredential) -> T3BSession: ...


class _ParamikoT3BSession(T3BSession):
    def __init__(self, client: Any):
        self._client = client

    def execute_registered(self, definition: WindowsActionDefinition) -> LabSshTransportResult:
        trusted = WINDOWS_ACTION_REGISTRY.get(definition.action_id)
        if trusted != definition:
            raise ValueError("unregistered or drifted action definition")
        # Every token is registry-owned. No proposal text reaches this construction.
        command = shlex.join((definition.program, *definition.argv))
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


def _bounded(raw: bytes, limit: int) -> tuple[str, bool]:
    clipped = raw[:limit]
    return clipped.decode("utf-8", errors="replace"), len(raw) > limit


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
    ):
        self.resolver, self.transport = resolver, transport
        self.kill_switch, self.clock = kill_switch, clock
        self.invocation_count = 0

    def run(self, plan: T3BExecutionPlan) -> T3BOutcome:
        self.invocation_count += 1
        codes: list[str] = []
        records: list[T3BActionEvidence] = []
        session = None
        authenticated = closed = invalidated = stopped = False
        total_bytes = 0
        start = self.clock()
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
                    stdout, stdout_cut = _bounded(raw.stdout, T3B_STDOUT_LIMIT)
                    stderr, stderr_cut = _bounded(raw.stderr, T3B_STDERR_LIMIT)
                    remaining = max(0, T3B_TOTAL_OUTPUT_LIMIT - total_bytes)
                    combined = stdout.encode() + stderr.encode()
                    total_cut = len(combined) > remaining
                    if total_cut:
                        stdout = combined[:remaining].decode("utf-8", errors="replace")
                        stderr = ""
                    total_bytes += min(len(combined), remaining)
                    verification, summary = verify_observation(
                        definition.action_id, stdout, stdout_cut or total_cut
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
                            stdout_cut or total_cut,
                            stderr_cut,
                            execution,
                            verification,
                            summary,
                            "pending",
                        )
                    )
                    codes.extend(("action_completed", "output_bounded", "observation_verified"))
                    if total_cut:
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
                if invalidate is not None:
                    invalidate(plan.credential_ref, plan.asset_id)
                invalidated = True
                codes.append("credential_lease_invalidated")
            except Exception:  # noqa: BLE001
                invalidated = False
                codes.append("credential_invalidation_failed")
        cleanup = closed and invalidated
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


def run_t3b(
    *,
    plan: T3BExecutionPlan,
    prerequisite: T3APrerequisite,
    executor: T3BExecutor,
    authority: ApprovalAuthority,
    approval_token: str,
    runs_root: str | Path,
    redactor: Redactor | None = None,
) -> Path:
    """Consume a T3-B-only approval, run once, and persist bounded evidence."""
    run_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-t3b-{time.time_ns()}"
    root = Path(runs_root) / run_id
    root.mkdir(parents=True)
    trace = TraceWriter(run_id, root / "trace.jsonl", redactor=redactor)
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "schema_version": SCHEMA_VERSION,
                "stage": T3B_STAGE,
                "mock_only": True,
            },
            indent=2,
        )
    )

    def emit(rule: str) -> None:
        trace.emit(TraceEventType.POLICY_EVENT, rule=rule, text="T3-B control state")

    emit("t3b_proposal_validated")
    emit("t3a_prerequisite_validated")
    current_registry = action_registry_digest()
    if (
        plan.bindings.stage_id != T3B_STAGE
        or plan.bindings.profile_id != T3B_PROFILE
        or plan.bindings.asset_id != plan.asset_id
        or plan.bindings.registry_digest != current_registry
        or tuple(item.action_id.value for item in plan.definitions) != plan.bindings.command_ids
        or any(WINDOWS_ACTION_REGISTRY.get(item.action_id) != item for item in plan.definitions)
    ):
        raise ValueError("T3-B execution plan binding invalid")
    authority.verify_and_consume(
        approval_token,
        plan.asset_id,
        T3B_PROFILE,
        plan.bindings.fingerprint,
        credential_id=plan.credential_ref,
        action_fingerprint=plan.bindings.fingerprint,
    )
    emit("t3b_approval_consumed")
    outcome = executor.run(plan)
    for code in outcome.trace_codes:
        emit(code)
    for item in outcome.action_evidence:
        trace.emit(
            TraceEventType.TOOL_RESULT,
            tool="t3b-registered-windows-action",
            command_id=item.action_id,
            attempted=True,
            return_code=item.exit_status,
            outcome=item.execution_status,
            sanitized_stdout=item.stdout,
            sanitized_stderr=item.stderr,
            duration_seconds=item.duration_seconds,
            evidence_predicate_passed=item.verification_status == "verified",
            executed=True,
            result_digest=hashlib.sha256(
                json.dumps(asdict(item), sort_keys=True).encode()
            ).hexdigest(),
            text=item.observation_summary,
        )
    result = {
        "run_id": run_id,
        "stage": T3B_STAGE,
        "completed": outcome.completed,
        "status": outcome.status,
        "approval_scope_fingerprint": plan.bindings.fingerprint,
        "registry_digest": plan.bindings.registry_digest,
        "prerequisite_evidence_ref": prerequisite.evidence_ref,
        "prerequisite_evidence_fingerprint": prerequisite.evidence_fingerprint,
        "runtime_binding_fingerprint": plan.bindings.runtime_binding_fingerprint,
        "outcome": asdict(outcome),
    }
    value = redactor.value(result) if redactor else result
    (root / "result.json").write_text(json.dumps(value, indent=2))
    return root


def replay_t3b(run_dir: str | Path, bindings: T3BBindings) -> dict[str, Any]:
    """Offline-only T3-B replay with binding drift detection."""
    root = Path(run_dir)
    result = json.loads((root / "result.json").read_text())
    events = [
        TraceEvent.model_validate_json(x) for x in (root / "trace.jsonl").read_text().splitlines()
    ]
    actions = [x for x in events if x.tool == "t3b-registered-windows-action"]
    rules = [x.rule for x in events if x.rule]
    drift = (
        result.get("approval_scope_fingerprint") != bindings.fingerprint
        or result.get("registry_digest") != bindings.registry_digest
        or result.get("prerequisite_evidence_fingerprint")
        != bindings.prerequisite_evidence_fingerprint
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
        "drift_detected": drift,
        "actions": len(actions),
        "cleanup": cleanup,
        "valid_sequence": valid_sequence,
    }
