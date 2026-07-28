"""Closed T3 executor boundaries for deterministic mock and isolated-lab SSH."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import struct
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from core.t3.models import T3ActionRequest, T3Stage

LAB_SSH_CAPABILITY = "lab.ssh.observe"
LAB_SSH_METHOD = "fixed-observation"
LAB_SSH_PORT = 22
LAB_EXECUTION_SCOPE = "isolated_lab"
LAB_PLATFORM = "posix"
LAB_TIMEOUT_SECONDS = 5.0
MAX_OBSERVATION_BYTES = 512
MAX_OBSERVATION_LINES = 4


class LabObservation(str, Enum):
    IDENTITY = "identity"
    HOSTNAME = "hostname"


# These are the only remote command strings in the T3 lab slice. They are private,
# fixed, and selected solely from LabObservation; callers never provide command text.
_FIXED_COMMANDS = {
    LabObservation.IDENTITY: "id -un",
    LabObservation.HOSTNAME: "hostname",
}
_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class T3Executor(ABC):
    """Nominal executor boundary; Controller additionally allowlists exact implementations."""

    invocation_count: int


@dataclass(frozen=True)
class MockT3ExecutionPlan:
    """Validated identifiers only; credential and evidence references are excluded."""

    action_id: str
    stage: T3Stage
    source_asset_id: str
    destination_asset_id: str | None
    capability_id: str
    command_scope: tuple[str, ...]

    @classmethod
    def from_request(cls, request: T3ActionRequest) -> MockT3ExecutionPlan:
        return cls(
            action_id=request.action_id,
            stage=request.stage,
            source_asset_id=request.source_asset_id,
            destination_asset_id=request.destination_asset_id,
            capability_id=request.capability_id,
            command_scope=tuple(request.command_scope),
        )


@dataclass(frozen=True)
class MockT3Outcome:
    status: str
    mock_only: bool
    real_action_performed: bool
    action_id: str
    stage: str
    capability_id: str


class MockT3Executor(T3Executor):
    """Records invocation and returns a fixed result without performing any action."""

    def __init__(self) -> None:
        self.invocation_count = 0

    def run(self, plan: MockT3ExecutionPlan) -> MockT3Outcome:
        self.invocation_count += 1
        return MockT3Outcome(
            status="mock_completed",
            mock_only=True,
            real_action_performed=False,
            action_id=plan.action_id,
            stage=plan.stage.value,
            capability_id=plan.capability_id,
        )


@dataclass(frozen=True)
class LabSshExecutionPlan:
    action_id: str
    source_asset_id: str
    capability_id: str
    observation: LabObservation
    target: str
    port: int
    credential_handle: str
    timeout_seconds: float
    pinned_host_key: str


@dataclass(frozen=True)
class LabSshCredential:
    """One in-memory public-key credential; repr never exposes key material."""

    username: str
    private_key: Any

    def __repr__(self) -> str:
        return "LabSshCredential(username=<redacted>, private_key=<redacted>)"

    __str__ = __repr__


class LabSshCredentialResolver(ABC):
    @abstractmethod
    def resolve_for_lab_ssh(
        self, credential_handle: str, source_asset_id: str
    ) -> LabSshCredential: ...


@dataclass(frozen=True)
class LabSshConnection:
    target: str
    port: int
    timeout_seconds: float
    pinned_host_key: str


@dataclass(frozen=True)
class LabSshTransportResult:
    stdout: bytes
    stderr: bytes
    exit_status: int


class LabSshTransportError(RuntimeError):
    def __init__(
        self,
        rule: str,
        *,
        host_key_verified: bool = False,
        observation_started: bool = False,
    ):
        super().__init__("lab SSH transport failed")
        self.rule = rule
        self.host_key_verified = host_key_verified
        self.observation_started = observation_started


class LabSshObservationTransport(ABC):
    @abstractmethod
    def observe(
        self,
        connection: LabSshConnection,
        credential: LabSshCredential,
        observation: LabObservation,
    ) -> LabSshTransportResult: ...


class ParamikoLabSshTransport(LabSshObservationTransport):
    """Strict pinned-key SSH transport with one fixed observation and no fallback."""

    def observe(
        self,
        connection: LabSshConnection,
        credential: LabSshCredential,
        observation: LabObservation,
    ) -> LabSshTransportResult:
        try:
            import paramiko
        except ImportError as exc:
            raise LabSshTransportError("lab_ssh_dependency_unavailable") from exc

        command = _FIXED_COMMANDS.get(observation)
        if command is None:
            raise LabSshTransportError("lab_observation_not_permitted")
        entry = paramiko.hostkeys.HostKeyEntry.from_line(connection.pinned_host_key)
        if entry is None or entry.key is None:
            raise LabSshTransportError("lab_host_key_invalid")
        if not isinstance(credential.private_key, paramiko.PKey):
            raise LabSshTransportError("lab_credential_invalid")

        client = paramiko.SSHClient()
        stdout = stderr = None
        try:
            client.get_host_keys().add(
                connection.target,
                entry.key.get_name(),
                entry.key,
            )
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            try:
                client.connect(
                    hostname=connection.target,
                    port=connection.port,
                    username=credential.username,
                    pkey=credential.private_key,
                    timeout=connection.timeout_seconds,
                    banner_timeout=connection.timeout_seconds,
                    auth_timeout=connection.timeout_seconds,
                    allow_agent=False,
                    look_for_keys=False,
                )
            except paramiko.BadHostKeyException as exc:
                raise LabSshTransportError("lab_ssh_host_key_failed") from exc
            except paramiko.AuthenticationException as exc:
                raise LabSshTransportError(
                    "lab_ssh_authentication_failed",
                    host_key_verified=True,
                ) from exc
            except Exception as exc:
                raise LabSshTransportError("lab_ssh_connection_failed") from exc

            try:
                _, stdout, stderr = client.exec_command(
                    command,
                    timeout=connection.timeout_seconds,
                    get_pty=False,
                    environment=None,
                )
                stdout.channel.settimeout(connection.timeout_seconds)
                output = stdout.read(MAX_OBSERVATION_BYTES + 1)
                error = stderr.read(1)
                exit_status = stdout.channel.recv_exit_status()
            except Exception as exc:
                raise LabSshTransportError(
                    "lab_fixed_observation_failed",
                    host_key_verified=True,
                    observation_started=True,
                ) from exc
            return LabSshTransportResult(output, error, exit_status)
        except LabSshTransportError:
            raise
        finally:
            for stream in (stdout, stderr):
                if stream is not None:
                    stream.close()
            client.close()


@dataclass(frozen=True)
class LabT3Outcome:
    status: str
    rule: str
    mock_only: bool
    real_action_performed: bool
    arbitrary_command_exposed: bool
    action_id: str
    observation: str
    value: str | None
    trace_codes: tuple[str, ...]

    def result_document(self) -> dict:
        document = asdict(self)
        document.pop("trace_codes")
        return document


def valid_pinned_host_key(value: object) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    parts = value.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        return False
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(decoded) != 51:
        return False
    algorithm_length = struct.unpack(">I", decoded[:4])[0]
    key_length = struct.unpack(">I", decoded[15:19])[0]
    return (
        algorithm_length == 11
        and decoded[4:15] == b"ssh-ed25519"
        and key_length == 32
    )


def lab_target_is_locally_permitted(target: str) -> bool:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return True
    return not (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
    )


def _safe_observation_value(result: LabSshTransportResult) -> str:
    if (
        len(result.stdout) > MAX_OBSERVATION_BYTES
        or result.stderr
        or result.exit_status != 0
    ):
        raise ValueError("invalid observation result")
    text = result.stdout.decode("utf-8", errors="replace")
    text = _ANSI_ESCAPE.sub("", text)
    text = "".join(
        char
        for char in text
        if char in "\n\t" or not unicodedata.category(char).startswith("C")
    )
    lines = text.splitlines()
    if not lines or len(lines) > MAX_OBSERVATION_LINES:
        raise ValueError("invalid observation result")
    value = "\n".join(line.strip() for line in lines).strip()
    if not value:
        raise ValueError("invalid observation result")
    return value


class LabSshT3Executor(T3Executor):
    """One enabled, pinned-target, public-key SSH observation per consumed approval."""

    def __init__(
        self,
        resolver: LabSshCredentialResolver,
        transport: LabSshObservationTransport,
        *,
        enablement: str | None = None,
        permitted_target: str,
        timeout_seconds: float = LAB_TIMEOUT_SECONDS,
    ):
        self.resolver = resolver
        self.transport = transport
        self.enabled = enablement == "true"
        self.permitted_target = permitted_target
        self.timeout_seconds = timeout_seconds
        self.invocation_count = 0

    def run(self, plan: LabSshExecutionPlan) -> LabT3Outcome:
        self.invocation_count += 1
        codes = ["credential_resolution_started"]
        credential = None
        try:
            try:
                credential = self.resolver.resolve_for_lab_ssh(
                    plan.credential_handle,
                    plan.source_asset_id,
                )
                if (
                    not isinstance(credential, LabSshCredential)
                    or not credential.username
                    or credential.private_key is None
                ):
                    raise ValueError("invalid lab credential")
            except Exception:  # noqa: BLE001 - credential details must not escape
                codes.extend(("credential_resolution_failed", "lab_executor_closed"))
                return self._failure(plan, "lab_credential_resolution_failed", codes)
            codes.append("credential_resolution_completed")

            connection = LabSshConnection(
                target=plan.target,
                port=plan.port,
                timeout_seconds=plan.timeout_seconds,
                pinned_host_key=plan.pinned_host_key,
            )
            codes.append("ssh_connection_started")
            try:
                result = self.transport.observe(connection, credential, plan.observation)
            except LabSshTransportError as exc:
                if exc.host_key_verified:
                    codes.append("ssh_host_key_verified")
                elif exc.rule == "lab_ssh_host_key_failed":
                    codes.append("ssh_host_key_failed")
                if exc.observation_started:
                    codes.append("fixed_observation_started")
                codes.extend(("fixed_observation_failed", "lab_executor_closed"))
                return self._failure(plan, exc.rule, codes)
            except Exception:  # noqa: BLE001 - transport details must not escape
                codes.extend(("fixed_observation_failed", "lab_executor_closed"))
                return self._failure(plan, "lab_ssh_connection_failed", codes)

            codes.extend(("ssh_host_key_verified", "fixed_observation_started"))
            try:
                value = _safe_observation_value(result)
            except Exception:  # noqa: BLE001 - output details must not escape
                codes.extend(("fixed_observation_failed", "lab_executor_closed"))
                return self._failure(plan, "lab_observation_output_invalid", codes)
            codes.extend(("fixed_observation_completed", "lab_executor_closed"))
            return LabT3Outcome(
                status="lab_observation_completed",
                rule="lab_observation_completed",
                mock_only=False,
                real_action_performed=True,
                arbitrary_command_exposed=False,
                action_id=plan.action_id,
                observation=plan.observation.value,
                value=value,
                trace_codes=tuple(codes),
            )
        finally:
            credential = None

    @staticmethod
    def _failure(
        plan: LabSshExecutionPlan,
        rule: str,
        codes: list[str],
    ) -> LabT3Outcome:
        return LabT3Outcome(
            status="lab_observation_failed",
            rule=rule,
            mock_only=False,
            real_action_performed=False,
            arbitrary_command_exposed=False,
            action_id=plan.action_id,
            observation=plan.observation.value,
            value=None,
            trace_codes=tuple(codes),
        )
