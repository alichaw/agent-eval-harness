import inspect
import json
from pathlib import Path

import pytest

from core.controller import Controller
from core.policy import Policy
from core.profiles import AssetRegistry
from core.schemas.models import TraceEvent
from core.t3.executor import (
    LAB_EXECUTION_SCOPE,
    LAB_PLATFORM,
    LAB_SSH_CAPABILITY,
    LAB_SSH_METHOD,
    LAB_SSH_PORT,
    MAX_OBSERVATION_BYTES,
    LabObservation,
    LabSshCredential,
    LabSshCredentialResolver,
    LabSshObservationTransport,
    LabSshT3Executor,
    LabSshTransportError,
    LabSshTransportResult,
)
from core.t3.models import T3ActionRequest, T3Stage, t3_action_fingerprint
from tests.test_t3_controller import approval, authority, initial_state

LAB_TARGET = "lab-host.invalid"
PINNED_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
CREDENTIAL_HANDLE = "lab-credential-reference"
SYNTHETIC_KEY_MATERIAL = "synthetic-private-key-material"


class FakeResolver(LabSshCredentialResolver):
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = []

    def resolve_for_lab_ssh(self, credential_handle, source_asset_id):
        self.calls.append((credential_handle, source_asset_id))
        if self.fail:
            raise RuntimeError("synthetic-resolver-detail")
        return LabSshCredential("approved-observer", SYNTHETIC_KEY_MATERIAL)


class FakeTransport(LabSshObservationTransport):
    def __init__(self, result=None, error=None):
        self.result = result or LabSshTransportResult(b"observer\n", b"", 0)
        self.error = error
        self.calls = []
        self.closed = False

    def observe(self, connection, credential, observation):
        self.calls.append((connection, credential, observation))
        try:
            if self.error is not None:
                raise self.error
            return self.result
        finally:
            self.closed = True


def lab_assets(**asset_updates):
    asset = {
        "asset_type": "host",
        "target": LAB_TARGET,
        "execution_scope": LAB_EXECUTION_SCOPE,
        "platform": LAB_PLATFORM,
        "ssh_port": LAB_SSH_PORT,
        "ssh_host_key": PINNED_HOST_KEY,
    }
    asset.update(asset_updates)
    return AssetRegistry({"asset-source": asset})


def lab_policy(**updates):
    values = {
        "allowed_targets": [LAB_TARGET],
        "t3_allowed_capabilities": [LAB_SSH_CAPABILITY],
        "t3_allowed_stages": [T3Stage.INITIAL_ACCESS.value],
    }
    values.update(updates)
    return Policy(**values)


def lab_request(observation=LabObservation.IDENTITY, **updates):
    values = {
        "action_id": "lab-observation-action",
        "stage": T3Stage.INITIAL_ACCESS,
        "source_asset_id": "asset-source",
        "capability_id": LAB_SSH_CAPABILITY,
        "method": LAB_SSH_METHOD,
        "finding_refs": ["finding-1"],
        "evidence_refs": ["evidence-1"],
        "credential_ref": CREDENTIAL_HANDLE,
        "command_scope": [observation.value],
        "written_justification": "Verify one fixed observation in the isolated lab.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def executor(resolver, transport, *, enablement="true", permitted_target=LAB_TARGET):
    return LabSshT3Executor(
        resolver,
        transport,
        enablement=enablement,
        permitted_target=permitted_target,
    )


def controller(tmp_path, approval_authority, **updates):
    values = {
        "runs_root": tmp_path / "runs",
        "policy": lab_policy(),
        "assets": lab_assets(),
        "approval_authority": approval_authority,
    }
    values.update(updates)
    return Controller(**values)


def artifacts(run_dir):
    result = json.loads((run_dir / "result.json").read_text())
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]
    serialized = "".join(
        (run_dir / name).read_text() for name in ("manifest.json", "trace.jsonl", "result.json")
    )
    return result, events, serialized


def assert_token_unconsumed(approval_authority, token, request):
    fingerprint = t3_action_fingerprint(request)
    approval_authority.verify_and_consume(
        token,
        request.source_asset_id,
        request.capability_id,
        fingerprint,
        action_fingerprint=fingerprint,
    )


@pytest.mark.parametrize("enablement", [None, "", "false", "TRUE", "True", "1"])
def test_lab_execution_is_disabled_unless_literal_true(tmp_path, enablement):
    request = lab_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver()
    transport = FakeTransport()
    lab_executor = executor(resolver, transport, enablement=enablement)

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    result, _, _ = artifacts(run_dir)

    assert result["rule"] == "lab_execution_disabled"
    assert lab_executor.invocation_count == 0
    assert resolver.calls == []
    assert transport.calls == []
    assert_token_unconsumed(approval_authority, token, request)


@pytest.mark.parametrize(
    ("observation", "stdout", "expected"),
    [
        (LabObservation.IDENTITY, b"approved-observer\n", "approved-observer"),
        (LabObservation.HOSTNAME, b"isolated-node\n", "isolated-node"),
    ],
)
def test_fixed_lab_observation_completes_after_approval(tmp_path, observation, stdout, expected):
    request = lab_request(observation)
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver()
    transport = FakeTransport(LabSshTransportResult(stdout, b"", 0))
    lab_executor = executor(resolver, transport)

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    result, events, serialized = artifacts(run_dir)

    assert result["status"] == "lab_observation_completed"
    assert result["approval_consumed"] is False
    assert result["lab_executor_invoked"] is True
    assert result["mock_executor_invoked"] is False
    assert result["lab_outcome"]["observation"] == observation.value
    assert result["lab_outcome"]["value"] == expected
    assert result["lab_outcome"]["arbitrary_command_exposed"] is False
    assert lab_executor.invocation_count == 1
    assert len(resolver.calls) == len(transport.calls) == 1
    connection, credential, selected = transport.calls[0]
    assert selected is observation
    assert connection.target == LAB_TARGET
    assert connection.port == 22
    assert connection.pinned_host_key == PINNED_HOST_KEY
    assert credential.username == "approved-observer"
    assert transport.closed is True
    rules = [event.rule for event in events]
    assert rules.index("t3_policy_gate_passed") < rules.index("credential_resolution_started")
    assert rules.index("ssh_connection_started") < rules.index("ssh_host_key_verified")
    assert rules[-1] == "t3_final_result"
    for forbidden in (
        token,
        CREDENTIAL_HANDLE,
        SYNTHETIC_KEY_MATERIAL,
        PINNED_HOST_KEY,
        request.model_dump_json(),
        "id -un",
    ):
        assert forbidden not in serialized
    assert_token_unconsumed(approval_authority, token, request)


@pytest.mark.parametrize(
    ("asset_updates", "request_updates", "executor_target", "policy_updates"),
    [
        ({"execution_scope": None}, {}, LAB_TARGET, {}),
        ({"execution_scope": "production"}, {}, LAB_TARGET, {}),
        ({"asset_type": "service"}, {}, LAB_TARGET, {}),
        ({"platform": "unknown"}, {}, LAB_TARGET, {}),
        ({"ssh_port": 2222}, {}, LAB_TARGET, {}),
        ({"ssh_host_key": ""}, {}, LAB_TARGET, {}),
        ({"ssh_host_key": "not-a-host-key"}, {}, LAB_TARGET, {}),
        ({}, {"credential_ref": None}, LAB_TARGET, {}),
        ({}, {"command_scope": ["unknown"]}, LAB_TARGET, {}),
        ({}, {"capability_id": "other.capability"}, LAB_TARGET, {}),
        ({}, {"stage": T3Stage.PRIVILEGE_ESCALATION}, LAB_TARGET, {}),
        ({}, {}, "other-host.invalid", {}),
        ({"target": "127.0.0.1"}, {}, "127.0.0.1", {"allowed_targets": ["127.0.0.1"]}),
        ({}, {}, LAB_TARGET, {"allowed_targets": []}),
        (
            {},
            {},
            LAB_TARGET,
            {"denied_targets": [LAB_TARGET]},
        ),
    ],
)
def test_lab_asset_request_and_policy_restrictions_are_preapproval(
    tmp_path, asset_updates, request_updates, executor_target, policy_updates
):
    request = lab_request(**request_updates)
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver()
    transport = FakeTransport()
    lab_executor = executor(resolver, transport, permitted_target=executor_target)

    run_dir = controller(
        tmp_path,
        approval_authority,
        assets=lab_assets(**asset_updates),
        policy=lab_policy(**policy_updates),
    ).run_t3_action(request, initial_state(), lab_executor, token)
    result, _, _ = artifacts(run_dir)

    assert result["completed"] is False
    assert lab_executor.invocation_count == 0
    assert resolver.calls == []
    assert transport.calls == []
    assert_token_unconsumed(approval_authority, token, request)


def test_lateral_destination_is_never_admitted_to_lab_executor(tmp_path):
    request = lab_request(
        stage=T3Stage.LATERAL_MOVEMENT,
        destination_asset_id="asset-destination",
    )
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver()
    transport = FakeTransport()
    lab_executor = executor(resolver, transport)
    registry = lab_assets()
    registry._assets["asset-destination"] = {
        "asset_type": "host",
        "target": "other-lab-host.invalid",
    }

    run_dir = controller(tmp_path, approval_authority, assets=registry).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    assert artifacts(run_dir)[0]["rule"] == "lab_target_not_permitted"
    assert lab_executor.invocation_count == 0
    assert_token_unconsumed(approval_authority, token, request)


def test_unresolved_source_and_missing_lab_marker_are_preapproval(tmp_path):
    for registry, request in (
        (AssetRegistry({}), lab_request()),
        (
            AssetRegistry(
                {
                    "asset-source": {
                        "asset_type": "host",
                        "target": LAB_TARGET,
                        "platform": LAB_PLATFORM,
                        "ssh_port": LAB_SSH_PORT,
                        "ssh_host_key": PINNED_HOST_KEY,
                    }
                }
            ),
            lab_request(),
        ),
    ):
        approval_authority = authority(tmp_path)
        token = approval(approval_authority, request)
        resolver = FakeResolver()
        transport = FakeTransport()
        lab_executor = executor(resolver, transport)

        run_dir = controller(
            tmp_path,
            approval_authority,
            assets=registry,
        ).run_t3_action(request, initial_state(), lab_executor, token)

        assert artifacts(run_dir)[0]["completed"] is False
        assert lab_executor.invocation_count == 0
        assert resolver.calls == []
        assert transport.calls == []
        assert_token_unconsumed(approval_authority, token, request)


def test_resolver_failure_consumes_approval_without_connecting(tmp_path):
    request = lab_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver(fail=True)
    transport = FakeTransport()
    lab_executor = executor(resolver, transport)

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    result, _, serialized = artifacts(run_dir)

    assert result["rule"] == "lab_credential_resolution_failed"
    assert lab_executor.invocation_count == 1
    assert len(resolver.calls) == 1
    assert transport.calls == []
    assert "synthetic-resolver-detail" not in serialized
    assert_token_unconsumed(approval_authority, token, request)


@pytest.mark.parametrize(
    "error",
    [
        LabSshTransportError("lab_ssh_connection_failed"),
        LabSshTransportError("lab_ssh_authentication_failed", host_key_verified=True),
        LabSshTransportError("lab_ssh_host_key_failed"),
        LabSshTransportError(
            "lab_fixed_observation_failed",
            host_key_verified=True,
            observation_started=True,
        ),
    ],
)
def test_transport_failures_are_safe_single_attempts(tmp_path, error):
    request = lab_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    resolver = FakeResolver()
    transport = FakeTransport(error=error)
    lab_executor = executor(resolver, transport)

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    result, _, serialized = artifacts(run_dir)

    assert result["rule"] == error.rule
    assert len(resolver.calls) == len(transport.calls) == 1
    assert transport.closed is True
    assert "lab SSH transport failed" not in serialized
    assert_token_unconsumed(approval_authority, token, request)


@pytest.mark.parametrize(
    "result",
    [
        LabSshTransportResult(b"x" * (MAX_OBSERVATION_BYTES + 1), b"", 0),
        LabSshTransportResult(b"1\n2\n3\n4\n5\n", b"", 0),
        LabSshTransportResult(b"value\n", b"private-error", 0),
        LabSshTransportResult(b"", b"", 0),
        LabSshTransportResult(b"value\n", b"", 1),
    ],
)
def test_invalid_output_fails_bounded_and_closed(tmp_path, result):
    request = lab_request()
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    transport = FakeTransport(result)
    lab_executor = executor(FakeResolver(), transport)

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request, initial_state(), lab_executor, token
    )
    stored, _, serialized = artifacts(run_dir)

    assert stored["rule"] == "lab_observation_output_invalid"
    assert transport.closed is True
    assert "private-error" not in serialized


def test_output_decoding_and_control_sanitization_is_deterministic(tmp_path):
    request = lab_request(LabObservation.HOSTNAME)
    approval_authority = authority(tmp_path)
    token = approval(approval_authority, request)
    output = b"\x1b[31misolated\xff-node\x00\x1b[0m\n"
    transport = FakeTransport(LabSshTransportResult(output, b"", 0))

    run_dir = controller(tmp_path, approval_authority).run_t3_action(
        request,
        initial_state(),
        executor(FakeResolver(), transport),
        token,
    )
    result, _, _ = artifacts(run_dir)

    assert result["status"] == "lab_observation_completed"
    assert result["lab_outcome"]["value"] == "isolated�-node"


def test_no_arbitrary_command_surface_or_shell_process_api():
    request_fields = set(T3ActionRequest.model_fields)
    forbidden_fields = {
        "raw_command",
        "command",
        "args",
        "shell",
        "script",
        "executable",
        "environment",
    }
    assert request_fields.isdisjoint(forbidden_fields)
    assert list(inspect.signature(LabSshT3Executor.run).parameters) == ["self", "plan"]
    assert list(inspect.signature(LabSshObservationTransport.observe).parameters) == [
        "self",
        "connection",
        "credential",
        "observation",
    ]
    source = Path("core/t3/executor.py").read_text()
    for forbidden in ("subprocess", "os.system", "shell=True", "sshpass"):
        assert forbidden not in source
