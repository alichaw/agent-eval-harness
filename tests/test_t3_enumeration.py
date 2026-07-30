import json
from dataclasses import replace

import pytest
from pydantic import ValidationError

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, ApprovalError, KillSwitch
from core.t3.binding import RuntimeBinding, canonical_digest, host_key_identity
from core.t3.enumeration import (
    T3B_PROFILE,
    WINDOWS_ACTION_REGISTRY,
    ExecutionMode,
    T3APrerequisite,
    T3BExecutionPlan,
    T3BExecutor,
    T3BProposal,
    WindowsActionId,
    action_registry_digest,
    build_bindings,
    replay_t3b,
    run_t3b,
    verify_observation,
)
from core.t3.executor import LabSshCredential, LabSshCredentialResolver, LabSshTransportResult

ASSET = {
    "asset_type": "host",
    "target": "lab.invalid",
    "platform": "windows_openssh",
    "execution_scope": "isolated_lab",
    "ssh_port": 22,
    "ssh_host_key": "ssh-ed25519 " + "A" * 68,
}


class FakeResolver(LabSshCredentialResolver):
    def __init__(self, *, resolve_error=False, invalidate_error=False):
        self.calls = 0
        self.resolve_error = resolve_error
        self.invalidate_error = invalidate_error

    def resolve_for_lab_ssh(self, credential_handle, source_asset_id):
        self.calls += 1
        if self.resolve_error:
            raise RuntimeError("fake authentication material unavailable")
        return LabSshCredential("fake-user", "fake-key-secret")

    def invalidate_for_lab_ssh(self, credential_handle, source_asset_id):
        if self.invalidate_error:
            raise RuntimeError("fake invalidation failure")
        return True


class FakeSession:
    def __init__(self, outputs, kill_file=None, close_error=False):
        self.outputs = list(outputs)
        self.actions = []
        self.kill_file = kill_file
        self.close_error = close_error
        self.closed = False

    def execute_registered(self, definition):
        self.actions.append(definition)
        result = self.outputs.pop(0)
        if self.kill_file and len(self.actions) == 1:
            self.kill_file.touch()
        return result

    def close(self):
        if self.close_error:
            raise RuntimeError("fake cleanup failure")
        self.closed = True


class FakeTransport:
    execution_mode = ExecutionMode.OFFLINE_MOCK
    network_capable = False
    transport_type = "offline_fake"

    def __init__(self, session):
        self.session = session
        self.calls = 0

    def open(self, connection, credential):
        self.calls += 1
        return self.session


def prerequisite(**updates):
    values = dict(
        evidence_ref="t3a-run:original",
        run_id="original",
        asset_id="asset-1",
        runtime_binding_fingerprint=runtime_binding().fingerprint,
        evidence_fingerprint="e" * 64,
        observed_at="2026-01-01T00:00:00+00:00",
        original_verified_evidence=True,
        authentication_succeeded=True,
        host_identity_matched=True,
        current_identity_observed=True,
        privilege_context_observed=True,
        session_closed=True,
        cleanup_succeeded=True,
        credential_lease_invalidated=True,
        profile_id="t3-authorized-access-bounded",
        stage="authorized_access",
    )
    values.update(updates)
    return T3APrerequisite(**values)


def proposal(*actions):
    return T3BProposal(
        asset_id="asset-1",
        profile_id=T3B_PROFILE,
        objective="Collect approved read-only observations",
        command_ids=actions or [WindowsActionId.OS_VERSION],
    )


def bindings(p=None, prereq=None, registry=WINDOWS_ACTION_REGISTRY):
    return build_bindings(
        p or proposal(),
        asset=ASSET,
        profile_fingerprint="profile-1",
        runtime_binding_fingerprint=runtime_binding().fingerprint,
        credential_ref="credential:fake",
        prerequisite=prereq or prerequisite(),
        registry=registry,
    )


def plan(p=None, prereq=None):
    selected = p or proposal()
    selected_prerequisite = prereq or prerequisite()
    bound = bindings(selected, selected_prerequisite)
    return T3BExecutionPlan(
        "asset-1",
        ASSET["target"],
        22,
        ASSET["ssh_host_key"],
        "credential:fake",
        selected_prerequisite.run_id,
        runtime_binding(),
        bound,
        tuple(WINDOWS_ACTION_REGISTRY[x] for x in selected.command_ids),
    )


def runtime_binding():
    algorithm, fingerprint = host_key_identity(ASSET["ssh_host_key"])
    return RuntimeBinding(
        asset_id="asset-1",
        target_identity=canonical_digest({"asset_id": "asset-1", "target": ASSET["target"]}),
        host=ASSET["target"],
        port=22,
        credential_ref="credential:fake",
        principal="fake-user",
        host_key_algorithm=algorithm,
        host_key_fingerprint=fingerprint,
        transport_type="offline_fake",
        runtime_config_digest="runtime-digest",
        asset_registry_digest="asset-digest",
        policy_digest="policy-digest",
        profile_digest="profile-digest",
        prerequisite_stage="authorized_access",
        prerequisite_capability="t3-authorized-access-bounded",
        session_limits_digest="limits-digest",
        action_registry_digest="t3a-registry-digest",
    )


def result(stdout, code=0, stderr=b""):
    return LabSshTransportResult(stdout.encode(), stderr, code)


def os_output():
    return json.dumps({"Caption": "Windows Server", "Version": "10.0", "BuildNumber": "1"})


@pytest.mark.parametrize(
    "field",
    ["command", "args", "shell", "target", "credential", "port", "ssh_options", "powershell"],
)
def test_agent_cannot_supply_executable_or_transport_fields(field):
    value = proposal().model_dump(mode="json")
    value[field] = "forbidden"
    with pytest.raises(ValidationError):
        T3BProposal.model_validate(value)


def test_unknown_wrong_stage_duplicates_and_count_fail_closed():
    with pytest.raises(ValidationError):
        T3BProposal.model_validate({**proposal().model_dump(), "unknown": True})
    with pytest.raises(ValidationError):
        proposal(WindowsActionId.OS_VERSION, WindowsActionId.OS_VERSION)
    with pytest.raises(ValidationError):
        T3BProposal(
            asset_id="asset-1",
            profile_id=T3B_PROFILE,
            objective="x",
            command_ids=[x.value for x in WindowsActionId] + ["windows_running_processes"],
        )
    with pytest.raises(ValidationError):
        T3BProposal(
            asset_id="asset-1",
            profile_id="t3-access-bounded",
            objective="x",
            command_ids=[WindowsActionId.OS_VERSION],
        )


def test_registry_is_complete_unique_immutable_and_order_is_bound():
    assert set(WINDOWS_ACTION_REGISTRY) == set(WindowsActionId)
    assert len({x.digest for x in WINDOWS_ACTION_REGISTRY.values()}) == len(WindowsActionId)
    assert all(
        x.read_only and x.enabled and isinstance(x.argv, tuple)
        for x in WINDOWS_ACTION_REGISTRY.values()
    )
    forward = bindings(proposal(WindowsActionId.OS_VERSION, WindowsActionId.RUNNING_SERVICES))
    reverse = bindings(proposal(WindowsActionId.RUNNING_SERVICES, WindowsActionId.OS_VERSION))
    assert forward.fingerprint != reverse.fingerprint


def test_registry_drift_invalidates_approval(tmp_path):
    original = bindings()
    drifted_registry = dict(WINDOWS_ACTION_REGISTRY)
    drifted_registry[WindowsActionId.OS_VERSION] = replace(
        drifted_registry[WindowsActionId.OS_VERSION], verifier="changed"
    )
    drifted = bindings(registry=drifted_registry)
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        "asset-1",
        T3B_PROFILE,
        original.fingerprint,
        credential_id="credential:fake",
        action_fingerprint=original.fingerprint,
    )
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(
            token,
            "asset-1",
            T3B_PROFILE,
            drifted.fingerprint,
            credential_id="credential:fake",
            action_fingerprint=drifted.fingerprint,
        )
    assert action_registry_digest(drifted_registry) != action_registry_digest()


@pytest.mark.parametrize(
    "updates",
    [
        {"asset_id": "other"},
        {"authentication_succeeded": False},
        {"host_identity_matched": False},
        {"current_identity_observed": False},
        {"privilege_context_observed": False},
        {"session_closed": False},
        {"cleanup_succeeded": False},
        {"original_verified_evidence": False},
    ],
)
def test_verified_same_asset_t3a_prerequisite_required(updates):
    with pytest.raises(ValueError):
        bindings(prereq=prerequisite(**updates))


def test_t3a_approval_cannot_authorize_t3b(tmp_path):
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue("asset-1", "t3-access-bounded", "t3a", action_fingerprint="t3a")
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(
            token,
            "asset-1",
            T3B_PROFILE,
            bindings().fingerprint,
            credential_id="credential:fake",
            action_fingerprint=bindings().fingerprint,
        )


@pytest.mark.parametrize(
    ("action", "payload"),
    [
        (WindowsActionId.OS_VERSION, {"Caption": "Windows", "Version": "1", "BuildNumber": "2"}),
        (WindowsActionId.NETWORK_CONFIGURATION, {"InterfaceAlias": "Ethernet", "IPv4Address": []}),
        (WindowsActionId.LISTENING_PORTS, {"LocalAddress": "0.0.0.0", "LocalPort": 443}),
        (WindowsActionId.RUNNING_SERVICES, {"Name": "Example", "Status": "Running"}),
        (WindowsActionId.INSTALLED_HOTFIXES, {"HotFixID": "KB000001"}),
    ],
)
def test_each_registered_action_verifier(action, payload):
    status, summary = verify_observation(action, json.dumps(payload), False)
    assert status == "verified"
    assert summary


def test_zero_exit_without_observation_and_missing_hotfix_are_inconclusive():
    assert verify_observation(WindowsActionId.OS_VERSION, "{}", False)[0] == "inconclusive"
    status, summary = verify_observation(WindowsActionId.INSTALLED_HOTFIXES, "[]", False)
    assert status == "inconclusive"
    assert "vulnerability" in summary


def test_one_session_each_action_once_and_observations_do_not_expand_scope():
    selected = proposal(WindowsActionId.NETWORK_CONFIGURATION, WindowsActionId.LISTENING_PORTS)
    session = FakeSession(
        [
            result(json.dumps({"InterfaceAlias": "Ethernet", "IPv4Address": "203.0.113.10"})),
            result(json.dumps({"LocalAddress": "0.0.0.0", "LocalPort": 9999})),
        ]
    )
    transport, resolver = FakeTransport(session), FakeResolver()
    outcome = T3BExecutor(resolver, transport).run(plan(selected))
    assert outcome.completed
    assert transport.calls == resolver.calls == 1
    assert [x.action_id for x in session.actions] == list(selected.command_ids)
    assert plan(selected).asset_id == "asset-1"


def test_kill_between_actions_prevents_later_action(tmp_path):
    selected = proposal(WindowsActionId.OS_VERSION, WindowsActionId.RUNNING_SERVICES)
    kill_file = tmp_path / "KILL"
    session = FakeSession([result(os_output())], kill_file)
    outcome = T3BExecutor(
        FakeResolver(), FakeTransport(session), kill_switch=KillSwitch(kill_file)
    ).run(plan(selected))
    assert outcome.stopped_by_kill_switch
    assert len(session.actions) == 1
    assert not outcome.completed


def test_output_truncation_and_cleanup_failure_prevent_verification():
    huge = os_output() + ("x" * 20_000)
    truncated = T3BExecutor(FakeResolver(), FakeTransport(FakeSession([result(huge)]))).run(plan())
    assert truncated.action_evidence[0].stdout_truncated
    assert not truncated.completed
    failed = T3BExecutor(
        FakeResolver(), FakeTransport(FakeSession([result(os_output())], close_error=True))
    ).run(plan())
    assert failed.residual_session_uncertainty
    assert not failed.completed
    assert failed.credential_lease_invalidated


def test_credential_resolution_and_invalidation_fail_closed():
    resolution = T3BExecutor(FakeResolver(resolve_error=True), FakeTransport(FakeSession([]))).run(
        plan()
    )
    assert not resolution.authentication_succeeded
    assert not resolution.completed
    invalidation = T3BExecutor(
        FakeResolver(invalidate_error=True),
        FakeTransport(FakeSession([result(os_output())])),
    ).run(plan())
    assert not invalidation.credential_lease_invalidated
    assert not invalidation.completed


def test_approval_single_use_run_and_replay_are_offline(tmp_path):
    bound, prereq = bindings(), prerequisite()
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        "asset-1",
        T3B_PROFILE,
        bound.fingerprint,
        credential_id="credential:fake",
        action_fingerprint=bound.fingerprint,
    )
    resolver, transport = FakeResolver(), FakeTransport(FakeSession([result(os_output())]))
    run_dir = run_t3b(
        plan=plan(),
        prerequisite=prereq,
        executor=T3BExecutor(resolver, transport),
        authority=authority,
        approval_token=token,
        runs_root=tmp_path / "runs",
    )
    before = (resolver.calls, transport.calls)
    replay = replay_t3b(
        run_dir,
        bound,
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )
    assert replay["completed"]
    assert (resolver.calls, transport.calls) == before == (1, 1)
    serialized = "".join(
        (run_dir / x).read_text() for x in ("manifest.json", "trace.jsonl", "result.json")
    )
    assert "fake-key-secret" not in serialized
    with pytest.raises(ApprovalError):
        authority.verify_and_consume(
            token,
            "asset-1",
            T3B_PROFILE,
            bound.fingerprint,
            credential_id="credential:fake",
            action_fingerprint=bound.fingerprint,
        )
