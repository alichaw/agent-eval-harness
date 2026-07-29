import inspect
import json

import pytest
from pydantic import ValidationError

from core.controller import Controller, load_case
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog
from core.replay import replay_run
from core.safety import ApprovalAuthority, ApprovalError, KillSwitch
from core.schemas.models import TraceEvent
from core.t3.access import (
    T3_ACCESS_CAPABILITY,
    T3_ACCESS_METHOD,
    BoundedLabSshT3Executor,
    BoundedSshSession,
    BoundedSshTransport,
    T3AccessProposal,
    T3CommandId,
    materialize_t3_access_request,
    t3_access_approval_fingerprint,
)
from core.t3.executor import (
    LabSshCredential,
    LabSshCredentialResolver,
    LabSshTransportError,
    LabSshTransportResult,
)
from core.t3.models import T3ActionRequest, T3Stage
from tests.test_t3_controller import authority, initial_state
from tests.test_t3_lab_executor import LAB_TARGET, PINNED_HOST_KEY

CREDENTIAL_REF = "credential:test-isolated-ssh"
SYNTHETIC_SECRET = "synthetic-in-memory-key-value"


class Resolver(LabSshCredentialResolver):
    def __init__(self, error=False):
        self.error = error
        self.calls = 0

    def resolve_for_lab_ssh(self, credential_handle, source_asset_id):
        self.calls += 1
        if self.error:
            raise RuntimeError("resolver-sensitive-detail")
        return LabSshCredential("synthetic-user", SYNTHETIC_SECRET)


class Session(BoundedSshSession):
    def __init__(self, outcomes=None, close_error=False, kill_file=None):
        self.outcomes = list(outcomes or [])
        self.close_error = close_error
        self.kill_file = kill_file
        self.calls = []
        self.closed = False

    def observe(self, command_id):
        self.calls.append(command_id)
        if self.kill_file is not None and len(self.calls) == 1:
            self.kill_file.touch()
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return LabSshTransportResult(b"bounded-value\n", b"", 0)

    def close(self):
        self.closed = True
        if self.close_error:
            raise RuntimeError("cleanup-sensitive-detail")


class Transport(BoundedSshTransport):
    def __init__(self, session=None, error=None):
        self.session = session or Session()
        self.error = error
        self.calls = 0
        self.connections = []

    def open(self, connection, credential, platform):
        self.calls += 1
        self.connections.append((connection, platform))
        if self.error:
            raise self.error
        return self.session


def request(**updates):
    values = {
        "action_id": "t3-action-1",
        "stage": T3Stage.INITIAL_ACCESS,
        "source_asset_id": "asset-source",
        "capability_id": T3_ACCESS_CAPABILITY,
        "method": T3_ACCESS_METHOD,
        "finding_refs": ["finding-1"],
        "evidence_refs": ["evidence-1"],
        "credential_ref": CREDENTIAL_REF,
        "command_scope": ["current_identity", "host_identity", "privilege_context"],
        "written_justification": "Verify bounded access and privilege context.",
    }
    values.update(updates)
    return T3ActionRequest(**values)


def assets(**updates):
    record = {
        "asset_type": "host",
        "target": LAB_TARGET,
        "ports": "22",
        "execution_scope": "isolated_lab",
        "platform": "windows_openssh",
        "ssh_port": 22,
        "ssh_host_key": PINNED_HOST_KEY,
    }
    record.update(updates)
    return AssetRegistry({"asset-source": record})


def policy(**updates):
    values = {
        "allowed_targets": [LAB_TARGET],
        "t3_allowed_capabilities": [T3_ACCESS_CAPABILITY],
        "t3_allowed_stages": ["initial_access"],
    }
    values.update(updates)
    return Policy(**values)


def approval(authority: ApprovalAuthority, action: T3ActionRequest):
    fingerprint = t3_access_approval_fingerprint(action)
    return authority.issue(
        action.source_asset_id,
        action.capability_id,
        fingerprint,
        credential_id=action.credential_ref or "",
        action_fingerprint=fingerprint,
    )


def run(tmp_path, action, executor, token, auth, **controller_updates):
    values = {
        "runs_root": tmp_path / "runs",
        "policy": policy(),
        "assets": assets(),
        "approval_authority": auth,
    }
    values.update(controller_updates)
    return Controller(**values).run_t3_action(action, initial_state(), executor, token)


def read(run_dir):
    result = json.loads((run_dir / "result.json").read_text())
    serialized = "".join(
        (run_dir / name).read_text() for name in ("manifest.json", "trace.jsonl", "result.json")
    )
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]
    return result, serialized, events


def make_executor(resolver, transport, **updates):
    values = {"enablement": "true", "permitted_target": LAB_TARGET}
    values.update(updates)
    return BoundedLabSshT3Executor(resolver, transport, **values)


def assert_unconsumed(auth, token, action):
    fingerprint = t3_access_approval_fingerprint(action)
    auth.verify_and_consume(
        token,
        action.source_asset_id,
        action.capability_id,
        fingerprint,
        credential_id=action.credential_ref or "",
        action_fingerprint=fingerprint,
    )


def test_valid_t3_access_uses_one_session_and_replays_without_execution(tmp_path):
    action = request()
    auth = authority(tmp_path)
    token = approval(auth, action)
    resolver = Resolver()
    session = Session()
    transport = Transport(session)
    executor = make_executor(resolver, transport)

    run_dir = run(tmp_path, action, executor, token, auth)
    result, serialized, events = read(run_dir)

    assert result["completed"] is True
    assert result["lab_outcome"]["assessment_succeeded"] is True
    assert result["lab_outcome"]["commands_succeeded"] == 3
    assert result["lab_outcome"]["session_closed"] is True
    assert result["lab_outcome"]["credential_lease_invalidated"] is True
    assert resolver.calls == transport.calls == executor.invocation_count == 1
    assert session.calls == list(T3CommandId)
    assert session.closed is True
    before = (resolver.calls, transport.calls)
    replayed = replay_run(run_dir)
    assert replayed["assessment_succeeded"] is True
    assert (resolver.calls, transport.calls) == before
    rules = [event.rule for event in events if event.rule]
    assert rules.index("t3_approval_verified") < rules.index("credential_resolution_started")
    for forbidden in (token, CREDENTIAL_REF, SYNTHETIC_SECRET, PINNED_HOST_KEY, "whoami /groups"):
        assert forbidden not in serialized
    with pytest.raises(ApprovalError, match="already consumed"):
        assert_unconsumed(auth, token, action)


@pytest.mark.parametrize("enablement", [None, "", "false", "TRUE", "1"])
def test_disabled_execution_preserves_approval(tmp_path, enablement):
    action = request()
    auth = authority(tmp_path)
    token = approval(auth, action)
    resolver, transport = Resolver(), Transport()
    executor = make_executor(resolver, transport, enablement=enablement)
    result, _, _ = read(run(tmp_path, action, executor, token, auth))
    assert result["rule"] == "lab_execution_disabled"
    assert resolver.calls == transport.calls == executor.invocation_count == 0
    assert_unconsumed(auth, token, action)


@pytest.mark.parametrize(
    "updates",
    [
        {"execution_scope": None},
        {"execution_scope": "production"},
        {"platform": "posix"},
        {"ssh_port": 2222},
        {"ssh_host_key": ""},
        {"target": "127.0.0.1"},
    ],
)
def test_asset_boundary_denials_precede_approval(tmp_path, updates):
    action = request()
    auth = authority(tmp_path)
    token = approval(auth, action)
    resolver, transport = Resolver(), Transport()
    result, _, _ = read(
        run(
            tmp_path,
            action,
            make_executor(resolver, transport, permitted_target=updates.get("target", LAB_TARGET)),
            token,
            auth,
            assets=assets(**updates),
            policy=policy(allowed_targets=[updates.get("target", LAB_TARGET)]),
        )
    )
    assert result["completed"] is False
    assert resolver.calls == transport.calls == 0
    assert_unconsumed(auth, token, action)


def test_credential_mismatch_is_denied_before_resolution(tmp_path):
    action = request()
    auth = authority(tmp_path)
    fingerprint = t3_access_approval_fingerprint(action)
    token = auth.issue(
        action.source_asset_id,
        action.capability_id,
        fingerprint,
        credential_id="credential:different-reference",
        action_fingerprint=fingerprint,
    )
    resolver, transport = Resolver(), Transport()
    result, serialized, _ = read(
        run(tmp_path, action, make_executor(resolver, transport), token, auth)
    )
    assert result["rule"] == "t3_approval_invalid"
    assert resolver.calls == transport.calls == 0
    assert CREDENTIAL_REF not in serialized


@pytest.mark.parametrize(
    ("transport_error", "expected"),
    [
        (LabSshTransportError("lab_ssh_authentication_failed"), "lab_ssh_authentication_failed"),
        (LabSshTransportError("lab_ssh_host_key_failed"), "lab_ssh_host_key_failed"),
        (LabSshTransportError("lab_ssh_connection_failed"), "lab_ssh_connection_failed"),
    ],
)
def test_authentication_failures_are_safe_and_consumed(tmp_path, transport_error, expected):
    action = request(command_scope=["current_identity"])
    auth = authority(tmp_path)
    token = approval(auth, action)
    resolver, transport = Resolver(), Transport(error=transport_error)
    result, serialized, _ = read(
        run(tmp_path, action, make_executor(resolver, transport), token, auth)
    )
    assert result["completed"] is False
    assert result["rule"] == expected
    assert result["lab_outcome"]["authentication_succeeded"] is False
    assert transport.calls == 1
    assert "lab SSH transport failed" not in serialized
    with pytest.raises(ApprovalError, match="already consumed"):
        assert_unconsumed(auth, token, action)


def test_nonzero_command_and_cleanup_failure_are_not_success(tmp_path):
    for session in (
        Session([LabSshTransportResult(b"value\n", b"", 1)]),
        Session(close_error=True),
    ):
        action = request(command_scope=["current_identity"])
        auth = authority(tmp_path)
        token = approval(auth, action)
        result, serialized, _ = read(
            run(tmp_path, action, make_executor(Resolver(), Transport(session)), token, auth)
        )
        assert result["completed"] is False
        assert result["lab_outcome"]["assessment_succeeded"] is False
        assert "cleanup-sensitive-detail" not in serialized


def test_timeout_is_not_success_and_still_closes_session(tmp_path):
    session = Session([LabSshTransportError("timed_out")])
    action = request(command_scope=["current_identity"])
    auth = authority(tmp_path)
    token = approval(auth, action)
    result, _, _ = read(
        run(tmp_path, action, make_executor(Resolver(), Transport(session)), token, auth)
    )
    assert result["status"] == "timed_out"
    assert result["completed"] is False
    assert result["lab_outcome"]["assessment_succeeded"] is False
    assert result["lab_outcome"]["session_closed"] is True
    assert session.closed is True


def test_kill_switch_blocks_next_command_and_closes(tmp_path):
    kill_file = tmp_path / "KILL"
    session = Session(kill_file=kill_file)
    action = request(command_scope=["current_identity", "host_identity"])
    auth = authority(tmp_path)
    token = approval(auth, action)
    executor = make_executor(Resolver(), Transport(session), kill_switch=KillSwitch(kill_file))
    result, _, _ = read(run(tmp_path, action, executor, token, auth))
    outcome = result["lab_outcome"]
    assert outcome["stopped_by_kill_switch"] is True
    assert outcome["commands_attempted"] == 1
    assert outcome["session_closed"] is True
    assert outcome["credential_lease_invalidated"] is True
    assert session.closed is True


def test_kill_switch_before_approval_blocks_credential_use(tmp_path):
    kill_file = tmp_path / "KILL"
    kill_file.touch()
    switch = KillSwitch(kill_file)
    action = request(command_scope=["current_identity"])
    auth = authority(tmp_path)
    token = approval(auth, action)
    resolver, transport = Resolver(), Transport()
    executor = make_executor(resolver, transport, kill_switch=switch)
    result, _, _ = read(
        run(
            tmp_path,
            action,
            executor,
            token,
            auth,
            kill_switch=switch,
        )
    )
    assert result["rule"] == "kill_switch_engaged"
    assert resolver.calls == transport.calls == executor.invocation_count == 0
    assert_unconsumed(auth, token, action)


def test_agent_proposal_and_executor_have_no_arbitrary_command_surface():
    proposal = T3AccessProposal(
        asset_id="asset:winsrv2025-01",
        profile_id=T3_ACCESS_CAPABILITY,
        objective="Verify bounded access",
        command_ids=["current_identity"],
    )
    assert proposal.command_ids == [T3CommandId.CURRENT_IDENTITY]
    forbidden = {
        "raw_command",
        "command",
        "args",
        "shell",
        "script",
        "port",
        "target",
        "username",
        "password",
        "private_key",
        "timeout",
    }
    assert forbidden.isdisjoint(T3AccessProposal.model_fields)
    with pytest.raises(ValidationError):
        T3AccessProposal(
            asset_id="asset:winsrv2025-01",
            profile_id=T3_ACCESS_CAPABILITY,
            objective="Verify bounded access",
            command_ids=["whoami; hostname"],
        )
    assert list(inspect.signature(BoundedSshSession.observe).parameters) == ["self", "command_id"]
    derived = materialize_t3_access_request(
        # Test fixture adjustment only; model_copy bypasses production revalidation.
        proposal.model_copy(update={"asset_id": "asset-source"}),
        action_id="derived-action",
        state=initial_state(),
        assets=assets(credential_ref=CREDENTIAL_REF),
    )
    assert derived.credential_ref == CREDENTIAL_REF
    assert derived.command_scope == ["current_identity"]


def test_t3_cases_and_profile_are_repository_compatible():
    catalog = ProfileCatalog.from_yaml("profiles.yaml")
    profile = catalog.get(T3_ACCESS_CAPABILITY)
    assert profile.approval_required is True
    assert profile.risk_tier.value == "high"
    primary = load_case("cases/profile_t3_access_bounded.yaml")
    assert primary.asset_id == "asset:winsrv2025-01"
    assert primary.command_ids == ["current_identity", "host_identity", "privilege_context"]
