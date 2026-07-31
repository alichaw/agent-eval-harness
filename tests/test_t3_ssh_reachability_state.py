import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.investigation.models import InvestigationState
from core.investigation.ssh_reachability import (
    CAPABILITY_ID,
    PROFILE_ID,
    SshReachabilityResult,
    produce_ssh_reachability_state,
)
from core.safety import KillSwitch
from core.t3.access import T3AuthorizedAccessProposal
from core.t3.runtime import compose_t3_runtime
from tests.test_t3_lab_executor import PINNED_HOST_KEY

ASSET_ID = "asset:winsrv2025-01"
TARGET = "192.0.2.25"


@dataclass
class FakeExecutor:
    state: str = "reachable"
    malformed: bool = False
    wrong_target: bool = False
    invocation_count: int = 0

    def probe(self, asset_id: str) -> SshReachabilityResult:
        self.invocation_count += 1
        if self.malformed:
            return SshReachabilityResult(asset_id, 0, "", "", "")
        target = "198.51.100.8" if self.wrong_target else TARGET
        binding = hashlib.sha256(f"{asset_id}\0{target}\0{22}".encode()).hexdigest()
        return SshReachabilityResult(asset_id, 22, "tcp", "ssh", self.state, binding)


def files(tmp_path: Path, *, denied=("198.51.100.0/24",), include_asset=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    assets = tmp_path / "assets.yaml"
    assets.write_text(
        "assets:\n"
        + (
            f'  "{ASSET_ID}":\n'
            "    asset_type: host\n"
            "    execution_scope: isolated_lab\n"
            "    platform: windows_openssh\n"
            "    ssh_port: 22\n"
            "    credential_ref: credential:ssh-winsrv2025-01\n"
            f'    target: "{TARGET}"\n'
            if include_asset
            else "  {}\n"
        )
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "default: deny\n"
        "allowed_tools: [t3-ssh-reachability]\n"
        f'allowed_targets: ["{TARGET}/32"]\n'
        f"denied_targets: {json.dumps(list(denied))}\n"
        "t3_allowed_capabilities:\n"
        "  - t3-authorized-access-bounded\n"
        "t3_allowed_stages:\n"
        "  - authorized_access\n"
    )
    runtime = tmp_path / "runtime.json"
    runtime.write_text(
        json.dumps(
            {
                "asset_id": ASSET_ID,
                "profile_id": "t3-authorized-access-bounded",
                "credential_ref": "credential:ssh-winsrv2025-01",
                "username": "poc_websvc",
                "private_key_path": "/operator/not-read-by-readiness",
                "pinned_host_key": PINNED_HOST_KEY,
                "assurance": {"profile": "poc"},
            }
        )
    )
    runtime.chmod(0o600)
    return assets, policy, runtime


def produce(tmp_path: Path, executor: FakeExecutor, **updates):
    assets, policy, runtime = files(
        tmp_path,
        denied=updates.pop("denied", ("198.51.100.0/24",)),
        include_asset=updates.pop("include_asset", True),
    )
    run = produce_ssh_reachability_state(
        asset_id=updates.pop("asset_id", ASSET_ID),
        assets_path=assets,
        profiles_path=Path(__file__).parents[1] / "profiles.yaml",
        policy_path=policy,
        runs_root=tmp_path / "runs",
        executor=executor,
        kill_switch=KillSwitch(tmp_path / "KILL"),
        **updates,
    )
    return run, assets, policy, runtime


def load_state(run: Path) -> InvestigationState:
    return InvestigationState.model_validate_json((run / "investigation_state.json").read_text())


def test_reachable_produces_serializable_state_accepted_by_t3a_composition(tmp_path):
    executor = FakeExecutor()
    run, assets, policy, runtime = produce(tmp_path, executor)
    state = load_state(run)
    assert CAPABILITY_ID in state.executed_capabilities
    assert state.evidence[0].facts == {
        "profile_id": PROFILE_ID,
        "port": 22,
        "open_ports": [22],
        "protocol": "tcp",
        "service": "ssh",
        "state": "reachable",
    }
    composition = compose_t3_runtime(
        proposal=T3AuthorizedAccessProposal(
            asset_id=ASSET_ID,
            profile_id="t3-authorized-access-bounded",
        ),
        runtime_config_path=runtime,
        assets_path=assets,
        profiles_path=Path(__file__).parents[1] / "profiles.yaml",
        policy_path=policy,
        investigation_state_path=run / "investigation_state.json",
    )
    assert composition.request.evidence_refs == [state.evidence[0].evidence_id]
    assert executor.invocation_count == 1
    assert json.loads((run / "result.json").read_text())["ssh_login_attempted"] is False


@pytest.mark.parametrize("state", ["unreachable", "error"])
def test_unreachable_or_error_does_not_satisfy_t3a(tmp_path, state):
    run, assets, policy, runtime = produce(tmp_path, FakeExecutor(state=state))
    produced = load_state(run)
    assert CAPABILITY_ID not in produced.executed_capabilities
    with pytest.raises(ValueError, match="prerequisite"):
        compose_t3_runtime(
            proposal=T3AuthorizedAccessProposal(
                asset_id=ASSET_ID,
                profile_id="t3-authorized-access-bounded",
            ),
            runtime_config_path=runtime,
            assets_path=assets,
            profiles_path=Path(__file__).parents[1] / "profiles.yaml",
            policy_path=policy,
            investigation_state_path=run / "investigation_state.json",
        )


def test_denied_target_precedes_allowlist_without_invocation(tmp_path):
    executor = FakeExecutor()
    assets, policy, _ = files(tmp_path, denied=("192.0.2.0/24",))
    with pytest.raises(ValueError, match="target_forbidden_zone"):
        produce_ssh_reachability_state(
            asset_id=ASSET_ID,
            assets_path=assets,
            profiles_path=Path(__file__).parents[1] / "profiles.yaml",
            policy_path=policy,
            runs_root=tmp_path / "runs",
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "KILL"),
        )
    assert executor.invocation_count == 0


def test_missing_denied_networks_fail_closed_without_invocation(tmp_path):
    executor = FakeExecutor()
    assets, policy, _ = files(tmp_path, denied=())
    with pytest.raises(ValueError, match="denied-target"):
        produce_ssh_reachability_state(
            asset_id=ASSET_ID,
            assets_path=assets,
            profiles_path=Path(__file__).parents[1] / "profiles.yaml",
            policy_path=policy,
            runs_root=tmp_path / "runs",
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "KILL"),
        )
    assert executor.invocation_count == 0


def test_unknown_asset_and_caller_execution_fields_rejected(tmp_path):
    executor = FakeExecutor()
    assets, policy, _ = files(tmp_path, include_asset=False)
    with pytest.raises(Exception, match="unknown asset"):
        produce_ssh_reachability_state(
            asset_id=ASSET_ID,
            assets_path=assets,
            profiles_path=Path(__file__).parents[1] / "profiles.yaml",
            policy_path=policy,
            runs_root=tmp_path / "runs",
            executor=executor,
            kill_switch=KillSwitch(tmp_path / "KILL"),
        )
    with pytest.raises(TypeError):
        produce(
            tmp_path / "injection",
            executor,
            target="203.0.113.8",
            port=2222,
            command="whoami",
        )
    assert executor.invocation_count == 0


def test_other_registered_asset_is_not_authorized(tmp_path):
    executor = FakeExecutor()
    with pytest.raises(ValueError, match="not authorized"):
        produce(tmp_path, executor, asset_id="asset:vm-lab-01")
    assert executor.invocation_count == 0


def test_missing_evidence_fields_fail_closed_and_no_credential_surface(tmp_path):
    executor = FakeExecutor(malformed=True)
    run, *_ = produce(tmp_path, executor)
    state = load_state(run)
    assert state.evidence[0].facts["state"] == "error"
    assert CAPABILITY_ID in state.failed_capabilities
    artifacts = "".join(item.read_text() for item in run.iterdir())
    assert "private_key" not in artifacts
    assert "credential:ssh-winsrv2025-01" not in artifacts


def test_executor_target_binding_must_match_asset_registry(tmp_path):
    run, *_ = produce(tmp_path, FakeExecutor(wrong_target=True))
    assert CAPABILITY_ID in load_state(run).failed_capabilities
