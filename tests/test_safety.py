"""Safety-control tests for approval binding, replay resistance, and kill switch."""

import time

import pytest

from core.adapters.base import RunContext
from core.executor import execute_profile
from core.policy import Policy
from core.profiles import AssetRegistry, ProfileCatalog
from core.safety import (
    ApprovalAuthority,
    ApprovalError,
    ExecutionState,
    KillSwitch,
    profile_fingerprint,
)
from core.schemas.models import AgentResult, TaskSpec, TraceEvent, TraceEventType
from core.trace.writer import TraceWriter


def _profile(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
profiles:
  approved-scan:
    interaction_mode: active
    risk_tier: medium
    allowed_asset_types: [host]
    tool_id: nmap
    parameters: {scan_type: "-sV"}
    approval_required: true
"""
    )
    return ProfileCatalog.from_yaml(path).get("approved-scan")


def test_approval_is_bound_to_asset_profile_and_hash(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)

    claims = authority.verify_and_consume(
        token,
        "asset:test",
        profile.profile_id,
        fingerprint,
    )

    assert claims.asset_id == "asset:test"


def test_approval_cannot_be_replayed(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)
    authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="already consumed"):
        authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)


def test_approval_rejects_wrong_asset_and_tampering(tmp_path):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="does not match"):
        authority.verify_and_consume(token, "asset:other", profile.profile_id, fingerprint)

    with pytest.raises(ApprovalError, match="signature"):
        authority.verify_and_consume(
            token[:-1] + "A", "asset:test", profile.profile_id, fingerprint
        )


def test_expired_approval_is_rejected(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    fingerprint = profile_fingerprint(profile)
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, fingerprint, ttl_seconds=1)
    monkeypatch.setattr(time, "time", lambda: 2_000_000_000)

    with pytest.raises(ApprovalError, match="expired"):
        authority.verify_and_consume(token, "asset:test", profile.profile_id, fingerprint)


def test_kill_switch_is_file_backed(tmp_path):
    switch = KillSwitch(tmp_path / "STOP")
    assert switch.engaged() is False
    switch.path.touch()
    assert switch.engaged() is True


class _Executor:
    name = "test-executor"

    def __init__(self):
        self.calls = 0

    def run(self, task, ctx):
        self.calls += 1
        return AgentResult(
            task_id=task.id,
            completed=True,
            final_output="ok",
            raw_trace_path=str(ctx.trace.path),
        )


def _execution_setup(tmp_path):
    profiles_path = tmp_path / "execution-profiles.yaml"
    profiles_path.write_text(
        """
profiles:
  approved-scan:
    interaction_mode: active
    risk_tier: medium
    allowed_asset_types: [host]
    tool_id: nmap
    parameters: {scan_type: "-sV"}
    approval_required: true
"""
    )
    assets_path = tmp_path / "assets.yaml"
    assets_path.write_text(
        """
assets:
  "asset:test":
    asset_type: host
    target: 192.0.2.10
    ports: "80"
"""
    )
    catalog = ProfileCatalog.from_yaml(profiles_path)
    assets = AssetRegistry.from_yaml(assets_path)
    policy = Policy(
        default="deny",
        allowed_tools=["nmap"],
        allowed_targets=["192.0.2.10/32"],
    )
    task = TaskSpec(
        id="safety",
        category="safety",
        task="approved scan",
        scoring={"success_predicate": "x"},
    )
    return catalog, assets, policy, task


def _context(tmp_path, **updates):
    context = RunContext(
        run_id="s",
        run_dir=tmp_path,
        trace=TraceWriter("s", tmp_path / "trace.jsonl"),
    )
    for key, value in updates.items():
        setattr(context, key, value)
    return context


def test_approval_required_profile_cannot_run_without_token(tmp_path):
    catalog, assets, policy, task = _execution_setup(tmp_path)
    executor = _Executor()

    result = execute_profile(
        executor, catalog, assets, policy, "asset:test", "approved-scan", task, _context(tmp_path)
    )

    assert result.admitted is False
    assert result.rule == "approval_token_required"
    assert executor.calls == 0


def test_valid_approval_runs_once_and_emits_states(tmp_path):
    catalog, assets, policy, task = _execution_setup(tmp_path)
    profile = catalog.get("approved-scan")
    authority = ApprovalAuthority(b"x" * 32, tmp_path / "spent")
    token = authority.issue("asset:test", profile.profile_id, profile_fingerprint(profile))
    context = _context(
        tmp_path,
        approval_authority=authority,
        approval_token=token,
    )
    executor = _Executor()

    result = execute_profile(
        executor, catalog, assets, policy, "asset:test", "approved-scan", task, context
    )

    assert result.admitted is True
    assert executor.calls == 1
    events = [
        TraceEvent.model_validate_json(line)
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    states = [event.state for event in events if event.type is TraceEventType.EXECUTION_STATE]
    assert states == ["proposed", "approved", "running", "verified"]


def test_kill_switch_blocks_before_execution(tmp_path):
    catalog, assets, policy, task = _execution_setup(tmp_path)
    stop_path = tmp_path / "STOP"
    stop_path.touch()
    executor = _Executor()

    result = execute_profile(
        executor,
        catalog,
        assets,
        policy,
        "asset:test",
        "approved-scan",
        task,
        _context(tmp_path, kill_switch=KillSwitch(stop_path)),
    )

    assert result.state is ExecutionState.KILLED
    assert executor.calls == 0
