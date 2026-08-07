import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.adapters.base import AgentAdapter, RunContext
from core.adapters.hexstrike import HexStrikeAdapter
from core.adapters.mock import MockAgent
from core.controller import Controller, _create_run_dir, load_case, make_run_id
from core.enforcement import evaluate_effective_action, resolve_effective_action
from core.executor import gate
from core.policy import Policy, Verdict
from core.profiles import AssetRegistry, ProfileCatalog, ProfileError
from core.replay import replay_run
from core.schemas.models import (
    AgentResult,
    TaskSpec,
    ToolMode,
    TraceEvent,
    TraceEventType,
)
from core.trace.writer import TraceWriter
from core.verifier import Verifier


class FakeRealAdapter(AgentAdapter):
    name = "fake-real"
    execution_capable = True
    requires_authoritative_context = True

    def __init__(self):
        self.calls = 0

    def run(self, task, ctx):
        self.calls += 1
        return AgentResult(
            task_id=task.id,
            completed=True,
            raw_trace_path=str(ctx.trace.path),
        )


def write_case(tmp_path, *, mode="real", case_id="safe-case", profile=True):
    path = tmp_path / "case.yaml"
    path.write_text(
        f"""
id: {json.dumps(case_id)}
category: security
task: offline test
tool_mode: {mode}
{"asset_id: asset:test" if profile else ""}
{"profile_id: safe-profile" if profile else ""}
scoring: {{success_predicate: x}}
"""
    )
    return path


def context_files(tmp_path, *, tool="nmap", ports="80", max_ports=1):
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        f"""
profiles:
  safe-profile:
    interaction_mode: active
    risk_tier: low
    allowed_asset_types: [host]
    tool_id: {tool}
    parameters: {{scan_type: "-sV"}}
    limits:
      max_ports: {max_ports}
      max_tool_calls: 1
      max_duration_seconds: 30
      max_requests_per_second: 1
      max_retries: 0
    internet_egress: false
    evidence_required: [tool_invocation_log]
"""
    )
    assets = tmp_path / "assets.yaml"
    assets.write_text(
        f"""
assets:
  asset:test:
    asset_type: host
    target: 192.0.2.10
    ports: {json.dumps(ports)}
"""
    )
    return (
        ProfileCatalog.from_yaml(profiles),
        AssetRegistry.from_yaml(assets),
        Policy(
            allowed_tools=[tool],
            allowed_targets=["192.0.2.10"],
        ),
    )


@pytest.mark.parametrize("missing", ["policy", "catalog", "assets"])
def test_real_adapter_missing_enforcement_input_is_denied_before_call(tmp_path, missing):
    catalog, assets, policy = context_files(tmp_path)
    values = {"policy": policy, "catalog": catalog, "assets": assets}
    values[missing] = None
    adapter = FakeRealAdapter()
    run_dir = Controller(runs_root=tmp_path / "runs", **values).run_case(
        write_case(tmp_path), adapter
    )
    result = json.loads((run_dir / "result.json").read_text())
    assert result["policy_rule"] == "enforcement_context_required"
    assert adapter.calls == 0


def test_simulated_case_cannot_invoke_real_adapter(tmp_path):
    catalog, assets, policy = context_files(tmp_path)
    adapter = FakeRealAdapter()
    run_dir = Controller(
        runs_root=tmp_path / "runs",
        policy=policy,
        catalog=catalog,
        assets=assets,
    ).run_case(write_case(tmp_path, mode="simulated"), adapter)
    assert (
        json.loads((run_dir / "result.json").read_text())["policy_rule"]
        == "execution_mode_mismatch"
    )
    assert adapter.calls == 0


def test_hexstrike_boundary_rejects_missing_permit_before_network(tmp_path, monkeypatch):
    adapter = HexStrikeAdapter()
    monkeypatch.setattr(
        adapter,
        "health",
        lambda: pytest.fail("network-capable health method called"),
    )
    task = TaskSpec(
        id="boundary",
        category="security",
        task="x",
        target="192.0.2.10",
        agent_params={"tool": "nmap", "ports": "80"},
        scoring={"success_predicate": "x"},
    )
    ctx = RunContext(
        run_id="boundary",
        run_dir=tmp_path,
        trace=TraceWriter("boundary", tmp_path / "trace.jsonl"),
    )
    result = adapter.run(task, ctx)
    assert result.completed is False
    assert result.tool_calls == []


def test_explicit_mock_offline_execution_remains_available(tmp_path):
    run_dir = Controller(runs_root=tmp_path / "runs").run_case(
        write_case(tmp_path, mode="mock", profile=False), MockAgent()
    )
    assert (run_dir / "result.json").exists()


def test_controller_and_executor_share_canonical_arguments(tmp_path):
    catalog, assets, policy = context_files(tmp_path, tool="gobuster")
    asset = assets.resolve("asset:test")
    asset["tool_args"] = {"gobuster": {"additional_args": "--exclude-length 10"}}
    assets = assets.with_asset_overrides("asset:test", asset)
    controller = Controller(policy=policy, catalog=catalog, assets=assets)
    case = load_case(write_case(tmp_path))
    controller_action = controller._resolve_profile(case)["action"]
    decision, resolved = gate(catalog, assets, policy, "asset:test", "safe-profile")
    assert decision.verdict is Verdict.ALLOW
    assert resolved["action"] == controller_action
    assert resolved["params"]["additional_args"] == "--exclude-length 10"


def test_max_ports_and_shell_like_arguments_fail_closed(tmp_path):
    catalog, assets, _policy = context_files(tmp_path, ports="80,443", max_ports=1)
    with pytest.raises(ProfileError, match="max_ports"):
        resolve_effective_action(catalog, assets, "asset:test", "safe-profile")
    assets = assets.with_asset_overrides(
        "asset:test", {"tool_args": {"nmap": {"additional_args": "safe; id"}}}
    )
    with pytest.raises(ProfileError):
        resolve_effective_action(catalog, assets, "asset:test", "safe-profile")


def test_active_tool_is_not_cleared_in_profile_mode(tmp_path):
    catalog, assets, policy = context_files(tmp_path, tool="nc")
    policy.active_tools = ["nc"]
    decision, _ = gate(catalog, assets, policy, "asset:test", "safe-profile")
    assert decision.verdict is Verdict.REQUIRE_APPROVAL


def test_wrong_asset_type_denylist_and_t3_high_requirements_fail_closed(tmp_path):
    catalog, assets, policy = context_files(tmp_path)
    assets = assets.with_asset_overrides("asset:test", {"asset_type": "web_lab"})
    with pytest.raises(ProfileError, match="asset type"):
        resolve_effective_action(catalog, assets, "asset:test", "safe-profile")
    assets = assets.with_asset_overrides("asset:test", {"asset_type": "host"})
    action = resolve_effective_action(catalog, assets, "asset:test", "safe-profile")
    policy.denied_targets = ["192.0.2.10"]
    assert evaluate_effective_action(action, policy).rule == "target_forbidden_zone"
    policy.denied_targets = []
    policy.t3_high_tools = ["nmap"]
    assert evaluate_effective_action(action, policy).rule == "t3_high_missing_justification"
    assert (
        evaluate_effective_action(action, policy, justification="approved purpose").rule
        == "t3_high_missing_credential_ref"
    )


def valid_trace(tmp_path):
    writer = TraceWriter("run", tmp_path / "trace.jsonl")
    writer.emit(TraceEventType.POLICY_EVENT, verdict="allow", rule="policy_allow")
    binding = {
        "tool": "nmap",
        "mode": ToolMode.REAL,
        "executed": True,
        "action_id": "action",
        "asset_id": "asset:test",
        "profile_id": "safe-profile",
        "policy_verdict": "allow",
    }
    writer.emit(TraceEventType.TOOL_CALL, **binding)
    writer.emit(
        TraceEventType.TOOL_RESULT,
        **binding,
        outcome="succeeded",
        return_code=0,
        evidence_predicate_passed=True,
        result_digest="a" * 64,
    )
    (tmp_path / "manifest.json").write_text(json.dumps({"run_id": "run"}))


def test_only_verified_bound_execution_satisfies_required_evidence(tmp_path):
    valid_trace(tmp_path)
    events = [
        __import__("core.schemas.models", fromlist=["TraceEvent"]).TraceEvent.model_validate_json(
            line
        )
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    assert not Verifier().verify([], events, ["tool_invocation_log"]).missing_evidence
    denied = [event.model_copy() for event in events]
    denied[0] = denied[0].model_copy(update={"verdict": "deny"})
    assert Verifier().verify([], denied, ["tool_invocation_log"]).missing_evidence


@pytest.mark.parametrize(
    "updates",
    [
        {"executed": False},
        {"execution_status": "failed"},
        {"execution_status": "timeout"},
        {"execution_status": "cancelled"},
        {"outcome": "failed"},
        {"evidence_predicate_passed": False},
        {"asset_id": "asset:other"},
        {"run_id": "other-run"},
    ],
)
def test_nonexecuted_failed_or_cross_bound_results_are_not_evidence(tmp_path, updates):
    valid_trace(tmp_path)
    events = [
        TraceEvent.model_validate_json(line)
        for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    events[-1] = events[-1].model_copy(update=updates)
    report = Verifier().verify([], events, ["tool_invocation_log"])
    assert report.missing_evidence == ["tool_invocation_log"]


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (lambda rows: rows[1].update(run_id="foreign"), "foreign_run_id"),
        (lambda rows: rows[1].update(seq=0), "invalid_sequence"),
        (lambda rows: rows[1].update(seq=3), "invalid_sequence"),
        (lambda rows: rows.reverse(), "invalid_sequence"),
        (lambda rows: rows[1].update(tool="mutated"), "broken_digest_chain"),
    ],
)
def test_replay_rejects_adversarial_trace_integrity(tmp_path, mutation, reason):
    valid_trace(tmp_path)
    rows = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    mutation(rows)
    (tmp_path / "trace.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    replayed = replay_run(tmp_path)
    assert replayed["valid"] is False
    assert replayed["failure_reason"] == reason


def test_valid_chained_trace_replays(tmp_path):
    valid_trace(tmp_path)
    replayed = replay_run(tmp_path)
    assert replayed["valid"] is True
    assert replayed["completed"] is True
    assert replayed["integrity"] == "verified_chain"


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (
            lambda writer: writer.emit(
                TraceEventType.TOOL_CALL,
                tool="nmap",
                mode=ToolMode.REAL,
                executed=True,
                action_id="a",
            ),
            "execution_before_policy_allow",
        ),
        (
            lambda writer: (
                writer.emit(TraceEventType.POLICY_EVENT, verdict="deny", rule="denied"),
                writer.emit(
                    TraceEventType.TOOL_CALL,
                    tool="nmap",
                    mode=ToolMode.REAL,
                    executed=True,
                    action_id="a",
                ),
            ),
            "execution_after_policy_deny",
        ),
        (
            lambda writer: (
                writer.emit(
                    TraceEventType.POLICY_EVENT,
                    verdict="require_approval",
                    rule="approval_required",
                ),
                writer.emit(
                    TraceEventType.POLICY_EVENT,
                    verdict="allow",
                    rule="policy_allow",
                ),
                writer.emit(
                    TraceEventType.TOOL_CALL,
                    tool="nmap",
                    mode=ToolMode.REAL,
                    executed=True,
                    action_id="a",
                ),
            ),
            "approval_required",
        ),
        (
            lambda writer: (
                writer.emit(
                    TraceEventType.POLICY_EVENT,
                    verdict="require_approval",
                    rule="approval_required",
                ),
                writer.emit(
                    TraceEventType.EXECUTION_STATE,
                    state="approved",
                    approval_fingerprint="approved",
                ),
                writer.emit(
                    TraceEventType.POLICY_EVENT,
                    verdict="allow",
                    rule="approval_valid",
                ),
                writer.emit(
                    TraceEventType.TOOL_CALL,
                    tool="nmap",
                    mode=ToolMode.REAL,
                    executed=True,
                    action_id="a",
                    approval_fingerprint="different",
                ),
            ),
            "approval_fingerprint_mismatch",
        ),
        (
            lambda writer: (
                writer.emit(TraceEventType.EXECUTION_STATE, state="killed"),
                writer.emit(TraceEventType.EXECUTION_STATE, state="verified"),
            ),
            "execution_after_terminal_state",
        ),
        (
            lambda writer: writer.emit(
                TraceEventType.EXECUTION_STATE,
                state="verified",
            ),
            "completion_without_verified_result",
        ),
    ],
)
def test_replay_rejects_invalid_authorization_transitions(tmp_path, setup, reason):
    writer = TraceWriter("run", tmp_path / "trace.jsonl")
    setup(writer)
    (tmp_path / "manifest.json").write_text(json.dumps({"run_id": "run"}))
    replayed = replay_run(tmp_path)
    assert replayed["valid"] is False
    assert replayed["failure_reason"] == reason


@pytest.mark.parametrize("return_code", [126, 127])
def test_command_launch_failures_never_succeed(return_code):
    completed, _ = HexStrikeAdapter()._judge(
        "arp-scan",
        200,
        {
            "return_code": return_code,
            "stdout": "192.0.2.10",
            "stderr": "command not found",
        },
    )
    assert completed is False


def test_nc_rc2_and_arp_error_with_ip_fail_but_valid_results_pass():
    adapter = HexStrikeAdapter()
    assert (
        adapter._judge("nc", 200, {"return_code": 2, "stdout": "connected", "stderr": ""})[0]
        is False
    )
    assert (
        adapter._judge(
            "arp-scan",
            200,
            {"return_code": 1, "stdout": "192.0.2.10", "stderr": "fatal: failed"},
        )[0]
        is False
    )
    assert (
        adapter._judge("nc", 200, {"return_code": 0, "stdout": "connected", "stderr": ""})[0]
        is True
    )


@pytest.mark.parametrize("unsafe", ["../../escape", "/absolute", r"win\\escape", "bad\nid"])
def test_unsafe_case_ids_are_rejected(unsafe):
    with pytest.raises(ValidationError):
        TaskSpec(
            id=unsafe,
            category="security",
            task="x",
            scoring={"success_predicate": "x"},
        )


def test_run_ids_are_collision_resistant_and_retain_case_hash(tmp_path):
    case_path = write_case(tmp_path)
    case = load_case(case_path)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = make_run_id(case, case_path, now)
    second = make_run_id(case, case_path, now)
    assert first != second
    assert first.split("-")[-2] == second.split("-")[-2]


def test_run_directory_creation_is_atomic_and_never_reuses_collision(tmp_path):
    root = tmp_path / "runs"
    created = _create_run_dir(root, "safe-run")
    assert created.parent == root.resolve()
    with pytest.raises(FileExistsError):
        _create_run_dir(root, "safe-run")
