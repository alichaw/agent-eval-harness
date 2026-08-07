"""Capability-based profile resolution and policy interplay tests."""

import json
from pathlib import Path

import pytest

from core.adapters.mock import MockAgent
from core.controller import Controller
from core.enforcement import effective_approval_fingerprint, resolve_effective_action
from core.executor import gate
from core.policy import Policy, Verdict
from core.profiles import AssetRegistry, ProfileCatalog, ProfileError
from core.safety import ApprovalAuthority, ExecutionState, KillSwitch
from core.schemas.models import TraceEvent, TraceEventType

ROOT = Path(__file__).resolve().parent.parent


def _cat():
    return ProfileCatalog.from_yaml(ROOT / "profiles.yaml")


def _assets():
    return AssetRegistry.from_yaml(ROOT / "assets.yaml")


def _policy():
    return Policy(
        default="deny",
        allowed_tools=[
            "nmap",
            "gobuster",
            "httpx",
            "nuclei",
            "smb-posture",
            "smb-anonymous-access",
            "smb-ms17-010-check",
            "rdp-posture",
            "smbmap",
            "rpcclient",
            "nbtscan",
            "netexec",
            "none",
        ],
        allowed_targets=[
            "juiceshop",
            "192.0.2.10/32",
            "172.18.0.0/16",
            "192.0.2.10/32",
        ],
        max_cost_usd=1.0,
    )


def _trace_events(run_dir):
    trace_path = run_dir / "trace.jsonl"
    return [TraceEvent.model_validate_json(line) for line in trace_path.read_text().splitlines()]


def test_catalog_loads_and_carries_evidence():
    profile = _cat().get("tcp-service-inventory-low")

    assert profile.approval_required is False
    assert "network_flow_log" in profile.evidence_required


def test_unknown_profile_fail_closed():
    with pytest.raises(ProfileError):
        _cat().get("does-not-exist")


def test_unknown_asset_fail_closed():
    with pytest.raises(ProfileError):
        _assets().resolve("asset:nope")


def _run(case_name):
    controller = Controller(
        runs_root=ROOT / "runs_test",
        policy=_policy(),
        catalog=_cat(),
        assets=_assets(),
    )
    case_path = ROOT / "cases" / case_name
    return controller.run_case(case_path, MockAgent())


def test_t2_profile_runs_after_policy_gate_without_approval():
    run_dir = _run("profile_tcp_inventory.yaml")
    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text())

    assert result["agent_reported_completed"] is True

    events = _trace_events(run_dir)
    assert any(event.type is TraceEventType.TOOL_CALL for event in events)


def test_low_impact_profile_allowed_and_runs():
    run_dir = _run("profile_http_metadata.yaml")
    events = _trace_events(run_dir)

    policy_events = [event for event in events if event.type is TraceEventType.POLICY_EVENT]

    assert policy_events
    assert policy_events[0].verdict == "allow"
    assert any(event.type is TraceEventType.TOOL_CALL for event in events)


def test_httpx_t1_profile_resolves_to_authorised_vm():
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:vm-lab-01",
        "http-fingerprint-low",
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None
    assert resolved["tool"] == "httpx"
    assert resolved["target"] == _assets().resolve("asset:vm-lab-01")["target"]

    profile = resolved["profile"]
    assert profile.approval_required is False
    assert profile.risk_tier.value == "low"
    assert profile.internet_egress is False


def test_httpx_t1_profile_uses_structured_parameters():
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:vm-lab-01",
        "http-fingerprint-low",
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None

    params = resolved["params"]

    assert params["probe"] is True
    assert params["tech_detect"] is True
    assert params["status_code"] is True
    assert params["title"] is True
    assert params["web_server"] is True
    assert params["threads"] == 10

    # Raw/free-form flags must not be part of this profile.
    assert "additional_args" not in params
    assert "raw_command" not in params
    assert "custom_flags" not in params


def test_direct_t2_profile_does_not_consume_supplied_approval(tmp_path):
    catalog = _cat()
    assets = _assets()
    profile = catalog.get("tcp-service-inventory-low")
    authority = ApprovalAuthority(b"a" * 32, tmp_path / "spent")
    token = authority.issue(
        "asset:t1-target",
        profile.profile_id,
        effective_approval_fingerprint(
            resolve_effective_action(catalog, assets, "asset:t1-target", profile.profile_id)
        ),
        action_fingerprint=resolve_effective_action(
            catalog, assets, "asset:t1-target", profile.profile_id
        ).fingerprint,
    )
    controller = Controller(
        runs_root=tmp_path / "runs",
        policy=_policy(),
        catalog=catalog,
        assets=assets,
        approval_token=token,
        approval_authority=authority,
    )

    run_dir = controller.run_case(
        ROOT / "cases" / "profile_tcp_inventory.yaml",
        MockAgent(),
    )
    events = _trace_events(run_dir)
    states = [event.state for event in events if event.type is TraceEventType.EXECUTION_STATE]

    assert ExecutionState.APPROVED.value not in states
    assert ExecutionState.RUNNING.value in states
    assert any(event.type is TraceEventType.TOOL_CALL for event in events)


def test_direct_profile_kill_switch_blocks_before_tool(tmp_path):
    kill_file = tmp_path / "KILL"
    kill_file.touch()
    controller = Controller(
        runs_root=tmp_path / "runs",
        policy=_policy(),
        catalog=_cat(),
        assets=_assets(),
        kill_switch=KillSwitch(kill_file),
    )

    run_dir = controller.run_case(
        ROOT / "cases" / "profile_http_metadata.yaml",
        MockAgent(),
    )
    result = json.loads((run_dir / "result.json").read_text())
    events = _trace_events(run_dir)

    assert result["policy_rule"] == "kill_switch_engaged"
    assert not any(event.type is TraceEventType.TOOL_CALL for event in events)
    assert any(
        event.type is TraceEventType.EXECUTION_STATE and event.state == ExecutionState.KILLED.value
        for event in events
    )


def test_late_kill_switch_does_not_relabel_completed_adapter(tmp_path):
    from core.schemas.models import AgentResult

    class CompleteThenKill:
        name = "complete_then_kill"

        def run(self, task, ctx):
            ctx.kill_switch.path.touch()
            return AgentResult(
                task_id=task.id,
                completed=True,
                tool_calls=[],
                final_output="completed before switch",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

    kill_file = tmp_path / "KILL"
    controller = Controller(
        runs_root=tmp_path / "runs",
        policy=_policy(),
        catalog=_cat(),
        assets=_assets(),
        kill_switch=KillSwitch(kill_file),
    )

    run_dir = controller.run_case(
        ROOT / "cases" / "profile_http_metadata.yaml",
        CompleteThenKill(),
    )
    states = [
        event.state
        for event in _trace_events(run_dir)
        if event.type is TraceEventType.EXECUTION_STATE
    ]

    assert states[-1] == ExecutionState.VERIFIED.value


def test_bounded_nuclei_profile_does_not_allow_and_has_no_raw_flags():
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:web-lab-01",
        "web-vulnerability-scan-bounded",
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None
    assert resolved["tool"] == "nuclei"
    profile = resolved["profile"]
    assert profile.approval_required is False
    assert profile.risk_tier.value == "medium"

    params = resolved["params"]
    assert params["template_set"] == "baseline-web-v1"
    assert params["rate_limit"] == 5
    assert params["concurrency"] == 1
    assert params["timeout"] == 5
    assert "additional_args" not in params
    assert "templates" not in params
    assert "template_url" not in params


@pytest.mark.parametrize(
    ("profile_id", "tool"),
    [
        ("smb-posture-assessment", "smb-posture"),
        ("smb-anonymous-access-check", "smb-anonymous-access"),
        ("smb-ms17-010-check", "smb-ms17-010-check"),
        ("rdp-posture-assessment", "rdp-posture"),
    ],
)
def test_smb_profiles_allow_and_expose_no_commands(profile_id, tool):
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:vm-lab-01",
        profile_id,
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None
    assert resolved["tool"] == tool
    assert resolved["profile"].approval_required is False
    params = resolved["params"]
    assert "command" not in params
    assert "scripts" not in params
    assert "username" not in params
    assert "password" not in params
    assert "additional_args" not in params


@pytest.mark.parametrize(
    ("profile_id", "tool"),
    [
        ("smb-share-enum-low", "smbmap"),
        ("smb-user-enum-rid-low", "rpcclient"),
        ("ad-null-session-posture", "netexec"),
    ],
)
def test_ad_t2_profiles_allow_and_expose_no_raw_flags(profile_id, tool):
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:vm-lab-01",
        profile_id,
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None
    assert resolved["tool"] == tool
    profile = resolved["profile"]
    assert profile.approval_required is False
    assert profile.risk_tier.value == "medium"

    params = resolved["params"]
    assert "raw_command" not in params
    assert "custom_flags" not in params
    assert "password" not in params
    assert "additional_args" not in params


def test_netbios_name_scan_profile_is_low_risk_and_autonomous():
    decision, resolved = gate(
        _cat(),
        _assets(),
        _policy(),
        "asset:vm-lab-01",
        "netbios-name-scan",
    )

    assert decision.verdict is Verdict.ALLOW
    assert resolved is not None
    assert resolved["tool"] == "nbtscan"
    profile = resolved["profile"]
    assert profile.approval_required is False
    assert profile.risk_tier.value == "low"
