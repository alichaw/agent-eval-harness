"""Capability-based profile resolution and policy interplay tests."""

import json
from pathlib import Path

import pytest

from core.adapters.mock import MockAgent
from core.controller import Controller
from core.executor import gate
from core.policy import Policy, Verdict
from core.profiles import AssetRegistry, ProfileCatalog, ProfileError
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
            "none",
        ],
        allowed_targets=[
            "juiceshop",
            "t1-target",
            "172.18.0.0/16",
            "192.168.56.10/32",
        ],
        max_cost_usd=1.0,
    )


def _trace_events(run_dir):
    trace_path = run_dir / "trace.jsonl"
    return [TraceEvent.model_validate_json(line) for line in trace_path.read_text().splitlines()]


def test_catalog_loads_and_carries_evidence():
    profile = _cat().get("tcp-service-inventory-low")

    assert profile.approval_required is True
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


def test_approval_profile_requires_approval():
    run_dir = _run("profile_tcp_inventory.yaml")
    result_path = run_dir / "result.json"
    result = json.loads(result_path.read_text())

    assert result["policy_verdict"] == "require_approval"

    events = _trace_events(run_dir)
    assert not any(event.type is TraceEventType.TOOL_CALL for event in events)


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
    assert resolved["target"] == "192.168.56.10"

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
