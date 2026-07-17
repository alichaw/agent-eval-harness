"""tests/test_profiles.py — capability-based profile resolution + policy interplay."""

import json
from pathlib import Path

import pytest

from core.adapters.mock import MockAgent
from core.controller import Controller
from core.policy import Policy
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
        allowed_tools=["nmap", "gobuster", "none"],
        allowed_targets=["juiceshop", "172.18.0.0/16"],
        max_cost_usd=1.0,
    )


def test_catalog_loads_and_carries_evidence():
    p = _cat().get("tcp-service-inventory-low")
    assert p.approval_required is True
    assert "network_flow_log" in p.evidence_required  # W4 spec present


def test_unknown_profile_fail_closed():
    with pytest.raises(ProfileError):
        _cat().get("does-not-exist")


def test_unknown_asset_fail_closed():
    with pytest.raises(ProfileError):
        _assets().resolve("asset:nope")


def _run(case_name):
    ctrl = Controller(
        runs_root=ROOT / "runs_test", policy=_policy(), catalog=_cat(), assets=_assets()
    )
    return ctrl.run_case(ROOT / "cases" / case_name, MockAgent())


def test_approval_profile_requires_approval():
    run_dir = _run("profile_tcp_inventory.yaml")
    result = json.loads((run_dir / "result.json").read_text())
    assert result["policy_verdict"] == "require_approval"
    # agent not run
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]
    assert not any(e.type is TraceEventType.TOOL_CALL for e in events)


def test_low_impact_profile_allowed_and_runs():
    run_dir = _run("profile_http_metadata.yaml")
    events = [
        TraceEvent.model_validate_json(line)
        for line in (run_dir / "trace.jsonl").read_text().splitlines()
    ]
    pol = [e for e in events if e.type is TraceEventType.POLICY_EVENT]
    assert pol and pol[0].verdict == "allow"
    # allowed -> the (mock) agent actually ran
    assert any(e.type is TraceEventType.TOOL_CALL for e in events)
