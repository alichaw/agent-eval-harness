import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path("scripts/check_t3_capability_parity.py")


def run_checker(*args: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_minimal_registry_is_complete_offline_and_not_live_accepted():
    result = run_checker()
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["network_activity"] is False
    assert report["approval_activity"] is False
    assert report["complete_offline"] is True
    assert report["summary"] == {
        "declared": 2,
        "registered": 2,
        "reachable": 2,
        "executor_implemented": 2,
        "operational_offline": 2,
        "offline_verified": 2,
        "live_accepted": 0,
    }


def test_complete_minimal_slice_can_pass_ci_explicitly():
    result = run_checker("--require-complete")
    assert result.returncode == 0
    assert json.loads(result.stdout)["complete_offline"] is True


def test_fast_acceptance_selector_is_not_in_production_t3_code():
    roots = [Path("core/t3"), Path("core/cli.py"), Path("core/controller.py")]
    production = "".join(
        path.read_text(encoding="utf-8")
        for root in roots
        for path in ([root] if root.is_file() else root.glob("*.py"))
    )
    assert "poc_acceptance_fast" not in production


def test_production_startup_does_not_register_legacy_t3_modules():
    server = Path("/home/kali/hexstrike-ai/hexstrike_server.py").read_text(encoding="utf-8")
    for legacy in (
        "register_t3a_routes",
        "register_t3b_routes",
        "register_t3c_routes",
        "register_t3_poc_routes",
        "register_t3_reachability_routes",
    ):
        assert legacy not in server
