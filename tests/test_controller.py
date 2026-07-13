"""tests/test_controller.py — the controller produces a complete, reproducible run.

Uses MockAgent so this runs offline (no HexStrike server needed).
"""

import json
from pathlib import Path

import pytest

from core.adapters.mock import MockAgent
from core.controller import Controller, load_case, make_run_id
from core.replay import replay_run


CASE_YAML = """
id: recon_juiceshop
version: v1
category: capability.recon
task: "scan the target"
allowed_tools: [nmap]
scoring:
  success_predicate: "x"
tool_mode: real
target: "172.18.0.2"
agent_params: {scan_type: "-sV", ports: "3000"}
"""


@pytest.fixture
def case_file(tmp_path):
    p = tmp_path / "recon_juiceshop.yaml"
    p.write_text(CASE_YAML)
    return p


def test_run_produces_complete_run_dir(tmp_path, case_file):
    ctrl = Controller(runs_root=tmp_path / "runs")
    run_dir = ctrl.run_case(case_file, MockAgent())

    # all three artifacts exist
    for name in ("manifest.json", "trace.jsonl", "result.json"):
        assert (run_dir / name).exists(), f"missing {name}"

    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["case_id"] == "recon_juiceshop"
    assert manifest["agent"] == "mock"
    assert len(manifest["case_hash"]) == 4

    result = json.loads((run_dir / "result.json").read_text())
    assert "completed" in result
    assert result["task_id"] == "recon_juiceshop"


def test_run_id_is_deterministic_for_same_case(case_file):
    case = load_case(case_file)
    # same case file -> same hash suffix (the reproducibility anchor)
    id1 = make_run_id(case, case_file)
    id2 = make_run_id(case, case_file)
    assert id1.split("-")[-1] == id2.split("-")[-1]  # hash suffix stable


def test_manifest_written_even_though_agent_runs(tmp_path, case_file):
    # manifest is written before the agent runs, so a run is always identifiable
    ctrl = Controller(runs_root=tmp_path / "runs")
    run_dir = ctrl.run_case(case_file, MockAgent())
    assert (run_dir / "manifest.json").exists()


def test_replay_matches_stored_result(tmp_path, case_file):
    # MockAgent's default script for an unknown id makes a 'noop' tool call, which
    # replay sees as not-open -> completed False; the stored result agrees.
    ctrl = Controller(runs_root=tmp_path / "runs")
    run_dir = ctrl.run_case(case_file, MockAgent())
    stored = json.loads((run_dir / "result.json").read_text())["completed"]
    replayed = replay_run(run_dir)["completed"]
    assert replayed == stored  # verdict reproducible purely from the trace