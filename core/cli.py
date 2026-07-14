"""core/cli.py — command-line entry point.

    harness run cases/recon_juiceshop.yaml --agent hexstrike
    harness replay runs/<run_id>

Wired to pyproject [project.scripts]:  harness = "core.cli:main"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.controller import Controller


def _make_agent(name: str):
    """Instantiate an adapter by name. Add new agents here — the ONLY place the CLI
    needs to know concrete adapters; everything else uses the base contract."""
    if name == "mock":
        from core.adapters.mock import MockAgent
        return MockAgent()
    if name == "hexstrike":
        from core.adapters.hexstrike import HexStrikeAdapter
        return HexStrikeAdapter()
    raise SystemExit(f"unknown agent '{name}' (choices: mock, hexstrike)")


def cmd_run(args) -> int:
    agent = _make_agent(args.agent)
    policy = None
    if args.policy:
        from core.policy import Policy
        policy = Policy.from_yaml(args.policy)
    run_dir = Controller(runs_root=args.runs_root, policy=policy).run_case(args.case, agent)
    result = json.loads((run_dir / "result.json").read_text())
    print(f"run dir : {run_dir}")
    print(f"agent   : {args.agent}")
    if result.get("policy_denied"):
        print(f"POLICY  : DENIED [{result['policy_rule']}] {result['policy_detail']}")
    print(f"completed: {result['completed']}   elapsed: {result['elapsed_s']}s")
    print(f"artifacts: manifest.json  trace.jsonl  result.json")
    return 0 if result["completed"] else 1


def cmd_replay(args) -> int:
    """Reproducibility check: recompute the verdict PURELY from the stored trace,
    touching nothing live. Proves a run is auditable after the fact."""
    from core.replay import replay_run
    run_dir = Path(args.run_dir)
    recomputed = replay_run(run_dir)
    stored = json.loads((run_dir / "result.json").read_text())
    match = recomputed["completed"] == stored["completed"]
    print(f"stored   completed = {stored['completed']}")
    print(f"replayed completed = {recomputed['completed']}")
    print("MATCH ✅" if match else "MISMATCH ❌ (result is not reproducible from trace)")
    return 0 if match else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run a case with an agent")
    p_run.add_argument("case", help="path to a case YAML")
    p_run.add_argument("--agent", default="mock", help="mock | hexstrike")
    p_run.add_argument("--runs-root", default="runs")
    p_run.add_argument("--policy", default=None, help="path to policy.yaml (enables the policy gate)")
    p_run.set_defaults(func=cmd_run)

    p_replay = sub.add_parser("replay", help="recompute a run's verdict from its trace")
    p_replay.add_argument("run_dir", help="path to runs/<run_id>")
    p_replay.set_defaults(func=cmd_replay)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())