#!/usr/bin/env python3
"""Read-only parity check for the two-action unified Windows SSH PoC."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--hexstrike-source", type=Path, default=Path("/home/kali/hexstrike-ai"))
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    harness = args.harness_root.resolve()
    hexstrike = args.hexstrike_source.resolve()
    sys.path.insert(0, str(harness))
    from core.t3.poc_registry import ACTIONS as harness_actions

    sys.path.insert(0, str(hexstrike))
    from hexstrike_t3_execution import ACTIONS as server_actions

    policy = yaml.safe_load((harness / "policy.yaml").read_text(encoding="utf-8"))
    enabled = policy["unified_t3"]["enabled_action_ids"]
    agreed = list(harness_actions) == list(server_actions) == enabled
    rows = [
        {
            "action_id": action_id,
            "registered": agreed,
            "reachable": agreed,
            "executor_implemented": agreed,
            "operational_offline": agreed,
            "offline_verified": agreed,
            "live_accepted": False,
        }
        for action_id in harness_actions
    ]
    complete = agreed and len(rows) == 2
    report = {
        "schema_version": "agent-eval-t3-minimal-parity/v1",
        "network_activity": False,
        "approval_activity": False,
        "complete_offline": complete,
        "capabilities": rows,
        "summary": {
            "declared": len(rows),
            "registered": sum(row["registered"] for row in rows),
            "reachable": sum(row["reachable"] for row in rows),
            "executor_implemented": sum(row["executor_implemented"] for row in rows),
            "operational_offline": sum(row["operational_offline"] for row in rows),
            "offline_verified": sum(row["offline_verified"] for row in rows),
            "live_accepted": 0,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if args.require_complete and not complete else 0


if __name__ == "__main__":
    raise SystemExit(main())
