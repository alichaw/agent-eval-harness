"""Human-reviewed, explicit real T3-C acceptance entry point."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from core.safety import ApprovalAuthority, KillSwitch
from core.t3.impact import ACTION_ID, HexStrikeT3CExecutor, T3CAgentProposal, T3CConfig, run_t3c


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-isolated-lab", action="store_true")
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--t3a-result", required=True)
    parser.add_argument("--t3b-result", required=True)
    parser.add_argument("--approval-token-file", required=True)
    parser.add_argument("--approval-spent-dir", required=True)
    parser.add_argument("--kill-switch-file", required=True)
    args = parser.parse_args()
    if not args.confirm_isolated_lab:
        raise SystemExit("refusing real T3-C without --confirm-isolated-lab")
    secret = os.environ.get("HARNESS_APPROVAL_SECRET", "")
    if len(secret.encode()) < 32:
        raise SystemExit("HARNESS_APPROVAL_SECRET must contain at least 32 bytes")
    token_path = Path(args.approval_token_file)
    if stat.S_IMODE(token_path.stat().st_mode) & 0o077:
        raise SystemExit("approval token file must have mode 0600")
    token = token_path.read_text(encoding="utf-8").strip()
    config = T3CConfig.model_validate_json(Path(args.runtime_config).read_text(encoding="utf-8"))
    run_dir = run_t3c(
        proposal=T3CAgentProposal(action_id=ACTION_ID),
        config=config,
        t3a_path=Path(args.t3a_result),
        t3b_path=Path(args.t3b_result),
        authority=ApprovalAuthority(secret.encode(), args.approval_spent_dir),
        approval_token=token,
        executor=HexStrikeT3CExecutor(str(config.hexstrike_url)),
        kill_switch=KillSwitch(Path(args.kill_switch_file)),
    )
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    print(f"run dir: {run_dir}")
    print(f"result: {result['rule']}")
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
