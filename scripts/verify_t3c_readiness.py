"""Offline-only readiness verification for one reviewed T3-C acceptance run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from core.artifacts import ArtifactSealAuthority
from core.safety import ApprovalAuthority, KillSwitch
from core.t3.impact import ACTION_ID, T3CConfig, binding, validate_readiness


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--hexstrike-config", required=True)
    parser.add_argument("--t3b-result", required=True)
    parser.add_argument("--approval-spent-dir", required=True)
    parser.add_argument("--approval-token-file", required=True)
    parser.add_argument("--kill-switch-file", required=True)
    args = parser.parse_args()
    secret = os.environ.get("HARNESS_APPROVAL_SECRET", "")
    if len(secret.encode()) < 32:
        raise SystemExit("FAIL: HARNESS_APPROVAL_SECRET must contain at least 32 bytes")
    config = T3CConfig.model_validate_json(Path(args.runtime_config).read_text(encoding="utf-8"))
    hexstrike = json.loads(Path(args.hexstrike_config).read_text(encoding="utf-8"))
    expected = {
        "scenario_id": config.scenario_id,
        "source_asset_id": config.source_asset_id,
        "destination_asset_id": config.destination_asset_id,
        "destination_target": config.destination_target,
        "credential_ref": config.credential_ref,
        "proof_marker": config.proof_marker,
        "rollback_checkpoint": config.rollback_checkpoint,
        "isolated_lab": config.isolated_lab,
        "rollback_ready": config.rollback_ready,
    }
    if any(hexstrike.get(key) != value for key, value in expected.items()):
        raise SystemExit("FAIL: harness and HexStrike canonical scenario configuration differ")
    if KillSwitch(Path(args.kill_switch_file)).engaged():
        raise SystemExit("FAIL: kill switch is engaged")
    token_path = Path(args.approval_token_file)
    if token_path.exists():
        raise SystemExit("FAIL: approval token path already exists; issue a fresh approval later")
    authority = ApprovalAuthority(secret.encode(), args.approval_spent_dir)
    digest = validate_readiness(
        config,
        Path(args.t3b_result),
        seal_authority=ArtifactSealAuthority.from_approval_authority(authority),
    )
    print("PASS: offline T3-C readiness checks completed")
    print(f"canonical action: {ACTION_ID}")
    print(f"scenario ID: {config.scenario_id}")
    print(f"T3-B result digest: {digest}")
    print(f"safe approval fingerprint: {binding(config, digest)}")
    print("network traffic generated: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
