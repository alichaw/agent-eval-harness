#!/usr/bin/env python3
"""Migrate protected legacy inputs into the one unified T3 PoC runtime."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

import yaml

HARNESS = Path(__file__).resolve().parents[1]
PROTECTED = Path("/etc/hexstrike")
STATE_ROOT = Path("/var/lib/hexstrike")
ASSET_ID = "asset:winsrv2025-01"
IDENTITY_AGENT = "/run/hexstrike-t3-ssh-agent/agent.sock"
UNIFIED_RUNTIME_NAME = "t3-unified-runtime.json"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Atomically derive one owner-only unified T3 runtime from protected "
            "legacy runtime and authoritative local asset/policy files. Legacy "
            "input is never overwritten; no network or external tool is used."
        )
    )
    value.add_argument("--harness-root", type=Path, default=HARNESS)
    value.add_argument("--protected-dir", type=Path, default=PROTECTED)
    value.add_argument("--state-root", type=Path, default=STATE_ROOT)
    value.add_argument("--runtime-config", type=Path)
    value.add_argument("--assets-config", type=Path)
    value.add_argument("--unified-policy-config", type=Path)
    return value


def atomic_json(path: Path, value: dict, *, uid: int, gid: int, mode: int) -> None:
    if path.is_symlink():
        raise ValueError("output_symlink_rejected")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_legacy(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("legacy_runtime_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("legacy_runtime_invalid")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    required = {
        "asset_id",
        "profile_id",
        "credential_ref",
        "username",
        "private_key_path",
        "pinned_host_key",
        "assurance",
    }
    if not isinstance(value, dict) or set(value) != required or value["asset_id"] != ASSET_ID:
        raise ValueError("legacy_runtime_invalid")
    return value


def build_unified_runtime(
    *,
    asset: dict,
    legacy_runtime: dict,
    policy: dict,
    state_root: Path,
    runtime_revision: str | None = None,
) -> dict:
    sys.path.insert(0, str(HARNESS))
    from core.t3.poc_registry import ACTIONS
    from core.t3.poc_runtime import PocRuntime

    enabled = policy.get("unified_t3", {}).get("enabled_action_ids")
    if enabled != list(ACTIONS):
        raise ValueError("unified_action_policy_invalid")
    if asset.get("credential_ref") != legacy_runtime["credential_ref"]:
        raise ValueError("authoritative_credential_mismatch")
    value = {
        "schema_version": "hexstrike-t3-runtime/v1",
        "runtime_revision": runtime_revision or str(uuid4()),
        "assets": {
            ASSET_ID: {
                "target": asset["target"],
                "port": 22,
                "credential_ref": legacy_runtime["credential_ref"],
                "username": legacy_runtime["username"],
                "identity_agent": IDENTITY_AGENT,
                "pinned_host_key": legacy_runtime["pinned_host_key"],
            }
        },
        "approval_database": str((state_root / "t3-unified-approvals-v2.sqlite3").resolve()),
        "evidence_root": str((state_root / "t3-unified-evidence").resolve()),
        "kill_switch_file": "/run/hexstrike/KILL",
        "action_policy": {"enabled_action_ids": enabled},
    }
    return PocRuntime.model_validate(value).model_dump(mode="json")


def prepare_unified_state(runtime: dict, *, uid: int, gid: int) -> None:
    from core.t3.poc_approval import ApprovalStore

    database = Path(runtime["approval_database"])
    evidence = Path(runtime["evidence_root"])
    if database.is_symlink() or evidence.is_symlink():
        raise ValueError("unified_state_symlink_rejected")
    ApprovalStore(database).initialize()
    os.chown(database, uid, gid)
    os.chmod(database, 0o600)
    evidence.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chown(evidence, uid, gid)
    os.chmod(evidence, 0o700)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        raise SystemExit("root_required")
    import pwd

    harness = args.harness_root.resolve()
    protected = args.protected_dir.resolve()
    state_root = args.state_root.resolve()
    legacy_path = (args.runtime_config or harness / "config/local/t3-runtime.json").resolve()
    assets_path = (args.assets_config or harness / "config/local/assets.yaml").resolve()
    policy_path = (args.unified_policy_config or harness / "policy.yaml").resolve()
    legacy = _read_legacy(legacy_path)
    assets = yaml.safe_load(assets_path.read_text(encoding="utf-8"))["assets"]
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    runtime = build_unified_runtime(
        asset=assets[ASSET_ID], legacy_runtime=legacy, policy=policy, state_root=state_root
    )
    account = pwd.getpwnam("hexstrike")
    output = protected / UNIFIED_RUNTIME_NAME
    atomic_json(output, runtime, uid=account.pw_uid, gid=account.pw_gid, mode=0o600)
    prepare_unified_state(runtime, uid=account.pw_uid, gid=account.pw_gid)
    sys.path.insert(0, str(harness))
    from core.t3.poc_runtime import load_runtime

    load_runtime(output, owner_uid=account.pw_uid)
    print(
        json.dumps(
            {
                "configuration_created": True,
                "runtime_path": str(output),
                "protected_values_disclosed": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
