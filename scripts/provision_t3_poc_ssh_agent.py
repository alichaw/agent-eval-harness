#!/usr/bin/env python3
"""Interactively load the protected PoC key into the dedicated SSH agent."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import stat
import subprocess
from pathlib import Path

DEFAULT_RUNTIME = Path("/home/kali/agent-eval-harness/config/local/t3-runtime.json")
AGENT_SOCKET = Path("/run/hexstrike-t3-ssh-agent/agent.sock")
PROVISIONED_MARKER = Path("/run/hexstrike-t3-ssh-agent/identity-provisioned")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Interactively provision the dedicated SSH agent from the protected "
            "legacy runtime. No key value or protected path is printed."
        )
    )
    value.add_argument("--legacy-runtime-file", type=Path, default=DEFAULT_RUNTIME)
    return value


def _protected_json(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("legacy_runtime_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        permitted_owners = {0, int(os.environ.get("SUDO_UID", "0"))}
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in permitted_owners
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("legacy_runtime_invalid")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    expected = {
        "asset_id",
        "profile_id",
        "credential_ref",
        "username",
        "private_key_path",
        "pinned_host_key",
        "assurance",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("legacy_runtime_invalid")
    return value


def provision(
    legacy_runtime: Path,
    *,
    confirmation=input,
    runner=subprocess.run,
) -> None:
    if os.geteuid() != 0:
        raise ValueError("root_required")
    account = pwd.getpwnam("hexstrike")
    runtime = _protected_json(legacy_runtime)
    key = Path(runtime["private_key_path"])
    if not key.is_absolute() or key.is_symlink():
        raise ValueError("private_key_invalid")
    descriptor = os.open(key, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        permitted_owners = {0, int(os.environ.get("SUDO_UID", "0"))}
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in permitted_owners
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("private_key_invalid")
        key_material = os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)
    socket_info = AGENT_SOCKET.lstat()
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != account.pw_uid
        or not os.access(AGENT_SOCKET, os.R_OK | os.W_OK)
        or PROVISIONED_MARKER.exists()
        or PROVISIONED_MARKER.is_symlink()
    ):
        raise ValueError("identity_agent_invalid")
    if (
        confirmation(
            "Interactive confirmation: type PROVISION to load the approved key "
            "into the protected agent: "
        )
        != "PROVISION"
    ):
        raise ValueError("operator_confirmation_rejected")
    environment = {"SSH_AUTH_SOCK": str(AGENT_SOCKET)}
    loaded = runner(
        [
            "runuser",
            "-u",
            "hexstrike",
            "--",
            "env",
            *[f"{k}={v}" for k, v in environment.items()],
            "ssh-add",
            "-",
        ],
        input=key_material,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    key_material = b""
    if loaded.returncode != 0:
        raise ValueError("identity_provisioning_failed")
    verified = runner(
        [
            "runuser",
            "-u",
            "hexstrike",
            "--",
            "env",
            *[f"{k}={v}" for k, v in environment.items()],
            "ssh-add",
            "-l",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if verified.returncode != 0:
        raise ValueError("identity_agent_verification_failed")
    descriptor = os.open(PROVISIONED_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    os.chown(PROVISIONED_MARKER, account.pw_uid, account.pw_gid)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        provision(args.legacy_runtime_file.resolve())
    except Exception as exc:
        allowed = {
            "root_required",
            "legacy_runtime_invalid",
            "private_key_invalid",
            "identity_agent_invalid",
            "operator_confirmation_rejected",
            "identity_provisioning_failed",
            "identity_agent_verification_failed",
        }
        code = str(exc) if str(exc) in allowed else "identity_provisioning_failed"
        raise SystemExit(code) from None
    print("identity provisioning PASS: protected agent contains an approved identity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
