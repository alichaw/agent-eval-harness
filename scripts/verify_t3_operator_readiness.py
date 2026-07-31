#!/usr/bin/env python3
"""Sanitized, read-only T3 operator readiness verifier; run with sudo."""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import yaml


def _metadata(path: Path) -> dict[str, object]:
    info = path.stat()
    return {
        "owner": pwd.getpwuid(info.st_uid).pw_name,
        "group": grp.getgrgid(info.st_gid).gr_name,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }


def _command(*args: str) -> str:
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout


def _destination_allowed(rules: str, target: str) -> bool:
    for line in rules.splitlines():
        fields = line.split()
        if "-d" not in fields or "-j" not in fields:
            continue
        try:
            network = ipaddress.ip_network(fields[fields.index("-d") + 1], strict=False)
        except (IndexError, ValueError):
            continue
        if (
            network.version == 4
            and network.prefixlen == 32
            and str(network.network_address) == target
            and fields[fields.index("-j") + 1] == "ACCEPT"
        ):
            return True
    return False


def _endpoint_rejects_without_permit(path: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:8888{path}",
        data=b'{"permit":"invalid-synthetic-permit"}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=3)  # noqa: S310 - fixed loopback URL
    except urllib.error.HTTPError as exc:
        return exc.code == 401
    except OSError:
        return False
    return False


def _service_accepts_harness_signature(secret: bytes, path: str) -> bool:
    payload = b'{"synthetic_readiness":true}'

    def encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    signature = hmac.new(secret, payload, hashlib.sha256).digest()
    token = f"{encode(payload)}.{encode(signature)}"
    request = urllib.request.Request(
        f"http://127.0.0.1:8888{path}",
        data=json.dumps({"permit": token}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=3)  # noqa: S310 - fixed loopback URL
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except (OSError, ValueError):
            return False
        return exc.code == 401 and body == {"error": "permit_claims_invalid"}
    except OSError:
        return False
    return False


def _read_harness_permit_secret() -> bytes:
    line = Path("/etc/agent-eval-harness/t3-permit.env").read_text(encoding="utf-8")
    prefix = "HARNESS_EXECUTION_PERMIT_SECRET="
    if not line.endswith("\n") or not line.startswith(prefix) or "\n" in line[:-1]:
        raise ValueError("invalid permit configuration")
    secret = line[len(prefix) : -1].encode()
    if len(secret) < 32:
        raise ValueError("invalid permit configuration")
    return secret


def _verify(args: argparse.Namespace) -> tuple[dict[str, object], bool]:
    harness = Path(args.harness_root)
    hexstrike = Path(args.hexstrike_root)
    assets_doc = yaml.safe_load((harness / "config/local/assets.yaml").read_text(encoding="utf-8"))
    asset = assets_doc["assets"]["asset:winsrv2025-01"]
    target = str(asset["target"])
    ipaddress.IPv4Address(target)

    matrix_path = Path("/etc/hexstrike/job-targets.json")
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    networks = matrix.get("allowed_targets", [])
    matrix_result = {
        **_metadata(matrix_path),
        "owner_pass": matrix_path.stat().st_uid == 0,
        "group_pass": grp.getgrgid(matrix_path.stat().st_gid).gr_name == "hexstrike",
        "mode_pass": stat.S_IMODE(matrix_path.stat().st_mode) == 0o640,
        "all_entries_ipv4_32": bool(networks)
        and all(
            ipaddress.ip_network(item, strict=True).version == 4
            and ipaddress.ip_network(item, strict=True).prefixlen == 32
            for item in networks
        ),
        "expected_asset_binding_pass": f"{target}/32" in networks,
    }

    credentials_path = Path("/etc/hexstrike/t3a-credentials.json")
    credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
    mapping = credentials.get("credentials", {}).get("credential:ssh-winsrv2025-01")
    mapping_pass = (
        isinstance(mapping, dict)
        and mapping.get("asset_id") == "asset:winsrv2025-01"
        and mapping.get("username") == "poc_websvc"
        and isinstance(mapping.get("identity_agent"), str)
    )
    credential_result = {
        **_metadata(credentials_path),
        "owner_pass": credentials_path.stat().st_uid == 0,
        "group_pass": grp.getgrgid(credentials_path.stat().st_gid).gr_name == "hexstrike",
        "mode_pass": stat.S_IMODE(credentials_path.stat().st_mode) == 0o640,
        "expected_binding_pass": mapping_pass,
    }

    socket_result: dict[str, object] = {"present": False}
    if mapping_pass:
        socket_path = Path(mapping["identity_agent"])
        socket_info = socket_path.stat()
        readable = (
            subprocess.run(
                ["runuser", "-u", "hexstrike", "--", "test", "-r", str(socket_path)],
                check=False,
            ).returncode
            == 0
        )
        writable = (
            subprocess.run(
                ["runuser", "-u", "hexstrike", "--", "test", "-w", str(socket_path)],
                check=False,
            ).returncode
            == 0
        )
        socket_result = {
            **_metadata(socket_path),
            "present": True,
            "is_socket": stat.S_ISSOCK(socket_info.st_mode),
            "hexstrike_readable": readable,
            "hexstrike_writable": writable,
        }

    listener = _command("ss", "-ltnp", "sport = :8888")
    bind_result = {
        "loopback_only_pass": "127.0.0.1:8888" in listener
        and "0.0.0.0:8888" not in listener
        and "[::]:8888" not in listener,
        "port_8888_listening": ":8888" in listener,
    }

    source = (hexstrike / "hexstrike_server.py").read_text(encoding="utf-8")
    t3a_source = (hexstrike / "hexstrike_t3a.py").read_text(encoding="utf-8")
    code_result = {
        "source_revision": _command("git", "-C", str(hexstrike), "rev-parse", "HEAD").strip(),
        "t3a_route_registered": "register_t3a_routes(app)" in source,
        "t3a_endpoint_present": "/api/v1/t3a/executions" in t3a_source,
        "t3b_route_registered": "register_t3b_routes(app)" in source,
        "t3b_endpoint_present": (hexstrike / "hexstrike_t3b.py").is_file(),
        "running_t3a_endpoint_rejects_invalid_permit": _endpoint_rejects_without_permit(
            "/api/v1/t3a/executions"
        ),
        "running_t3b_endpoint_rejects_invalid_permit": _endpoint_rejects_without_permit(
            "/api/v1/t3b/executions"
        ),
    }
    harness_permit_secret = _read_harness_permit_secret()
    code_result["t3a_verifies_harness_synthetic_signature"] = _service_accepts_harness_signature(
        harness_permit_secret, "/api/v1/t3a/executions"
    )
    code_result["t3b_verifies_harness_synthetic_signature"] = _service_accepts_harness_signature(
        harness_permit_secret, "/api/v1/t3b/executions"
    )
    harness_secret_path = Path("/etc/agent-eval-harness/t3-permit.env")
    hexstrike_secret_path = Path("/etc/hexstrike/t3-permit.env")
    permit_result = {
        "harness": {
            **_metadata(harness_secret_path),
            "owner_pass": harness_secret_path.stat().st_uid == 0,
            "mode_pass": stat.S_IMODE(harness_secret_path.stat().st_mode) == 0o600,
        },
        "hexstrike": {
            **_metadata(hexstrike_secret_path),
            "owner_pass": hexstrike_secret_path.stat().st_uid == 0,
            "group_pass": grp.getgrgid(hexstrike_secret_path.stat().st_gid).gr_name == "hexstrike",
            "mode_pass": stat.S_IMODE(hexstrike_secret_path.stat().st_mode) == 0o640,
        },
        "synthetic_verification_compatible": (
            code_result["t3a_verifies_harness_synthetic_signature"]
            and code_result["t3b_verifies_harness_synthetic_signature"]
        ),
    }

    uid = pwd.getpwnam("hexstrike").pw_uid
    output_rules = _command("iptables", "-S", "OUTPUT")
    chain_rules = _command("iptables", "-S", "HEXSTRIKE_EGRESS")
    firewall_result = {
        "uid": uid,
        "uid_attachment_pass": (f"--uid-owner {uid} -j HEXSTRIKE_EGRESS" in output_rules),
        "loopback_allow_present": "-o lo -j ACCEPT" in chain_rules,
        "expected_target_allow_present": _destination_allowed(chain_rules, target),
        "default_deny_pass": chain_rules.rstrip().endswith("-j DROP"),
    }

    report = {
        "target_matrix": matrix_result,
        "credential_mapping": credential_result,
        "ssh_agent_socket": socket_result,
        "hexstrike_bind": bind_result,
        "service_code": code_result,
        "permit_configuration": permit_result,
        "uid_firewall": firewall_result,
    }
    checks = [
        matrix_result["owner_pass"],
        matrix_result["group_pass"],
        matrix_result["mode_pass"],
        matrix_result["all_entries_ipv4_32"],
        matrix_result["expected_asset_binding_pass"],
        credential_result["owner_pass"],
        credential_result["group_pass"],
        credential_result["mode_pass"],
        credential_result["expected_binding_pass"],
        socket_result.get("is_socket"),
        socket_result.get("hexstrike_readable"),
        socket_result.get("hexstrike_writable"),
        bind_result["loopback_only_pass"],
        *(value for key, value in code_result.items() if key != "source_revision"),
        permit_result["harness"]["owner_pass"],
        permit_result["harness"]["mode_pass"],
        permit_result["hexstrike"]["owner_pass"],
        permit_result["hexstrike"]["group_pass"],
        permit_result["hexstrike"]["mode_pass"],
        permit_result["synthetic_verification_compatible"],
        firewall_result["uid_attachment_pass"],
        firewall_result["loopback_allow_present"],
        firewall_result["expected_target_allow_present"],
        firewall_result["default_deny_pass"],
    ]
    return report, all(checks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", default="/home/kali/agent-eval-harness")
    parser.add_argument("--hexstrike-root", default="/home/kali/hexstrike-ai")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(json.dumps({"overall_pass": False, "error_code": "sudo_required"}))
        return 2
    try:
        report, passed = _verify(args)
    except Exception:  # noqa: BLE001 - never expose protected paths or values
        print(json.dumps({"overall_pass": False, "error_code": "readiness_verification_failed"}))
        return 2
    report["overall_pass"] = passed
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
