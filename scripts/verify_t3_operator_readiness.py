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
from typing import Any

import yaml


class ReadinessCheckError(Exception):
    def __init__(self, check: str, code: str):
        super().__init__(code)
        self.check = check
        self.code = code


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


def _poc_endpoint_rejects_invalid_authorization(path: str, action: str) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:8888{path}",
        data=json.dumps(
            {
                "authorization_id": "invalid-synthetic-authorization",
                "canonical_action": action,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=3)  # noqa: S310 - fixed loopback URL
    except urllib.error.HTTPError as exc:
        return exc.code == 403
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


def _verify_hardened(args: argparse.Namespace) -> tuple[dict[str, object], bool]:
    harness = Path(args.harness_root)
    hexstrike = Path(args.hexstrike_root)
    assets_doc = yaml.safe_load((harness / "config/local/assets.yaml").read_text(encoding="utf-8"))
    asset = assets_doc["assets"]["asset:winsrv2025-01"]
    target = str(asset["target"])
    ipaddress.IPv4Address(target)

    reachability_path = Path("/etc/hexstrike/t3-reachability.json")
    reachability = json.loads(reachability_path.read_text(encoding="utf-8"))
    expected_binding = hashlib.sha256(f"asset:winsrv2025-01\0{target}\0{22}".encode()).hexdigest()
    actual_binding = hashlib.sha256(
        f"{reachability.get('asset_id')}\0{reachability.get('target')}"
        f"\0{reachability.get('port')}".encode()
    ).hexdigest()
    reachability_result = {
        **_metadata(reachability_path),
        "owner_pass": reachability_path.stat().st_uid == 0,
        "group_pass": grp.getgrgid(reachability_path.stat().st_gid).gr_name == "hexstrike",
        "mode_pass": stat.S_IMODE(reachability_path.stat().st_mode) == 0o640,
        "exact_schema_pass": set(reachability) == {"asset_id", "target", "port"},
        "asset_binding_pass": reachability.get("asset_id") == "asset:winsrv2025-01",
        "target_binding_pass": actual_binding == expected_binding,
        "fixed_port_pass": reachability.get("port") == 22,
    }

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

    socket_result = _identity_agent_result(
        harness,
        (mapping.get("identity_agent") if isinstance(mapping, dict) else None,),
    )

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
    permit_result: dict[str, Any] = {
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

    report: dict[str, object] = {
        "assurance_profile": "hardened",
        "ssh_reachability_configuration": reachability_result,
        "target_matrix": matrix_result,
        "credential_mapping": credential_result,
        "ssh_agent_socket": socket_result,
        "hexstrike_bind": bind_result,
        "service_code": code_result,
        "permit_configuration": permit_result,
        "uid_firewall": firewall_result,
    }
    checks = [
        reachability_result["owner_pass"],
        reachability_result["group_pass"],
        reachability_result["mode_pass"],
        reachability_result["exact_schema_pass"],
        reachability_result["asset_binding_pass"],
        reachability_result["target_binding_pass"],
        reachability_result["fixed_port_pass"],
        matrix_result["owner_pass"],
        matrix_result["group_pass"],
        matrix_result["mode_pass"],
        matrix_result["all_entries_ipv4_32"],
        matrix_result["expected_asset_binding_pass"],
        credential_result["owner_pass"],
        credential_result["group_pass"],
        credential_result["mode_pass"],
        credential_result["expected_binding_pass"],
        socket_result.get("status") == "PASS",
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


def _protected_json_result(
    path: Path, check: str | None = None
) -> tuple[dict[str, Any], dict[str, object]]:
    selected_check = check or path.name.removesuffix(".json").replace("-", "_")
    try:
        raw = path.read_text(encoding="utf-8")
        info = path.stat()
        value = json.loads(raw)
    except FileNotFoundError as exc:
        raise ReadinessCheckError(selected_check, "configuration_missing") from exc
    except PermissionError as exc:
        raise ReadinessCheckError(selected_check, "configuration_unreadable") from exc
    except json.JSONDecodeError as exc:
        raise ReadinessCheckError(selected_check, "configuration_json_invalid") from exc
    except OSError as exc:
        raise ReadinessCheckError(selected_check, "configuration_metadata_unavailable") from exc
    if not isinstance(value, dict):
        raise ReadinessCheckError(selected_check, "configuration_root_not_object")
    result = {
        **_metadata(path),
        "owner_pass": info.st_uid == 0,
        "group_pass": grp.getgrgid(info.st_gid).gr_name == "hexstrike",
        "mode_pass": stat.S_IMODE(info.st_mode) == 0o640,
    }
    return value, result


def _diagnose(result: dict[str, object], rules: dict[str, str]) -> None:
    codes = [code for key, code in rules.items() if result.get(key) is not True]
    result["status"] = "PASS" if not codes else "FAIL"
    result["error_codes"] = codes


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _systemd_unit_active(unit_name: str) -> bool:
    return (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", unit_name],
            check=False,
            capture_output=True,
            timeout=10,
        ).returncode
        == 0
    )


def _identity_agent_result(
    harness: Path,
    configured_agents: tuple[object, ...],
    *,
    systemd_root: Path = Path("/etc/systemd/system"),
) -> dict[str, object]:
    """Validate the fixed agent contract without opening or querying the agent."""
    result: dict[str, object] = {
        "repository_contract_defined": False,
        "configuration_binding_pass": False,
        "systemd_unit_installed": False,
        "systemd_unit_contract_pass": False,
        "service_running": False,
        "runtime_directory_available": False,
        "runtime_directory_type_pass": False,
        "runtime_directory_owner_pass": False,
        "runtime_directory_access_pass": False,
        "socket_available": False,
        "socket_type_pass": False,
        "socket_owner_pass": False,
        "socket_access_pass": False,
        "identity_provisioning_completed": False,
    }
    contract_path = harness / "config/t3-identity-agent-runtime.json"
    if not contract_path.is_file():
        result.update(
            status="FAIL",
            error_code="identity_agent_runtime_contract_missing",
            error_codes=["identity_agent_runtime_contract_missing"],
        )
        return result
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        required = {
            "unit_name",
            "service_account",
            "runtime_directory",
            "socket_path",
            "provisioning_marker_path",
        }
        if not isinstance(contract, dict) or set(contract) != required:
            raise ValueError
        unit_name = contract["unit_name"]
        account = contract["service_account"]
        runtime = Path(contract["runtime_directory"])
        socket_path = Path(contract["socket_path"])
        marker_path = Path(contract["provisioning_marker_path"])
        if (
            unit_name != "hexstrike-t3-ssh-agent.service"
            or account != "hexstrike"
            or not runtime.is_absolute()
            or not socket_path.is_absolute()
            or not marker_path.is_absolute()
            or runtime == Path("/run")
            or Path("/run") not in runtime.parents
            or socket_path.parent != runtime
            or marker_path.parent != runtime
        ):
            raise ValueError
        result["repository_contract_defined"] = True
    except (OSError, TypeError, ValueError):
        result.update(
            status="FAIL",
            error_code="identity_agent_runtime_contract_invalid",
            error_codes=["identity_agent_runtime_contract_invalid"],
        )
        return result

    result["configuration_binding_pass"] = bool(configured_agents) and all(
        value == str(socket_path) for value in configured_agents
    )
    unit_path = systemd_root / unit_name
    try:
        unit_source = unit_path.read_text(encoding="utf-8")
        result["systemd_unit_installed"] = True
        result["systemd_unit_contract_pass"] = all(
            value in unit_source
            for value in (
                "User=hexstrike",
                "Group=hexstrike",
                f"RuntimeDirectory={runtime.name}",
                "RuntimeDirectoryMode=0700",
                f"ExecStart=/usr/bin/ssh-agent -D -a {socket_path}",
                "UMask=0077",
            )
        )
    except OSError:
        pass

    result["service_running"] = (
        _systemd_unit_active(unit_name) if result["systemd_unit_installed"] else False
    )

    try:
        runtime_info = _lstat(runtime)
        account_info = pwd.getpwnam(account)
        runtime_mode = stat.S_IMODE(runtime_info.st_mode)
        result["runtime_directory_available"] = True
        result["runtime_directory_type_pass"] = stat.S_ISDIR(runtime_info.st_mode)
        result["runtime_directory_owner_pass"] = runtime_info.st_uid == account_info.pw_uid
        result["runtime_directory_access_pass"] = (
            result["runtime_directory_owner_pass"]
            and (runtime_mode >> 6) & 0o7 == 0o7
            and runtime_mode & 0o007 == 0
        )
    except (FileNotFoundError, PermissionError, KeyError):
        pass

    try:
        socket_info = _lstat(socket_path)
        result["socket_available"] = True
        result["socket_type_pass"] = stat.S_ISSOCK(socket_info.st_mode)
        account_info = pwd.getpwnam(account)
        result["socket_owner_pass"] = socket_info.st_uid == account_info.pw_uid
        owner_bits = (stat.S_IMODE(socket_info.st_mode) >> 6) & 0o7
        result["socket_access_pass"] = (
            result["socket_owner_pass"]
            and owner_bits & 0o6 == 0o6
            and stat.S_IMODE(socket_info.st_mode) & 0o006 == 0
        )
    except (FileNotFoundError, PermissionError, KeyError):
        pass

    try:
        marker_info = _lstat(marker_path)
        result["identity_provisioning_completed"] = (
            stat.S_ISREG(marker_info.st_mode)
            and marker_info.st_uid == pwd.getpwnam(account).pw_uid
            and stat.S_IMODE(marker_info.st_mode) & 0o077 == 0
        )
    except (FileNotFoundError, PermissionError, KeyError):
        pass

    ordered_failures = (
        ("configuration_binding_pass", "identity_agent_binding_invalid"),
        ("systemd_unit_installed", "identity_agent_unit_missing"),
        ("systemd_unit_contract_pass", "identity_agent_unit_contract_invalid"),
        ("runtime_directory_available", "identity_agent_runtime_directory_unavailable"),
        ("runtime_directory_type_pass", "identity_agent_runtime_directory_wrong_type"),
        ("runtime_directory_owner_pass", "identity_agent_runtime_directory_owner_invalid"),
        ("runtime_directory_access_pass", "identity_agent_runtime_directory_inaccessible"),
        ("socket_available", "identity_agent_socket_unavailable"),
        ("socket_type_pass", "identity_agent_socket_wrong_type"),
        ("socket_owner_pass", "identity_agent_socket_owner_invalid"),
        ("socket_access_pass", "identity_agent_socket_inaccessible"),
        ("service_running", "identity_agent_service_not_running"),
        ("identity_provisioning_completed", "identity_agent_identity_unprovisioned"),
    )
    codes = [code for key, code in ordered_failures if result[key] is not True]
    result["status"] = "PASS" if not codes else "FAIL"
    result["error_codes"] = codes
    if codes:
        result["error_code"] = codes[0]
    return result


def _pinned_host_source_result(value: object, expected_key: object) -> dict[str, object]:
    result: dict[str, object] = {
        "owner_pass": False,
        "group_pass": False,
        "mode_pass": False,
        "key_binding_pass": False,
    }
    if not isinstance(value, str) or not value.startswith("/") or not isinstance(expected_key, str):
        _diagnose(result, {"key_binding_pass": "pinned_host_source_invalid"})
        return result
    try:
        path = Path(value)
        info = path.stat()
        lines = path.read_text(encoding="utf-8").splitlines()
        result.update(
            {
                "owner_pass": info.st_uid == 0,
                "group_pass": grp.getgrgid(info.st_gid).gr_name == "hexstrike",
                "mode_pass": stat.S_IMODE(info.st_mode) == 0o640,
                "key_binding_pass": any(
                    line.split(maxsplit=1)[-1] == expected_key
                    for line in lines
                    if line and not line.lstrip().startswith("#") and " " in line
                ),
            }
        )
    except (OSError, UnicodeError):
        pass
    _diagnose(
        result,
        {
            "owner_pass": "pinned_host_source_owner_invalid",
            "group_pass": "pinned_host_source_group_invalid",
            "mode_pass": "pinned_host_source_mode_invalid",
            "key_binding_pass": "pinned_host_source_binding_invalid",
        },
    )
    return result


def _skipped(reason: str = "poc_profile") -> dict[str, str]:
    return {"status": "SKIPPED_BY_PROFILE", "reason": reason}

def _kill_switch_inactive(path: Path) -> bool:
    """Return True only when the kill-switch path is confirmed absent."""
    try:
        return not path.exists()
    except OSError:
        return False

def _verify_poc(args: argparse.Namespace) -> tuple[dict[str, object], bool]:
    harness = Path(args.harness_root)
    hexstrike = Path(args.hexstrike_root)
    assets_doc = yaml.safe_load((harness / "assets.yaml").read_text(encoding="utf-8"))
    asset = assets_doc["assets"]["asset:winsrv2025-01"]
    target = str(asset["target"])
    ipaddress.IPv4Address(target)

    reachability, reachability_result = _protected_json_result(
        Path("/etc/hexstrike/t3-reachability.json")
    )
    expected_binding = hashlib.sha256(f"asset:winsrv2025-01\0{target}\0{22}".encode()).hexdigest()
    actual_binding = hashlib.sha256(
        f"{reachability.get('asset_id')}\0{reachability.get('target')}"
        f"\0{reachability.get('port')}".encode()
    ).hexdigest()
    reachability_result.update(
        {
            "exact_schema_pass": set(reachability) == {"asset_id", "target", "port"},
            "asset_binding_pass": reachability.get("asset_id") == "asset:winsrv2025-01",
            "target_binding_pass": actual_binding == expected_binding,
            "fixed_port_pass": reachability.get("port") == 22,
        }
    )
    _diagnose(
        reachability_result,
        {
            "owner_pass": "owner_invalid",
            "group_pass": "group_invalid",
            "mode_pass": "mode_invalid",
            "exact_schema_pass": "schema_invalid",
            "asset_binding_pass": "asset_binding_invalid",
            "target_binding_pass": "target_binding_invalid",
            "fixed_port_pass": "port_binding_invalid",
        },
    )

    runtime, runtime_result = _protected_json_result(Path("/etc/hexstrike/t3-poc-runtime.json"))
    runtime_result.update(
        {
            "exact_schema_pass": set(runtime)
            == {"assurance_profile", "asset_id", "target_binding", "pinned_host_key"},
            "profile_pass": runtime.get("assurance_profile") == "poc",
            "asset_binding_pass": runtime.get("asset_id") == "asset:winsrv2025-01",
            "target_binding_pass": runtime.get("target_binding") == expected_binding,
            "pinned_host_key_present": isinstance(runtime.get("pinned_host_key"), str)
            and runtime.get("pinned_host_key", "").startswith("ssh-ed25519 "),
        }
    )
    _diagnose(
        runtime_result,
        {
            "owner_pass": "owner_invalid",
            "group_pass": "group_invalid",
            "mode_pass": "mode_invalid",
            "exact_schema_pass": "schema_invalid",
            "profile_pass": "assurance_profile_invalid",
            "asset_binding_pass": "asset_binding_invalid",
            "target_binding_pass": "target_binding_invalid",
            "pinned_host_key_present": "pinned_host_key_invalid",
        },
    )

    matrix, matrix_result = _protected_json_result(Path("/etc/hexstrike/job-targets.json"))
    matrix_result.update(
        {
            "exact_schema_pass": set(matrix) == {"allowed_targets"},
            "fixed_target_pass": matrix.get("allowed_targets") == [f"{target}/32"],
        }
    )
    _diagnose(
        matrix_result,
        {
            "owner_pass": "owner_invalid",
            "group_pass": "group_invalid",
            "mode_pass": "mode_invalid",
            "exact_schema_pass": "schema_invalid",
            "fixed_target_pass": "target_binding_invalid",
        },
    )

    credentials, credential_result = _protected_json_result(
        Path("/etc/hexstrike/t3a-credentials.json")
    )
    mapping = credentials.get("credentials", {}).get("credential:ssh-winsrv2025-01")
    credential_result.update(
        {
            "exact_binding_pass": isinstance(mapping, dict)
            and mapping.get("asset_id") == "asset:winsrv2025-01"
            and mapping.get("username") == "poc_websvc"
            and isinstance(mapping.get("identity_agent"), str),
            "identity_loaded": False,
        }
    )
    _diagnose(
        credential_result,
        {
            "owner_pass": "owner_invalid",
            "group_pass": "group_invalid",
            "mode_pass": "mode_invalid",
            "exact_binding_pass": "credential_binding_invalid",
        },
    )

    t3c, t3c_result = _protected_json_result(Path("/etc/hexstrike/t3c-runtime.json"))
    t3c_required = {
        "assurance_profile",
        "scenario_id",
        "asset_id",
        "target",
        "credential_ref",
        "identity_agent",
        "username",
        "pinned_host_key_file",
        "marker_path",
        "marker_content_sha256",
        "cleanup_required",
        "rollback_verification_required",
        "maximum_duration_seconds",
        "maximum_tool_calls",
        "isolated_lab_ready",
    }
    expected_marker_digest = hashlib.sha256(b"HEXSTRIKE_T3C_SYNTHETIC_MARKER_V2").hexdigest()
    t3c_result.update(
        {
            "exact_schema_pass": set(t3c) == t3c_required,
            "profile_pass": t3c.get("assurance_profile") == "poc",
            "scenario_pass": t3c.get("scenario_id") == "lab.synthetic-marker.v2",
            "asset_binding_pass": t3c.get("asset_id") == "asset:winsrv2025-01",
            "target_binding_pass": t3c.get("target") == target,
            "credential_binding_pass": t3c.get("credential_ref") == "credential:ssh-winsrv2025-01",
            "identity_binding_pass": isinstance(mapping, dict)
            and t3c.get("username") == mapping.get("username")
            and t3c.get("identity_agent") == mapping.get("identity_agent"),
            "marker_binding_pass": t3c.get("marker_path")
            == r"C:\ProgramData\HexStrike\t3c-synthetic-marker.txt"
            and t3c.get("marker_content_sha256") == expected_marker_digest,
            "cleanup_required_pass": t3c.get("cleanup_required") is True,
            "rollback_required_pass": t3c.get("rollback_verification_required") is True,
            "limits_pass": t3c.get("maximum_duration_seconds") == 60
            and t3c.get("maximum_tool_calls") == 6,
            "isolated_lab_pass": t3c.get("isolated_lab_ready") is True,
        }
    )
    _diagnose(
        t3c_result,
        {
            "owner_pass": "owner_invalid",
            "group_pass": "group_invalid",
            "mode_pass": "mode_invalid",
            "exact_schema_pass": "schema_invalid",
            "profile_pass": "assurance_profile_invalid",
            "scenario_pass": "scenario_invalid",
            "asset_binding_pass": "asset_binding_invalid",
            "target_binding_pass": "target_binding_invalid",
            "credential_binding_pass": "credential_binding_invalid",
            "identity_binding_pass": "identity_binding_invalid",
            "marker_binding_pass": "marker_contract_invalid",
            "cleanup_required_pass": "cleanup_requirement_invalid",
            "rollback_required_pass": "rollback_requirement_invalid",
            "limits_pass": "limits_invalid",
            "isolated_lab_pass": "isolated_lab_assertion_invalid",
        },
    )
    pinned_host_result = _pinned_host_source_result(
        t3c.get("pinned_host_key_file"), runtime.get("pinned_host_key")
    )
    identity_agent_result = _identity_agent_result(
        harness,
        (
            mapping.get("identity_agent") if isinstance(mapping, dict) else None,
            t3c.get("identity_agent"),
        ),
    )

    listener = _command("ss", "-ltnp", "sport = :8888")
    bind_result = {
        "loopback_only_pass": "127.0.0.1:8888" in listener
        and "0.0.0.0:8888" not in listener
        and "[::]:8888" not in listener,
        "port_8888_listening": ":8888" in listener,
    }
    endpoint_result = {
        "t3a_poc_invalid_authorization_rejected": _poc_endpoint_rejects_invalid_authorization(
            "/api/v1/t3a/poc-executions", "windows.ssh.identity.v1"
        ),
        "t3b_poc_invalid_authorization_rejected": _poc_endpoint_rejects_invalid_authorization(
            "/api/v1/t3b/poc-executions", "windows.host.enumeration.readonly.v1"
        ),
        "t3c_poc_invalid_authorization_rejected": _poc_endpoint_rejects_invalid_authorization(
            "/api/v1/t3c/executions", "t3c.controlled_impact_proof.v1"
        ),
    }
    authorization_source = (hexstrike / "hexstrike_t3_authorization.py").read_text(encoding="utf-8")
    replay_result = {
        "ttl_60_seconds_pass": "AUTHORIZATION_TTL_SECONDS = 60" in authorization_source,
        "stage_tags_pass": all(tag in authorization_source for tag in ('"a1"', '"b1"', '"c1"')),
        "atomic_single_use_pass": all(
            marker in authorization_source
            for marker in ("PRIMARY KEY", 'isolation_level="IMMEDIATE"', "IntegrityError")
        ),
    }
    poc_source = (hexstrike / "hexstrike_t3_poc.py").read_text(encoding="utf-8")
    t3a_source = (hexstrike / "hexstrike_t3a.py").read_text(encoding="utf-8")
    limits_result = {
        "t3a_single_session_pass": 'limits.get("max_sessions") != 1' in t3a_source,
        "t3b_fixed_limits_pass": all(
            marker in poc_source
            for marker in (
                '"max_commands": 5',
                '"max_sessions": 1',
                '"per_command_timeout_seconds": 15',
                '"total_timeout_seconds": 60',
            )
        ),
        "t3c_fixed_limits_pass": t3c.get("maximum_duration_seconds") == 60
        and t3c.get("maximum_tool_calls") == 6,
    }
    kill_switch_path = Path("/run/hexstrike/KILL")
    kill_switch_result = {
        "path": str(kill_switch_path),
        "inactive_pass": _kill_switch_inactive(kill_switch_path),
        "t3a_check_present": "kill_switch_path.exists()"
        in (hexstrike / "hexstrike_t3a.py").read_text(encoding="utf-8"),
        "t3b_check_present": "kill_switch_path.exists()"
        in (hexstrike / "hexstrike_t3b.py").read_text(encoding="utf-8"),
    }

    report: dict[str, object] = {
        "assurance_profile": "poc",
        "ssh_reachability_configuration": reachability_result,
        "poc_runtime_configuration": runtime_result,
        "target_matrix": matrix_result,
        "credential_mapping": credential_result,
        "t3c_runtime_configuration": t3c_result,
        "pinned_host_key_source": pinned_host_result,
        "identity_agent_runtime": identity_agent_result,
        "hexstrike_bind": bind_result,
        "poc_endpoints": endpoint_result,
        "replay_protection": replay_result,
        "fixed_execution_limits": limits_result,
        "kill_switch": kill_switch_result,
        "signed_permits": _skipped(),
        "approval_key_isolation": _skipped(),
        "hardened_routes": _skipped(),
        "uid_firewall": _skipped(),
    }
    common_sections = (
        reachability_result,
        runtime_result,
        matrix_result,
        credential_result,
        t3c_result,
        pinned_host_result,
        identity_agent_result,
        bind_result,
        endpoint_result,
        replay_result,
        limits_result,
        kill_switch_result,
    )
    passed = (
        all(
            value is True
            for section in common_sections
            for key, value in section.items()
            if key.endswith("_pass") or key.endswith("_present") or key.endswith("_rejected")
        )
        and identity_agent_result["status"] == "PASS"
    )
    return report, passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--assurance-profile",
        required=True,
        choices=("poc", "hardened"),
    )
    parser.add_argument("--harness-root", default="/home/kali/agent-eval-harness")
    parser.add_argument("--hexstrike-root", default="/home/kali/hexstrike-ai")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print(json.dumps({"overall_pass": False, "error_code": "sudo_required"}))
        return 2
    try:
        if args.assurance_profile == "poc":
            report, passed = _verify_poc(args)
        else:
            report, passed = _verify_hardened(args)
    except ReadinessCheckError as exc:
        print(
            json.dumps(
                {
                    "assurance_profile": args.assurance_profile,
                    "overall_pass": False,
                    "failed_check": exc.check,
                    "error_code": exc.code,
                }
            )
        )
        return 2
    except Exception:  # noqa: BLE001 - never expose protected paths or values
        print(json.dumps({"overall_pass": False, "error_code": "readiness_verification_failed"}))
        return 2
    report["overall_pass"] = passed
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
